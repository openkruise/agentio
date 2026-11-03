// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package httpcallout

import (
	"maps"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
)

func TestSourceContextWithoutWorkload(t *testing.T) {
	stream := &filter.Stream{RequestContext: filter.RequestContext{Caller: filter.CallerContext{Subject: subject.Subject{
		Sandbox: &subject.Sandbox{UID: "kruise:sbx"},
	}}}}
	if got := sourceContext(stream); !reflect.DeepEqual(got, SourceContext{}) {
		t.Fatalf("Sandbox identity projected as workload: %+v", got)
	}
}

func testUnitID() filter.UnitID {
	return filter.UnitID{Scope: "default/profile", Name: "inspect", Ordinal: 2}
}

// testStream mirrors what the engine hands a filter: a caller with a token that
// must never leave the mesh, and a request whose parsed Query disagrees with
// RawQuery so a builder reading the wrong one is visible.
func testStream() *filter.Stream {
	return &filter.Stream{RequestContext: filter.RequestContext{Caller: filter.CallerContext{
		Token: &filter.SandboxToken{AccessToken: "secret-token", SandboxClientID: "client-1"},
		Subject: subject.Subject{
			Workload: subject.Workload{
				Namespace: "default",
				Name:      "agent-0",
				IP:        "10.0.0.8",
				Labels:    map[string]string{"app": "agent"},
			},
		},
	},
		RequestID: "req-123",
		Request: httpreq.HTTPRequest{
			Host:     "api.example.com",
			Port:     443,
			Path:     "/v1/run",
			Query:    url.Values{"debug": []string{"true"}},
			RawQuery: "debug=true;trace=1",
			Method:   "POST",
			Scheme:   "https",
			Headers: map[string]string{
				"content-type":  "application/json",
				"x-tenant":      "demo",
				"authorization": "Bearer caller-credential",
				"cookie":        "session=abc",
				"x-request-id":  "req-123",
			},
		}}, StreamRuntime: filter.StreamRuntime{Response: httpreq.HTTPResponse{
		Status: 201,
		Headers: map[string]string{
			"content-type":       "text/plain",
			"x-upstream":         "demo",
			"set-cookie":         "session=upstream-minted",
			"www-authenticate":   `Bearer realm="upstream"`,
			"proxy-authenticate": `Basic realm="proxy"`,
		},
	}},
	}
}

func testConfig(t *testing.T, cfg Config) Config {
	t.Helper()
	cfg.Provider = "scanner"
	effective, err := cfg.Effective()
	if err != nil {
		t.Fatalf("Effective: %v", err)
	}
	return effective
}

func TestBuildRequestInvocationMapsEveryField(t *testing.T) {
	cfg := testConfig(t, Config{Request: &PhaseConfig{Body: true}})
	st := testStream()

	inv, err := buildRequestInvocation(
		cfg,
		testUnitID(),
		st,
		filter.Body{Bytes: []byte(`{"input":"hi"}`), Complete: true},
	)
	if err != nil {
		t.Fatalf("buildRequestInvocation: %v", err)
	}
	if err := inv.Validate(); err != nil {
		t.Fatalf("built invocation failed Validate: %v", err)
	}

	if inv.Version != ProtocolVersion || inv.Phase != PhaseRequest {
		t.Errorf("version/phase = %q/%q, want %q/%q", inv.Version, inv.Phase, ProtocolVersion, PhaseRequest)
	}
	wantSource := SourceContext{
		Namespace: "default",
		Workload:  "agent-0",
		IP:        "10.0.0.8",
		Labels:    map[string]string{"app": "agent"},
	}
	if !reflect.DeepEqual(inv.Source, wantSource) {
		t.Errorf("source = %#v, want %#v", inv.Source, wantSource)
	}
	wantPolicy := PolicyContext{Scope: "default/profile", Rule: "inspect", Ordinal: 2}
	if inv.Policy != wantPolicy {
		t.Errorf("policy = %#v, want %#v", inv.Policy, wantPolicy)
	}
	if inv.Response != nil {
		t.Errorf("request-phase invocation carried a response: %#v", inv.Response)
	}

	got := *inv.Request
	got.Body = nil
	want := HTTPRequest{
		ID:          "req-123",
		Method:      "POST",
		Scheme:      "https",
		Host:        "api.example.com",
		Port:        443,
		Path:        "/v1/run",
		RawQuery:    "debug=true;trace=1",
		ContentType: "application/json",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("request view = %#v, want %#v", got, want)
	}
	if inv.Request.Body == nil || *inv.Request.Body != `{"input":"hi"}` {
		t.Errorf("request body = %#v, want the buffered bytes as a UTF-8 string", inv.Request.Body)
	}
}

// TestBuildRequestInvocationSendsAPresentEmptyBody pins that a bodyless request
// under a body-collecting phase still carries a body pointer, so the callout can
// tell "the message had no body" from "the phase never collected one".
func TestBuildRequestInvocationSendsAPresentEmptyBody(t *testing.T) {
	cfg := testConfig(t, Config{Request: &PhaseConfig{Body: true}})
	inv, err := buildRequestInvocation(cfg, testUnitID(), testStream(), filter.Body{Complete: true})
	if err != nil {
		t.Fatalf("buildRequestInvocation: %v", err)
	}
	if inv.Request.Body == nil || *inv.Request.Body != "" {
		t.Fatalf("request body = %#v, want a pointer to the empty string", inv.Request.Body)
	}
	if err := inv.Validate(); err != nil {
		t.Fatalf("built invocation failed Validate: %v", err)
	}
}

func TestBuildRequestInvocationHeaderModes(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  HeadersConfig
		want map[string]string
	}{
		{
			name: "none omits every header",
			cfg:  HeadersConfig{Mode: HeaderModeNone},
			want: nil,
		},
		{
			name: "allowlist forwards only the named headers",
			cfg:  HeadersConfig{Mode: HeaderModeAllowlist, Allowlist: []string{"X-Tenant", "x-absent"}},
			want: map[string]string{"x-tenant": "demo"},
		},
		{
			// "all" means all, credentials included: authorization and cookie
			// are named in the expectation so the reversal of the old
			// never-forward rule is visible rather than implied by an absence.
			name: "all forwards every header including the caller's credentials",
			cfg:  HeadersConfig{Mode: HeaderModeAll},
			want: map[string]string{
				"content-type":  "application/json",
				"x-tenant":      "demo",
				"authorization": "Bearer caller-credential",
				"cookie":        "session=abc",
				"x-request-id":  "req-123",
			},
		},
		{
			// The denylist is how an operator writes the old hardcoded rule.
			// x-request-id is unnamed and survives, which is what separates a
			// denylist from an allowlist.
			name: "denylist drops the named headers and keeps the rest",
			cfg:  HeadersConfig{Mode: HeaderModeDenylist, Denylist: []string{"Authorization", "cookie"}},
			want: map[string]string{
				"content-type": "application/json",
				"x-tenant":     "demo",
				"x-request-id": "req-123",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(t, Config{Request: &PhaseConfig{Headers: tc.cfg, Body: true}})
			inv, err := buildRequestInvocation(cfg, testUnitID(), testStream(), filter.Body{Complete: true})
			if err != nil {
				t.Fatalf("buildRequestInvocation: %v", err)
			}
			if !reflect.DeepEqual(inv.Request.Headers, tc.want) {
				t.Fatalf("forwarded headers = %#v, want %#v", inv.Request.Headers, tc.want)
			}
		})
	}
}

// TestBuildRequestInvocationNeverAliasesStreamHeaders pins that the builder owns
// its map: st.Request.Headers is shared with every other filter on the path.
func TestBuildRequestInvocationNeverAliasesStreamHeaders(t *testing.T) {
	cfg := testConfig(t, Config{Request: &PhaseConfig{Headers: HeadersConfig{Mode: HeaderModeAll}, Body: true}})
	st := testStream()
	before := maps.Clone(st.Request.Headers)

	inv, err := buildRequestInvocation(cfg, testUnitID(), st, filter.Body{Complete: true})
	if err != nil {
		t.Fatalf("buildRequestInvocation: %v", err)
	}
	inv.Request.Headers["x-injected"] = "value"
	if !reflect.DeepEqual(st.Request.Headers, before) {
		t.Fatalf("stream headers = %#v, want them untouched at %#v", st.Request.Headers, before)
	}
}

func TestBuildResponseInvocationOmitsTheRequestBodyAndHeaders(t *testing.T) {
	cfg := testConfig(t, Config{
		Request: &PhaseConfig{Headers: HeadersConfig{Mode: HeaderModeAll}, Body: true},
		Response: &PhaseConfig{
			Headers: HeadersConfig{Mode: HeaderModeAllowlist, Allowlist: []string{"x-upstream"}},
			Body:    true,
		},
	})
	st := testStream()

	inv, err := buildResponseInvocation(
		cfg,
		testUnitID(),
		st,
		filter.Body{Bytes: []byte("response text"), Complete: true},
	)
	if err != nil {
		t.Fatalf("buildResponseInvocation: %v", err)
	}
	if err := inv.Validate(); err != nil {
		t.Fatalf("built invocation failed Validate: %v", err)
	}
	if inv.Phase != PhaseResponse {
		t.Errorf("phase = %q, want %q", inv.Phase, PhaseResponse)
	}
	if inv.Request.Body != nil {
		t.Errorf("response-phase request view carried a body: %#v", *inv.Request.Body)
	}
	// Header forwarding config governs the request phase only; the response
	// phase never forwards request headers regardless of mode.
	if inv.Request.Headers != nil {
		t.Errorf("response-phase request view carried headers: %#v", inv.Request.Headers)
	}
	if inv.Request.ID != "req-123" || inv.Request.Method != "POST" || inv.Request.RawQuery != "debug=true;trace=1" {
		t.Errorf("correlation fields lost: %#v", *inv.Request)
	}

	want := HTTPResponse{
		StatusCode:  201,
		ContentType: "text/plain",
		Headers:     map[string]string{"x-upstream": "demo"},
		Body:        stringPointer("response text"),
	}
	if !reflect.DeepEqual(*inv.Response, want) {
		t.Errorf("response view = %#v, want %#v", *inv.Response, want)
	}
}

// TestBuildInvocationBodyPresenceFollowsThePhaseConfig is the collapse bite. A
// scanner must not read "never collected" as "collected and empty", so the two
// states are asserted as distinct rather than merely both falsy.
func TestBuildInvocationBodyPresenceFollowsThePhaseConfig(t *testing.T) {
	empty := filter.Body{Complete: true}

	t.Run("request phase", func(t *testing.T) {
		collected := testConfig(t, Config{Request: &PhaseConfig{Body: true}})
		notCollected := testConfig(t, Config{Request: &PhaseConfig{}})

		with, err := buildRequestInvocation(collected, testUnitID(), testStream(), empty)
		if err != nil {
			t.Fatalf("buildRequestInvocation: %v", err)
		}
		without, err := buildRequestInvocation(notCollected, testUnitID(), testStream(), empty)
		if err != nil {
			t.Fatalf("buildRequestInvocation: %v", err)
		}
		if with.Request.Body == nil {
			t.Fatal("a collected empty body was omitted, so the callout cannot tell it from an uncollected one")
		}
		if *with.Request.Body != "" {
			t.Errorf("collected body = %q, want the empty string", *with.Request.Body)
		}
		if without.Request.Body != nil {
			t.Errorf("an uncollected body was sent as %#v, want it absent", *without.Request.Body)
		}
		if err := with.Validate(); err != nil {
			t.Errorf("collected-body invocation failed Validate: %v", err)
		}
		if err := without.Validate(); err != nil {
			t.Errorf("uncollected-body invocation failed Validate: %v", err)
		}
	})

	t.Run("response phase", func(t *testing.T) {
		collected := testConfig(t, Config{Response: &PhaseConfig{Body: true}})
		notCollected := testConfig(t, Config{Response: &PhaseConfig{}})

		with, err := buildResponseInvocation(collected, testUnitID(), testStream(), empty)
		if err != nil {
			t.Fatalf("buildResponseInvocation: %v", err)
		}
		without, err := buildResponseInvocation(notCollected, testUnitID(), testStream(), empty)
		if err != nil {
			t.Fatalf("buildResponseInvocation: %v", err)
		}
		if with.Response.Body == nil {
			t.Fatal("a collected empty response body was omitted")
		}
		if *with.Response.Body != "" {
			t.Errorf("collected response body = %q, want the empty string", *with.Response.Body)
		}
		if without.Response.Body != nil {
			t.Errorf("an uncollected response body was sent as %#v, want it absent", *without.Response.Body)
		}
		if err := without.Validate(); err != nil {
			t.Errorf("uncollected-body invocation failed Validate: %v", err)
		}
	})
}

// TestBuildInvocationIgnoresTheBodyWhenThePhaseDidNotAskForIt pins that a body
// the adapter still delivered — an end-of-stream inline body, say — is not
// smuggled into an invocation whose config asked for none.
func TestBuildInvocationIgnoresTheBodyWhenThePhaseDidNotAskForIt(t *testing.T) {
	body := filter.Body{Bytes: []byte("delivered anyway"), Complete: true}

	request, err := buildRequestInvocation(
		testConfig(t, Config{Request: &PhaseConfig{}}), testUnitID(), testStream(), body)
	if err != nil {
		t.Fatalf("buildRequestInvocation: %v", err)
	}
	if request.Request.Body != nil {
		t.Errorf("request body = %q, want it absent for a bodyless phase", *request.Request.Body)
	}

	response, err := buildResponseInvocation(
		testConfig(t, Config{Response: &PhaseConfig{}}), testUnitID(), testStream(), body)
	if err != nil {
		t.Fatalf("buildResponseInvocation: %v", err)
	}
	if response.Response.Body != nil {
		t.Errorf("response body = %q, want it absent for a bodyless phase", *response.Response.Body)
	}
}

func TestBuildResponseInvocationNeverAliasesStreamHeaders(t *testing.T) {
	cfg := testConfig(t, Config{Response: &PhaseConfig{Headers: HeadersConfig{Mode: HeaderModeAll}, Body: true}})
	st := testStream()
	before := maps.Clone(st.Response.Headers)

	inv, err := buildResponseInvocation(cfg, testUnitID(), st, filter.Body{Complete: true})
	if err != nil {
		t.Fatalf("buildResponseInvocation: %v", err)
	}
	inv.Response.Headers["x-injected"] = "value"
	if !reflect.DeepEqual(st.Response.Headers, before) {
		t.Fatalf("stream headers = %#v, want them untouched at %#v", st.Response.Headers, before)
	}
}

func TestBuildResponseInvocationHeaderModes(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  HeadersConfig
		want map[string]string
	}{
		{
			name: "unset mode omits every header",
			cfg:  HeadersConfig{},
			want: nil,
		},
		{
			name: "none omits every header",
			cfg:  HeadersConfig{Mode: HeaderModeNone},
			want: nil,
		},
		{
			name: "allowlist forwards only the named headers",
			cfg:  HeadersConfig{Mode: HeaderModeAllowlist, Allowlist: []string{"X-Upstream", "x-absent"}},
			want: map[string]string{"x-upstream": "demo"},
		},
		{
			// set-cookie is the credential the previous amendment stripped here.
			// It is named in the expectation so the reversal is explicit: "all"
			// now discloses what the upstream minted, and the endpoint sits
			// outside the mesh trust boundary.
			name: "all forwards every header including the upstream's credentials",
			cfg:  HeadersConfig{Mode: HeaderModeAll},
			want: map[string]string{
				"content-type":       "text/plain",
				"x-upstream":         "demo",
				"set-cookie":         "session=upstream-minted",
				"www-authenticate":   `Bearer realm="upstream"`,
				"proxy-authenticate": `Basic realm="proxy"`,
			},
		},
		{
			// www-authenticate is a credential the operator did not name, so it
			// survives. A denylist drops exactly what it lists.
			name: "denylist drops the named headers and keeps an unnamed credential",
			cfg:  HeadersConfig{Mode: HeaderModeDenylist, Denylist: []string{"Set-Cookie", "proxy-authenticate"}},
			want: map[string]string{
				"content-type":     "text/plain",
				"x-upstream":       "demo",
				"www-authenticate": `Bearer realm="upstream"`,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(t, Config{Response: &PhaseConfig{Headers: tc.cfg, Body: true}})
			inv, err := buildResponseInvocation(cfg, testUnitID(), testStream(), filter.Body{Complete: true})
			if err != nil {
				t.Fatalf("buildResponseInvocation: %v", err)
			}
			if !reflect.DeepEqual(inv.Response.Headers, tc.want) {
				t.Fatalf("response headers = %#v, want %#v", inv.Response.Headers, tc.want)
			}
			if err := inv.Validate(); err != nil {
				t.Fatalf("built invocation failed Validate: %v", err)
			}
		})
	}
}

// TestBuildResponseInvocationKeepsStatusAndContentTypeUnderEveryMode mirrors
// TestInvocationOmitsHiddenRequestHeadersButKeepsContentType on the response
// side: ContentType must be read from the raw upstream headers, not the filtered
// map, or hiding headers would blank the one field a scanner needs.
func TestBuildResponseInvocationKeepsStatusAndContentTypeUnderEveryMode(t *testing.T) {
	for _, mode := range []HeaderMode{"", HeaderModeNone, HeaderModeAll} {
		t.Run(string(mode), func(t *testing.T) {
			cfg := testConfig(t, Config{Response: &PhaseConfig{Headers: HeadersConfig{Mode: mode}, Body: true}})
			inv, err := buildResponseInvocation(cfg, testUnitID(), testStream(), filter.Body{Complete: true})
			if err != nil {
				t.Fatalf("buildResponseInvocation: %v", err)
			}
			if inv.Response.StatusCode != 201 {
				t.Errorf("statusCode = %d, want 201 under mode %q", inv.Response.StatusCode, mode)
			}
			if inv.Response.ContentType != "text/plain" {
				t.Errorf(
					"contentType = %q, want it preserved independently of headers under mode %q",
					inv.Response.ContentType,
					mode,
				)
			}
		})
	}
}

// TestBuildResponseInvocationAcceptsAnUpstreamWithNoHeaders pins that a hidden
// map is a valid invocation: the never-nil rule that used to force disclosure is
// gone, so nil is indistinguishable from "the upstream sent none" by design.
func TestBuildResponseInvocationAcceptsAnUpstreamWithNoHeaders(t *testing.T) {
	cfg := testConfig(t, Config{Response: &PhaseConfig{Headers: HeadersConfig{Mode: HeaderModeAll}, Body: true}})
	st := testStream()
	st.Response.Headers = nil

	inv, err := buildResponseInvocation(cfg, testUnitID(), st, filter.Body{Complete: true})
	if err != nil {
		t.Fatalf("buildResponseInvocation: %v", err)
	}
	if len(inv.Response.Headers) != 0 {
		t.Errorf("response headers = %#v, want none", inv.Response.Headers)
	}
	if err := inv.Validate(); err != nil {
		t.Fatalf("built invocation failed Validate: %v", err)
	}
}

// TestBuildInvocationRejectsOversizedBody pins that the limit is a failure, not
// a truncation: asking a scanner to approve content it never saw is worse than
// failing the callout and letting FailOpen decide.
func TestBuildInvocationRejectsOversizedBody(t *testing.T) {
	cfg := testConfig(t, Config{Request: &PhaseConfig{Body: true}, Response: &PhaseConfig{Body: true}, MaxBodyBytes: 8})
	body := filter.Body{Bytes: []byte("123456789"), Complete: true}

	for _, tc := range []struct {
		name  string
		build func() (Invocation, error)
	}{
		{
			name:  "request",
			build: func() (Invocation, error) { return buildRequestInvocation(cfg, testUnitID(), testStream(), body) },
		},
		{
			name:  "response",
			build: func() (Invocation, error) { return buildResponseInvocation(cfg, testUnitID(), testStream(), body) },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inv, err := tc.build()
			if err == nil {
				t.Fatalf("build succeeded with %#v, want an error naming the limit", inv)
			}
			if !strings.Contains(err.Error(), "8") {
				t.Errorf("error = %q, want it to name the configured limit", err.Error())
			}
			if inv.Request != nil || inv.Response != nil {
				t.Errorf("a rejected build still returned content: %#v", inv)
			}
		})
	}

	t.Run("at the limit", func(t *testing.T) {
		inv, err := buildRequestInvocation(
			cfg,
			testUnitID(),
			testStream(),
			filter.Body{Bytes: []byte("12345678"), Complete: true},
		)
		if err != nil {
			t.Fatalf("a body exactly at the limit was rejected: %v", err)
		}
		if *inv.Request.Body != "12345678" {
			t.Fatalf("body = %q, want it intact", *inv.Request.Body)
		}
	})

	// The limit bounds what EPE sends. A phase that collects nothing sends
	// nothing, so an oversized buffer the adapter happened to deliver is not a
	// failure — but the check must not be lost for the phases that do collect,
	// which the subtests above are.
	t.Run("not enforced when the phase collects no body", func(t *testing.T) {
		bodyless := testConfig(t, Config{Request: &PhaseConfig{}, Response: &PhaseConfig{}, MaxBodyBytes: 8})
		if _, err := buildRequestInvocation(bodyless, testUnitID(), testStream(), body); err != nil {
			t.Errorf("buildRequestInvocation: %v", err)
		}
		if _, err := buildResponseInvocation(bodyless, testUnitID(), testStream(), body); err != nil {
			t.Errorf("buildResponseInvocation: %v", err)
		}
	})
}

// TestBuildInvocationLeavesTheUTF8ContractToValidate pins where the invariant
// lives rather than that some layer holds it. bodyText no longer scans the body:
// filter.callout validates every invocation before spending a round trip
// (filter.go:142), so checking in both places walked a large body twice for one
// contract. What must stay true is that a non-UTF-8 body cannot reach the
// endpoint, which is asserted here against the layer that now owns it.
func TestBuildInvocationLeavesTheUTF8ContractToValidate(t *testing.T) {
	cfg := testConfig(t, Config{Request: &PhaseConfig{Body: true}, Response: &PhaseConfig{Body: true}})
	body := filter.Body{Bytes: []byte{0xff, 0xfe}, Complete: true}

	for _, tc := range []struct {
		name  string
		build func() (Invocation, error)
	}{
		{"request", func() (Invocation, error) { return buildRequestInvocation(cfg, testUnitID(), testStream(), body) }},
		{"response", func() (Invocation, error) { return buildResponseInvocation(cfg, testUnitID(), testStream(), body) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inv, err := tc.build()
			if err != nil {
				t.Fatalf("the builder rejected the body itself: %v", err)
			}
			err = inv.Validate()
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), "utf-8") {
				t.Errorf("Validate error = %v, want one naming UTF-8", err)
			}
		})
	}
}

// TestBuildInvocationNeverForwardsTheSandboxToken is a standing guard rather
// than a behaviour test: SourceContext has no token field today, and this fails
// loudly if one is ever added and populated.
func TestBuildInvocationNeverForwardsTheSandboxToken(t *testing.T) {
	cfg := testConfig(t, Config{Request: &PhaseConfig{Headers: HeadersConfig{Mode: HeaderModeAll}, Body: true}})
	st := testStream()

	inv, err := buildRequestInvocation(cfg, testUnitID(), st, filter.Body{Complete: true})
	if err != nil {
		t.Fatalf("buildRequestInvocation: %v", err)
	}
	rendered := marshalJSONObject(t, inv)
	raw, ok := rendered["source"].(map[string]any)
	if !ok {
		t.Fatalf("source = %#v, want an object", rendered["source"])
	}
	for key := range raw {
		if strings.Contains(strings.ToLower(key), "token") {
			t.Errorf("source context exposed %q", key)
		}
	}
	for _, value := range inv.Request.Headers {
		if strings.Contains(value, st.Caller.Token.AccessToken) {
			t.Errorf("a forwarded header carried the sandbox access token: %q", value)
		}
	}
}

func TestBodyTextPhaseLimits(t *testing.T) {
	cfg := Config{MaxBodyBytes: 100}
	for _, tc := range []struct {
		name  string
		limit int64
		size  int
		fail  bool
	}{
		{"request boundary", 3, 3, false}, {"request overflow", 3, 4, true},
		{"response boundary", 5, 5, false}, {"response overflow", 5, 6, true},
		{"shared fallback", 0, 100, false}, {"shared overflow", 0, 101, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := bodyText(
				cfg,
				PhaseConfig{Body: true, MaxBodyBytes: tc.limit},
				filter.Body{Bytes: make([]byte, tc.size)},
				tc.name,
			)
			if (err != nil) != tc.fail {
				t.Fatalf("error=%v, want failure=%v", err, tc.fail)
			}
		})
	}
}
