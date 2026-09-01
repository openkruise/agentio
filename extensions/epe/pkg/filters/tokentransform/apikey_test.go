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
package tokentransform

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	celtypes "github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"k8s.io/utils/ptr"

	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/eval"
	"istio.io/istio/extensions/epe/pkg/httpreq"
	"istio.io/istio/extensions/epe/pkg/inputs"
)

func mustAPIKeyConfig(t *testing.T, rules ...headerSpec) ApiKeyConfig {
	t.Helper()
	cfg, err := compileHeaderRules(rules)
	if err != nil {
		t.Fatalf("compileHeaderRules: %v", err)
	}
	return cfg
}

func testRequest(headers map[string]string) (*filter.Stream, *inputs.Scope) {
	req := httpreq.HTTPRequest{
		Host: "api.example.com", Port: 443, Path: "/v1/items", Method: "POST", Scheme: "https",
		Headers: headers,
	}
	return &filter.Stream{Request: req}, inputs.NewScope(
		inputs.RequestFrom(req),
		inputs.Pod{Name: "agent-1", Namespace: "team-a", IP: "10.0.0.1"},
		inputs.Profile{Name: "backend", Namespace: "team-a"},
		inputs.Rule{Name: "inject"},
		map[string]any{"aud": "inventory"},
	)
}

func testScopeWithPort(port int32) *inputs.Scope {
	req := httpreq.HTTPRequest{Port: port}
	return inputs.NewScope(inputs.RequestFrom(req), inputs.Pod{}, inputs.Profile{}, inputs.Rule{}, nil)
}

func prepareAPIKey(t *testing.T, st *filter.Stream, scope *inputs.Scope, cfg ApiKeyConfig) (PreparedApiKeyConfig, bool, error) {
	t.Helper()
	prepared, empty, err := (apiKeySigner{}).Prepare(st, scope, cfg)
	if err != nil {
		return PreparedApiKeyConfig{}, empty, err
	}
	if empty {
		return PreparedApiKeyConfig{}, true, nil
	}
	pc, ok := prepared.(PreparedApiKeyConfig)
	if !ok {
		t.Fatalf("Prepare() config = %T, want PreparedApiKeyConfig", prepared)
	}
	return pc, false, nil
}

func preparedNames(headers []PreparedHeader) []string {
	out := make([]string, len(headers))
	for i := range headers {
		out[i] = headers[i].Name
	}
	return out
}

type observedSizeList struct {
	traits.Lister
	size     celtypes.Int
	iterated *bool
}

func (l *observedSizeList) Size() ref.Val { return l.size }

func (l *observedSizeList) Iterator() traits.Iterator {
	*l.iterated = true
	return l.Lister.Iterator()
}

func TestAPIKeyPrepareTargets(t *testing.T) {
	t.Run("static names include absent headers and capture snapshot values", func(t *testing.T) {
		st, scope := testRequest(map[string]string{"authorization": "caller"})
		cfg := mustAPIKeyConfig(t, headerSpec{
			Names: []string{"Authorization", "X-Backend-Authorization"},
			Value: valueSourceSpec{Value: ptr.To("fixed")},
		})
		prepared, empty, err := prepareAPIKey(t, st, scope, cfg)
		if err != nil || empty {
			t.Fatalf("Prepare() = (%#v, %v, %v), want targets", prepared, empty, err)
		}
		if got := preparedNames(prepared.Headers); !reflect.DeepEqual(got, []string{"authorization", "x-backend-authorization"}) {
			t.Fatalf("targets = %q, want canonical configured order", got)
		}
		if got := []string{prepared.Headers[0].OriginalValue, prepared.Headers[1].OriginalValue}; !reflect.DeepEqual(got, []string{"caller", ""}) {
			t.Fatalf("original values = %q, want present and absent snapshot values", got)
		}
	})

	t.Run("selector sees all original x-prefixed headers", func(t *testing.T) {
		st, scope := testRequest(map[string]string{"x-a": "1", "x-b": "2", "authorization": "caller"})
		cfg := mustAPIKeyConfig(t, headerSpec{
			CEL:   ptr.To(`request.headers.filter(name, name.startsWith("x-"))`),
			Value: valueSourceSpec{Value: ptr.To("fixed")},
		})
		prepared, empty, err := prepareAPIKey(t, st, scope, cfg)
		if err != nil || empty {
			t.Fatalf("Prepare() = (%#v, %v, %v), want targets", prepared, empty, err)
		}
		got := preparedNames(prepared.Headers)
		sort.Strings(got)
		if !reflect.DeepEqual(got, []string{"x-a", "x-b"}) {
			t.Fatalf("targets = %q, want both original x- headers", got)
		}
	})

	t.Run("selector sees every placeholder-valued header", func(t *testing.T) {
		st, scope := testRequest(map[string]string{
			"authorization": "${AGENTIO_TOKEN}", "x-api-key": "${AGENTIO_TOKEN}", "x-other": "keep",
		})
		cfg := mustAPIKeyConfig(t, headerSpec{
			CEL:   ptr.To(`request.headers.filter(name, request.headers[name] == "${AGENTIO_TOKEN}")`),
			Value: valueSourceSpec{Template: ptr.To("Bearer {{ .Token }}")},
		})
		prepared, empty, err := prepareAPIKey(t, st, scope, cfg)
		if err != nil || empty {
			t.Fatalf("Prepare() = (%#v, %v, %v), want targets", prepared, empty, err)
		}
		got := preparedNames(prepared.Headers)
		sort.Strings(got)
		if !reflect.DeepEqual(got, []string{"authorization", "x-api-key"}) {
			t.Fatalf("targets = %q, want all placeholders", got)
		}
	})

	t.Run("empty selector result is a successful no-op", func(t *testing.T) {
		st, scope := testRequest(map[string]string{"authorization": "caller"})
		cfg := mustAPIKeyConfig(t, headerSpec{
			CEL:   ptr.To(`request.headers.filter(name, name.startsWith("x-missing-"))`),
			Value: valueSourceSpec{Value: ptr.To("fixed")},
		})
		prepared, empty, err := (apiKeySigner{}).Prepare(st, scope, cfg)
		if err != nil || !empty || prepared != nil {
			t.Fatalf("Prepare() = (%#v, %v, %v), want (nil, true, nil)", prepared, empty, err)
		}
	})

	t.Run("selector requires an evaluation scope", func(t *testing.T) {
		st, _ := testRequest(map[string]string{"x-a": "1"})
		cfg := mustAPIKeyConfig(t, headerSpec{
			CEL:   ptr.To(`request.headers.filter(name, name.startsWith("x-"))`),
			Value: valueSourceSpec{Value: ptr.To("fixed")},
		})
		prepared, empty, err := (apiKeySigner{}).Prepare(st, nil, cfg)
		if err == nil || !strings.Contains(err.Error(), "evaluation scope unavailable") || prepared != nil || empty {
			t.Fatalf("Prepare() = (%#v, %v, %v), want unavailable-scope error", prepared, empty, err)
		}
	})

	for _, tc := range []struct {
		name  string
		rules []headerSpec
		want  string
	}{
		{
			name: "non-string dynamic result",
			rules: []headerSpec{{
				CEL: ptr.To(`request.headers.map(name, request.port)`), Value: valueSourceSpec{Value: ptr.To("x")},
			}},
			want: "element 0 is int64, want string",
		},
		{
			name: "forbidden dynamic header",
			rules: []headerSpec{{
				CEL: ptr.To(`["Host"]`), Value: valueSourceSpec{Value: ptr.To("x")},
			}},
			want: "cannot modify Host",
		},
		{
			name: "static dynamic duplicate after canonicalization",
			rules: []headerSpec{
				{Names: []string{"X-API-Key"}, Value: valueSourceSpec{Value: ptr.To("a")}},
				{CEL: ptr.To(`["x-api-key"]`), Value: valueSourceSpec{Value: ptr.To("b")}},
			},
			want: `duplicates header "x-api-key"`,
		},
		{
			name: "dynamic dynamic duplicate after canonicalization",
			rules: []headerSpec{
				{CEL: ptr.To(`["X-API-Key"]`), Value: valueSourceSpec{Value: ptr.To("a")}},
				{CEL: ptr.To(`["x-api-key"]`), Value: valueSourceSpec{Value: ptr.To("b")}},
			},
			want: `duplicates header "x-api-key"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, scope := testRequest(map[string]string{"x-a": "1"})
			cfg := mustAPIKeyConfig(t, tc.rules...)
			prepared, empty, err := (apiKeySigner{}).Prepare(st, scope, cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Prepare() = (%#v, %v, %v), want error containing %q", prepared, empty, err, tc.want)
			}
			if prepared != nil || empty {
				t.Fatalf("Prepare() returned partial config %#v, empty=%v", prepared, empty)
			}
		})
	}

	t.Run("more than sixty-four dynamic targets", func(t *testing.T) {
		headers := make(map[string]string, 65)
		for i := 0; i < 65; i++ {
			headers[fmt.Sprintf("x-token-%02d", i)] = "placeholder"
		}
		st, scope := testRequest(headers)
		cfg := mustAPIKeyConfig(t, headerSpec{
			CEL:   ptr.To(`request.headers.filter(name, name.startsWith("x-token-"))`),
			Value: valueSourceSpec{Value: ptr.To("x")},
		})
		prepared, empty, err := (apiKeySigner{}).Prepare(st, scope, cfg)
		if err == nil || !strings.Contains(err.Error(), "at most 64") || prepared != nil || empty {
			t.Fatalf("Prepare() = (%#v, %v, %v), want target bound error", prepared, empty, err)
		}
	})

	t.Run("selector size is rejected against remaining capacity before iteration", func(t *testing.T) {
		iterated := false
		targets := &observedSizeList{
			Lister:   celtypes.NewStringList(celtypes.DefaultTypeAdapter, nil),
			size:     celtypes.Int(maxHeaderTargets),
			iterated: &iterated,
		}
		cfg := mustAPIKeyConfig(t,
			headerSpec{Names: []string{"authorization"}, Value: valueSourceSpec{Value: ptr.To("static")}},
			headerSpec{CEL: ptr.To(`inputs.targets`), Value: valueSourceSpec{Value: ptr.To("dynamic")}},
		)
		scope := inputs.NewScope(inputs.Request{}, inputs.Pod{}, inputs.Profile{}, inputs.Rule{}, map[string]any{
			"targets": targets,
		})
		prepared, empty, err := (apiKeySigner{}).Prepare(&filter.Stream{}, scope, cfg)
		if err == nil || !strings.Contains(err.Error(), "64") || !strings.Contains(err.Error(), "remaining 63") {
			t.Errorf("Prepare() = (%#v, %v, %v), want remaining-capacity error", prepared, empty, err)
		}
		if iterated {
			t.Error("oversized selector result was iterated before its typed size was rejected")
		}
	})

	t.Run("all selectors observe the original snapshot", func(t *testing.T) {
		original := map[string]string{"x-first": "${AGENTIO_TOKEN}", "x-second": "${AGENTIO_TOKEN}"}
		st, scope := testRequest(original)
		cfg := mustAPIKeyConfig(t,
			headerSpec{CEL: ptr.To(`["x-first"]`), Value: valueSourceSpec{Value: ptr.To("first")}},
			headerSpec{CEL: ptr.To(`request.headers.filter(name, request.headers[name] == "${AGENTIO_TOKEN}")`), Value: valueSourceSpec{Value: ptr.To("second")}},
		)
		prepared, empty, err := (apiKeySigner{}).Prepare(st, scope, cfg)
		if err == nil || !strings.Contains(err.Error(), `duplicates header "x-first"`) {
			t.Fatalf("Prepare() = (%#v, %v, %v), want duplicate proving the second selector saw x-first", prepared, empty, err)
		}
		wantHeaders := map[string]string{"x-first": "${AGENTIO_TOKEN}", "x-second": "${AGENTIO_TOKEN}"}
		if !reflect.DeepEqual(st.Request.Headers, wantHeaders) {
			t.Fatalf("Prepare mutated stream headers: got %v, want %v", st.Request.Headers, wantHeaders)
		}
	})

	t.Run("scope snapshot wins over stream and nil scope falls back", func(t *testing.T) {
		st := &filter.Stream{Request: httpreq.HTTPRequest{Headers: map[string]string{"x-api-key": "stream"}}}
		snapshot := httpreq.HTTPRequest{Headers: map[string]string{"x-api-key": "snapshot"}}
		scope := inputs.NewScope(inputs.RequestFrom(snapshot), inputs.Pod{}, inputs.Profile{}, inputs.Rule{}, nil)
		cfg := mustAPIKeyConfig(t, headerSpec{Names: []string{"x-api-key"}, Value: valueSourceSpec{Value: ptr.To("x")}})
		prepared, _, err := prepareAPIKey(t, st, scope, cfg)
		if err != nil || prepared.Headers[0].OriginalValue != "snapshot" {
			t.Fatalf("scoped Prepare original = %q, err=%v, want snapshot", prepared.Headers[0].OriginalValue, err)
		}
		prepared, _, err = prepareAPIKey(t, st, nil, cfg)
		if err != nil || prepared.Headers[0].OriginalValue != "stream" {
			t.Fatalf("fallback Prepare original = %q, err=%v, want stream", prepared.Headers[0].OriginalValue, err)
		}
	})
}

func TestAPIKeyCELCostLimit(t *testing.T) {
	headers := make(map[string]string, 32)
	for i := 0; i < 32; i++ {
		headers[fmt.Sprintf("x-cost-%02d", i)] = "caller"
	}
	st, scope := testRequest(headers)

	t.Run("selector exhaustion is an ordinary preparation error", func(t *testing.T) {
		cfg := mustAPIKeyConfig(t, headerSpec{
			CEL: ptr.To(`request.headers.filter(a,
				request.headers.all(b, request.headers.all(c, c != "never")))`),
			Value: valueSourceSpec{Value: ptr.To("unused")},
		})
		prepared, empty, err := (apiKeySigner{}).Prepare(st, scope, cfg)
		if err == nil || !strings.Contains(err.Error(), "cost limit exceeded") {
			t.Fatalf("Prepare() = (%#v, %v, %v), want ordinary cost-limit error", prepared, empty, err)
		}
	})

	t.Run("value exhaustion is an ordinary signing error", func(t *testing.T) {
		cfg := mustAPIKeyConfig(t, headerSpec{
			Names: []string{"authorization"},
			Value: valueSourceSpec{Cel: ptr.To(`request.headers.all(a,
				request.headers.all(b, request.headers.all(c, c != "never"))) ? token : "unreachable"`)},
		})
		prepared, empty, err := prepareAPIKey(t, st, scope, cfg)
		if err != nil || empty {
			t.Fatalf("Prepare() = (%#v, %v, %v), want prepared target", prepared, empty, err)
		}
		muts, err := signPreparedAPIKey(t, scope, prepared.Headers...)
		if err == nil || !strings.Contains(err.Error(), "cost limit exceeded") || muts != nil {
			t.Fatalf("Sign() = (%#v, %v), want ordinary cost-limit error with no mutations", muts, err)
		}
	})
}

func signPreparedAPIKey(t *testing.T, scope *inputs.Scope, headers ...PreparedHeader) ([]filter.Mutation, error) {
	t.Helper()
	return (apiKeySigner{}).Sign(context.Background(), &filter.Stream{}, nil, scope,
		Credential{Token: "tok-1"}, PreparedApiKeyConfig{Headers: headers})
}

func TestAPIKeySign(t *testing.T) {
	t.Run("literal template and CEL value sources", func(t *testing.T) {
		st, scope := testRequest(map[string]string{"x-template": "old", "x-cel": "caller"})
		cfg := mustAPIKeyConfig(t,
			headerSpec{Names: []string{"x-literal"}, Value: valueSourceSpec{Value: ptr.To("")}},
			headerSpec{Names: []string{"x-template"}, Value: valueSourceSpec{Template: ptr.To("Bearer {{ .Token }}:{{ .Header.Value }}")}},
			headerSpec{Names: []string{"x-cel"}, Value: valueSourceSpec{Cel: ptr.To(`token + ":" + header.name + ":" + header.value + ":" + request.method`)}},
		)
		prepared, empty, err := prepareAPIKey(t, st, scope, cfg)
		if err != nil || empty {
			t.Fatalf("Prepare() = (%#v, %v, %v)", prepared, empty, err)
		}
		muts, err := signPreparedAPIKey(t, scope, prepared.Headers...)
		if err != nil {
			t.Fatal(err)
		}
		want := []filter.Mutation{{HeaderOps: []filter.HeaderOp{
			{Kind: filter.HeaderSet, Name: "x-literal", Value: ""},
			{Kind: filter.HeaderSet, Name: "x-template", Value: "Bearer tok-1:old"},
			{Kind: filter.HeaderSet, Name: "x-cel", Value: "tok-1:x-cel:caller:POST"},
		}}}
		if !reflect.DeepEqual(muts, want) {
			t.Fatalf("muts = %#v, want %#v", muts, want)
		}
	})

	t.Run("one shared value source applies to multiple names", func(t *testing.T) {
		st, scope := testRequest(map[string]string{"authorization": "a", "x-api-key": "b"})
		cfg := mustAPIKeyConfig(t, headerSpec{
			Names: []string{"authorization", "x-api-key"},
			Value: valueSourceSpec{Template: ptr.To("{{ .Token }}:{{ .Header.Name }}:{{ .Header.Value }}")},
		})
		prepared, _, err := prepareAPIKey(t, st, scope, cfg)
		if err != nil {
			t.Fatal(err)
		}
		muts, err := signPreparedAPIKey(t, scope, prepared.Headers...)
		if err != nil {
			t.Fatal(err)
		}
		want := []filter.Mutation{{HeaderOps: []filter.HeaderOp{
			{Kind: filter.HeaderSet, Name: "authorization", Value: "tok-1:authorization:a"},
			{Kind: filter.HeaderSet, Name: "x-api-key", Value: "tok-1:x-api-key:b"},
		}}}
		if !reflect.DeepEqual(muts, want) {
			t.Fatalf("muts = %#v, want %#v", muts, want)
		}
	})

	t.Run("different rules use different values", func(t *testing.T) {
		st, scope := testRequest(nil)
		cfg := mustAPIKeyConfig(t,
			headerSpec{Names: []string{"authorization"}, Value: valueSourceSpec{Template: ptr.To("Bearer {{ .Token }}")}},
			headerSpec{Names: []string{"x-api-key"}, Value: valueSourceSpec{Value: ptr.To("fixed")}},
		)
		prepared, _, err := prepareAPIKey(t, st, scope, cfg)
		if err != nil {
			t.Fatal(err)
		}
		muts, err := signPreparedAPIKey(t, scope, prepared.Headers...)
		if err != nil {
			t.Fatal(err)
		}
		if got := muts[0].HeaderOps; !reflect.DeepEqual(got, []filter.HeaderOp{
			{Kind: filter.HeaderSet, Name: "authorization", Value: "Bearer tok-1"},
			{Kind: filter.HeaderSet, Name: "x-api-key", Value: "fixed"},
		}) {
			t.Fatalf("ops = %#v", got)
		}
	})

	t.Run("template sees full context and lazy inputs", func(t *testing.T) {
		st, scope := testRequest(map[string]string{"x-context": "caller"})
		cfg := mustAPIKeyConfig(t, headerSpec{
			Names: []string{"x-context"},
			Value: valueSourceSpec{Template: ptr.To(
				`{{ .Token }}|{{ .Header.Name }}|{{ .Header.Value }}|{{ .Request.Method }}|{{ .Pod.Namespace }}|{{ .Profile.Name }}|{{ .Rule.Name }}|{{ index .Inputs "aud" }}`,
			)},
		})
		prepared, _, err := prepareAPIKey(t, st, scope, cfg)
		if err != nil {
			t.Fatal(err)
		}
		muts, err := signPreparedAPIKey(t, scope, prepared.Headers...)
		if err != nil {
			t.Fatal(err)
		}
		want := "tok-1|x-context|caller|POST|team-a|backend|inject|inventory"
		if got := muts[0].HeaderOps[0].Value; got != want {
			t.Fatalf("value = %q, want %q", got, want)
		}
	})

	t.Run("template inputs stay lazy when unavailable", func(t *testing.T) {
		req := httpreq.HTTPRequest{Method: "GET", Headers: map[string]string{"x-context": "caller"}}
		st := &filter.Stream{Request: req}
		scope := inputs.NewScope(inputs.RequestFrom(req), inputs.Pod{}, inputs.Profile{}, inputs.Rule{}, nil,
			inputs.WithInputsError("configmap missing"))
		withoutInputs := mustAPIKeyConfig(t, headerSpec{
			Names: []string{"x-context"}, Value: valueSourceSpec{Template: ptr.To("{{ .Token }}:{{ .Request.Method }}")},
		})
		prepared, _, err := prepareAPIKey(t, st, scope, withoutInputs)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := signPreparedAPIKey(t, scope, prepared.Headers...); err != nil {
			t.Fatalf("template that does not read Inputs failed: %v", err)
		}

		withInputs := mustAPIKeyConfig(t, headerSpec{
			Names: []string{"x-context"}, Value: valueSourceSpec{Template: ptr.To(`{{ index .Inputs "aud" }}`)},
		})
		prepared, _, err = prepareAPIKey(t, st, scope, withInputs)
		if err != nil {
			t.Fatal(err)
		}
		muts, err := signPreparedAPIKey(t, scope, prepared.Headers...)
		if err == nil || !strings.Contains(err.Error(), "profile inputs unavailable") || muts != nil {
			t.Fatalf("Sign() = (%#v, %v), want lazy Inputs error with no mutations", muts, err)
		}
	})

	t.Run("CEL sees token header and standard context", func(t *testing.T) {
		st, scope := testRequest(map[string]string{"x-context": "caller"})
		cfg := mustAPIKeyConfig(t, headerSpec{
			Names: []string{"x-context"},
			Value: valueSourceSpec{Cel: ptr.To(
				`token + "|" + header.name + "|" + header.value + "|" + request.path + "|" + pod.namespace + "|" + profile.name + "|" + rule.name + "|" + inputs.aud`,
			)},
		})
		prepared, _, err := prepareAPIKey(t, st, scope, cfg)
		if err != nil {
			t.Fatal(err)
		}
		muts, err := signPreparedAPIKey(t, scope, prepared.Headers...)
		if err != nil {
			t.Fatal(err)
		}
		want := "tok-1|x-context|caller|/v1/items|team-a|backend|inject|inventory"
		if got := muts[0].HeaderOps[0].Value; got != want {
			t.Fatalf("value = %q, want %q", got, want)
		}
	})

	t.Run("header CEL sees the shared mutation surface", func(t *testing.T) {
		st, scope := testRequest(map[string]string{"x-context": "caller"})
		cfg := mustAPIKeyConfig(t, headerSpec{
			Names: []string{"x-context"},
			Value: valueSourceSpec{Cel: ptr.To(
				`cel.bind(m, json('{"prefix":"Bearer "}').merge({'credential': value}), m.prefix + token + '|' + m.credential + '|' + header.name)`,
			)},
		})
		prepared, _, err := prepareAPIKey(t, st, scope, cfg)
		if err != nil {
			t.Fatal(err)
		}
		muts, err := signPreparedAPIKey(t, scope, prepared.Headers...)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := muts[0].HeaderOps[0].Value, "Bearer tok-1|tok-1|x-context"; got != want {
			t.Fatalf("value = %q, want %q", got, want)
		}
	})

	failingTemplate := mustAPIKeyConfig(t, headerSpec{
		Names: []string{"x"}, Value: valueSourceSpec{Template: ptr.To(`{{ fail "boom" }}`)},
	}).Headers[0].Value.Template
	missingTemplate := mustAPIKeyConfig(t, headerSpec{
		Names: []string{"x"}, Value: valueSourceSpec{Template: ptr.To(`{{ index .Inputs "missing" }}`)},
	}).Headers[0].Value.Template
	dynamicCEL := mustAPIKeyConfig(t, headerSpec{
		Names: []string{"x"}, Value: valueSourceSpec{Cel: ptr.To(`request.port`)},
	}).Headers[0].Value.CEL
	for _, tc := range []struct {
		name    string
		headers []PreparedHeader
		scope   *inputs.Scope
		want    string
	}{
		{
			name: "failure in last value is atomic",
			headers: []PreparedHeader{
				{Name: "authorization", Value: HeaderValueSource{Literal: ptr.To("first")}},
				{Name: "x-api-key", Value: HeaderValueSource{Template: failingTemplate}},
			},
			want: `render header "x-api-key"`,
		},
		{
			name:    "invalid field bytes",
			headers: []PreparedHeader{{Name: "authorization", Value: HeaderValueSource{Literal: ptr.To("ok\r\nx: 1")}}},
			want:    "invalid characters",
		},
		{
			name: "missing key sentinel",
			headers: []PreparedHeader{{
				Name: "authorization", Value: HeaderValueSource{Template: missingTemplate},
			}},
			want: "value resolved to <no value>",
		},
		{
			name: "dynamic CEL returns a non-string",
			headers: []PreparedHeader{{
				Name: "authorization", Value: HeaderValueSource{CEL: dynamicCEL},
			}},
			scope: testScopeWithPort(443),
			want:  "CEL value is int64, want string",
		},
		{
			name: "CEL value requires an evaluation scope",
			headers: []PreparedHeader{{
				Name: "authorization", Value: HeaderValueSource{CEL: dynamicCEL},
			}},
			want: "evaluation scope unavailable",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			muts, err := signPreparedAPIKey(t, tc.scope, tc.headers...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Sign() error = %v, want it to contain %q", err, tc.want)
			}
			if muts != nil {
				t.Fatalf("muts = %#v, want no partial mutation", muts)
			}
		})
	}
}

func TestAPIKeySignerKind(t *testing.T) {
	if (apiKeySigner{}).Kind() != CredentialKindToken {
		t.Fatal("apiKeySigner must declare CredentialKindToken")
	}
}

func TestAPIKeyBodyValueFailureDoesNotLeakToken(t *testing.T) {
	program, err := eval.CompileBodyMutation("request.body")
	if err != nil {
		t.Fatal(err)
	}
	tmpl, err := eval.CompileTemplate("apiKey.value.template", `{{ fail .Token }}`)
	if err != nil {
		t.Fatal(err)
	}
	const token = "TOKEN-MUST-NOT-LEAK"
	muts, err := (apiKeySigner{}).Sign(context.Background(), &filter.Stream{}, []byte("body"), nil,
		Credential{Token: token}, PreparedApiKeyConfig{Body: &ApiKeyBodyConfig{
			Program: program, Value: HeaderValueSource{Template: tmpl},
		}})
	if err == nil || !strings.Contains(err.Error(), "render body value failed") {
		t.Fatalf("Sign() = (%#v, %v), want sanitized body value error", muts, err)
	}
	if strings.Contains(err.Error(), token) {
		t.Fatalf("Sign() error leaked credential: %v", err)
	}
}

func TestAPIKeySignerRejectsForeignConfigs(t *testing.T) {
	if _, _, err := (apiKeySigner{}).Prepare(&filter.Stream{}, nil, "not-mine"); err == nil {
		t.Fatal("Prepare accepted a foreign config")
	}
	if _, err := (apiKeySigner{}).Sign(context.Background(), &filter.Stream{}, nil, nil, Credential{}, "not-mine"); err == nil {
		t.Fatal("Sign accepted a foreign config")
	}
	if _, err := (apiKeySigner{}).WantsBody(&filter.Stream{}, "not-mine"); err == nil {
		t.Fatal("WantsBody accepted a foreign config")
	}
}
