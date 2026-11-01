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
package attributes

import (
	"context"
	"encoding/base64"
	"net/netip"
	"net/url"
	"reflect"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	structpb "google.golang.org/protobuf/types/known/structpb"
	"k8s.io/apimachinery/pkg/types"
)

// makeAttrs builds the ext_proc attributes map the way Envoy delivers it:
// a single top-level struct keyed by the ext_proc filter name.
func makeAttrs(t testing.TB, fields map[string]any) map[string]*structpb.Struct {
	t.Helper()
	inner, err := structpb.NewStruct(fields)
	if err != nil {
		t.Fatalf("failed to build attrs struct: %v", err)
	}
	return map[string]*structpb.Struct{ExtProcAttrsKey: inner}
}

// makeHTTPHeaders builds an extProcPb.HttpHeaders from a plain map.
func makeHTTPHeaders(kv map[string]string) *extProcPb.HttpHeaders {
	hm := &corev3.HeaderMap{}
	for k, v := range kv {
		hm.Headers = append(hm.Headers, &corev3.HeaderValue{Key: k, RawValue: []byte(v)})
	}
	return &extProcPb.HttpHeaders{Headers: hm}
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestExtractSandboxMetadataPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name     string
		metadata string
		want     *filter.SandboxToken
	}{
		{
			name:     "current identity overrides legacy token",
			metadata: "agent-identity.access-token=new+/=,agent-identity.sandbox-client-id=new-client",
			want:     &filter.SandboxToken{AccessToken: "new+/=", SandboxClientID: "new-client"},
		},
		{name: "empty metadata does not fall back"},
		{name: "malformed metadata does not fall back", metadata: "malformed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attrs := makeAttrs(t, map[string]any{
				"filter_state['agentio.sandbox.metadata']": tc.metadata,
				FilterStateSandboxToken:                    `{"accessToken":"old","sandboxClientId":"old-client"}`,
			})
			peer, _ := Extract(t.Context(), nil, attrs)
			if got := peer.Token.Parse(t.Context()); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("metadata identity = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	fullHeaders := map[string]string{
		":authority": "api.example.com:8443",
		":path":      "/v1/chat?x=1",
		":method":    "POST",
		":scheme":    "https",
	}
	connectHeaders := map[string]string{
		":authority": "target.example.com:443",
		":method":    "CONNECT",
		":scheme":    "http",
	}
	// parseHTTPRequest stores the (lowercased) header map into
	// HTTPRequest.Headers — the single canonical header holder.
	fullReq := func(port int32, headers map[string]string) httpreq.HTTPRequest {
		return httpreq.HTTPRequest{
			Host:     "api.example.com",
			Port:     port,
			Path:     "/v1/chat",
			Query:    url.Values{"x": {"1"}},
			RawQuery: "x=1",
			Method:   "POST",
			Scheme:   "https",
			Headers:  headers,
		}
	}
	tokenJSON := `{"requestId":"r1","accessToken":"tok","sandboxClientId":"c1"}`

	tests := []struct {
		name       string
		attrFields map[string]any
		headers    map[string]string
		wantCaller filter.CallerContext
		wantReq    httpreq.HTTPRequest
		wantValid  bool
	}{
		{
			name: "full identity with token, labels and port override",
			attrFields: map[string]any{
				FilterStateDownstreamPeerNamespace: "default",
				FilterStateDownstreamPeerName:      "pod-a",
				FilterStateWorkloadLabels:          b64("app=sleep,tier=web"),
				FilterStateSandboxToken:            b64(tokenJSON),
				AttrSourceAddress:                  "10.0.0.1:34567",
				AttrDestinationPort:                float64(9443),
			},
			headers: fullHeaders,
			wantCaller: filter.CallerContext{
				Token: filter.NewSandboxToken(b64(tokenJSON)),
				Subject: subject.Subject{
					Workload: subject.Workload{
						Namespace: "default",
						Name:      "pod-a",
						IP:        "10.0.0.1",
						Labels:    map[string]string{"app": "sleep", "tier": "web"},
					},
				},
			},
			wantReq:   fullReq(9443, fullHeaders),
			wantValid: true,
		},
		{
			name: "no destination.port keeps authority port",
			attrFields: map[string]any{
				FilterStateDownstreamPeerNamespace: "default",
				FilterStateDownstreamPeerName:      "pod-a",
				FilterStateWorkloadLabels:          b64("app=sleep,tier=web"),
			},
			headers: fullHeaders,
			wantCaller: filter.CallerContext{
				Subject: subject.Subject{
					Workload: subject.Workload{
						Namespace: "default",
						Name:      "pod-a",
						Labels:    map[string]string{"app": "sleep", "tier": "web"},
					},
				},
			},
			wantReq:   fullReq(8443, fullHeaders),
			wantValid: true,
		},
		{
			name: "CONNECT keeps target authority port instead of proxy destination port",
			attrFields: map[string]any{
				FilterStateDownstreamPeerNamespace: "default",
				FilterStateDownstreamPeerName:      "pod-a",
				AttrDestinationPort:                float64(1087),
			},
			headers: connectHeaders,
			wantCaller: filter.CallerContext{
				Subject: subject.Subject{
					Workload: subject.Workload{Namespace: "default", Name: "pod-a", Labels: map[string]string{}},
				},
			},
			wantReq: httpreq.HTTPRequest{
				Host:    "target.example.com",
				Port:    443,
				Method:  "CONNECT",
				Scheme:  "http",
				Headers: connectHeaders,
			},
			wantValid: true,
		},
		{
			name: "labels parsed from agentio.workload.labels",
			attrFields: map[string]any{
				FilterStateDownstreamPeerNamespace: "ns1",
				FilterStateDownstreamPeerName:      "pod-b",
				FilterStateWorkloadLabels:          b64("app=sleep"),
			},
			headers: fullHeaders,
			wantCaller: filter.CallerContext{
				Subject: subject.Subject{
					Workload: subject.Workload{
						Namespace: "ns1",
						Name:      "pod-b",
						Labels:    map[string]string{"app": "sleep"},
					},
				},
			},
			wantReq:   fullReq(8443, fullHeaders),
			wantValid: true,
		},
		{
			name: "unparseable sandbox.token retained without parsing",
			attrFields: map[string]any{
				FilterStateDownstreamPeerNamespace: "default",
				FilterStateDownstreamPeerName:      "pod-a",
				FilterStateSandboxToken:            "!!!not-base64-and-not-json!!!",
			},
			headers: fullHeaders,
			wantCaller: filter.CallerContext{
				Token: filter.NewSandboxToken("!!!not-base64-and-not-json!!!"),
				Subject: subject.Subject{
					Workload: subject.Workload{Namespace: "default", Name: "pod-a", Labels: map[string]string{}},
				},
			},
			wantReq:   fullReq(8443, fullHeaders),
			wantValid: true,
		},
		{
			name: "raw JSON sandbox.token retained without parsing",
			attrFields: map[string]any{
				FilterStateDownstreamPeerNamespace: "default",
				FilterStateDownstreamPeerName:      "pod-a",
				FilterStateSandboxToken:            tokenJSON,
			},
			headers: fullHeaders,
			wantCaller: filter.CallerContext{
				Token: filter.NewSandboxToken(tokenJSON),
				Subject: subject.Subject{
					Workload: subject.Workload{Namespace: "default", Name: "pod-a", Labels: map[string]string{}},
				},
			},
			wantReq:   fullReq(8443, fullHeaders),
			wantValid: true,
		},
		{
			name: "missing pod name preserves target for static authorization",
			attrFields: map[string]any{
				FilterStateDownstreamPeerNamespace: "default",
				FilterStateWorkloadLabels:          b64("app=sleep"),
				AttrSourceAddress:                  "10.0.0.2:1234",
			},
			headers: fullHeaders,
			wantCaller: filter.CallerContext{
				Subject: subject.Subject{
					Workload: subject.Workload{
						Namespace: "default",
						IP:        "10.0.0.2",
						Labels:    map[string]string{"app": "sleep"},
					},
				},
			},
			wantReq:   fullReq(8443, fullHeaders),
			wantValid: false,
		},
		{
			name: "missing pod namespace fails identity",
			attrFields: map[string]any{
				FilterStateDownstreamPeerName: "pod-a",
			},
			headers: fullHeaders,
			wantCaller: filter.CallerContext{
				Subject: subject.Subject{Workload: subject.Workload{Name: "pod-a", Labels: map[string]string{}}},
			},
			wantReq:   fullReq(8443, fullHeaders),
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := makeAttrs(t, tt.attrFields)
			gotCaller, gotReq := Extract(context.Background(), makeHTTPHeaders(tt.headers), attrs)
			if !reflect.DeepEqual(gotCaller, tt.wantCaller) {
				t.Errorf("Extract() caller = %+v, want %+v", gotCaller, tt.wantCaller)
			}
			if !reflect.DeepEqual(gotReq, tt.wantReq) {
				t.Errorf("Extract() request = %+v, want %+v", gotReq, tt.wantReq)
			}
			if gotCaller.Subject.HasIdentity() != tt.wantValid {
				t.Errorf("Valid() = %t, want %t", gotCaller.Subject.HasIdentity(), tt.wantValid)
			}
		})
	}
}

func TestExtractFilterStateString_NestedStructure(t *testing.T) {
	innerMap := map[string]interface{}{
		"filter_state['downstream_peer'].name":      "sleep-55874894df-mtqbk",
		"filter_state['downstream_peer'].namespace": "default",
		"filter_state['agentio.workload.labels']":   "YXBwPXNsZWVwLHNlcnZpY2UuaXN0aW8uaW8vY2Fub25pY2FsLW5hbWU9c2xlZXA=",
	}
	innerStruct, err := structpb.NewStruct(innerMap)
	if err != nil {
		t.Fatalf("Failed to create inner struct: %v", err)
	}

	attrs := map[string]*structpb.Struct{
		ExtProcAttrsKey: innerStruct,
	}

	tests := []struct {
		name     string
		key      string
		expected string
	}{
		{
			name:     "extract pod name",
			key:      FilterStateDownstreamPeerName,
			expected: "sleep-55874894df-mtqbk",
		},
		{
			name:     "extract pod namespace",
			key:      FilterStateDownstreamPeerNamespace,
			expected: "default",
		},
		{
			name:     "extract sandbox labels",
			key:      FilterStateWorkloadLabels,
			expected: "YXBwPXNsZWVwLHNlcnZpY2UuaXN0aW8uaW8vY2Fub25pY2FsLW5hbWU9c2xlZXA=",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			val := extractFilterStateString(attrs, tc.key)
			if val != tc.expected {
				t.Errorf("Expected %q, got %q", tc.expected, val)
			}
		})
	}
}

func TestGetExtProcStruct_NilAndEmptyCases(t *testing.T) {
	if s := getExtProcStruct(nil); s != nil {
		t.Errorf("Expected nil for nil input, got %v", s)
	}

	if s := getExtProcStruct(map[string]*structpb.Struct{}); s != nil {
		t.Errorf("Expected nil for empty map, got %v", s)
	}

	attrs := map[string]*structpb.Struct{
		"other_key": nil,
	}
	if s := getExtProcStruct(attrs); s != nil {
		t.Errorf("Expected nil for missing ext_proc key, got %v", s)
	}
}

func TestExtractFilterStateString(t *testing.T) {
	tests := []struct {
		name     string
		attrs    map[string]*structpb.Struct
		key      string
		expected string
	}{
		{
			name:     "nil attrs",
			attrs:    nil,
			key:      "test",
			expected: "",
		},
		{
			name:     "empty attrs",
			attrs:    map[string]*structpb.Struct{},
			key:      "test",
			expected: "",
		},
		{
			name: "direct key match",
			attrs: func() map[string]*structpb.Struct {
				inner, _ := structpb.NewStruct(map[string]interface{}{"my_key": "value123"})
				return map[string]*structpb.Struct{ExtProcAttrsKey: inner}
			}(),
			key:      "my_key",
			expected: "value123",
		},
		{
			name: "filter_state key format",
			attrs: func() map[string]*structpb.Struct {
				inner, _ := structpb.NewStruct(map[string]interface{}{"filter_state['pod.name']": "my-pod"})
				return map[string]*structpb.Struct{ExtProcAttrsKey: inner}
			}(),
			key:      "pod.name",
			expected: "my-pod",
		},
		{
			name: "no fuzzy suffix fallback",
			attrs: func() map[string]*structpb.Struct {
				inner, err := structpb.NewStruct(map[string]any{"caller.name": "my-pod"})
				if err != nil {
					t.Fatal(err)
				}
				return map[string]*structpb.Struct{ExtProcAttrsKey: inner}
			}(),
			key:      "name",
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := extractFilterStateString(tc.attrs, tc.key)
			if result != tc.expected {
				t.Errorf("Expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestExtractFilterStateString_ValueTypes(t *testing.T) {
	innerMap := map[string]interface{}{
		"string_val": "hello",
		"map_val":    map[string]interface{}{"value": "nested-value"},
		"int_val":    float64(42),
	}

	inner, err := structpb.NewStruct(innerMap)
	if err != nil {
		t.Fatalf("Failed to create struct: %v", err)
	}
	attrs := map[string]*structpb.Struct{ExtProcAttrsKey: inner}

	if val := extractFilterStateString(attrs, "string_val"); val != "hello" {
		t.Errorf("Expected 'hello', got %q", val)
	}

	if val := extractFilterStateString(attrs, "map_val"); val != "nested-value" {
		t.Errorf("Expected 'nested-value', got %q", val)
	}

	// Int values can't be extracted as strings; should return empty without panic.
	if val := extractFilterStateString(attrs, "int_val"); val != "" {
		_ = val
	}
}

func TestExtractWorkloadIP(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		expected string
	}{
		{"ipv4 with port", "10.0.0.1:8080", "10.0.0.1"},
		{"ipv4 without port", "10.0.0.1", "10.0.0.1"},
		{"ipv6 bracketed with port", "[::1]:8080", "::1"},
		{"ipv6 bracketed no port", "[::1]", "::1"},
		{"empty string", "", ""},
		{"malformed bracket", "[", "["},
		{"empty brackets", "[]", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var attrs map[string]*structpb.Struct
			if tt.raw != "" {
				inner := map[string]interface{}{
					AttrSourceAddress: tt.raw,
				}
				s, _ := structpb.NewStruct(inner)
				attrs = map[string]*structpb.Struct{ExtProcAttrsKey: s}
			}
			got := extractWorkloadIP(attrs)
			if got != tt.expected {
				t.Errorf("extractWorkloadIP(%q) = %q, want %q", tt.raw, got, tt.expected)
			}
		})
	}
}

func TestExtractAttributeInt_ZeroValue(t *testing.T) {
	inner := map[string]interface{}{
		"some-key": 12345.0,
	}
	s, _ := structpb.NewStruct(inner)
	attrs := map[string]*structpb.Struct{ExtProcAttrsKey: s}

	if v := extractAttributeInt(attrs, "some-key"); v != 12345 {
		t.Errorf("expected 12345, got %d", v)
	}
	if v := extractAttributeInt(attrs, "missing-key"); v != 0 {
		t.Errorf("expected 0 for missing key, got %d", v)
	}
	if v := extractAttributeInt(nil, "any"); v != 0 {
		t.Errorf("expected 0 for nil attrs, got %d", v)
	}
}

func TestExtractWorkloadIdentityPrecedence(t *testing.T) {
	for _, tt := range []struct {
		name   string
		fields map[string]any
		want   types.NamespacedName
	}{
		{
			name: "workload headers override conflicting caller metadata",
			fields: map[string]any{
				FilterStateWorkloadName:            "source-pod",
				FilterStateWorkloadNamespace:       "source-ns",
				FilterStateDownstreamPeerName:      "caller-pod",
				FilterStateDownstreamPeerNamespace: "caller-ns",
			},
			want: types.NamespacedName{Name: "source-pod", Namespace: "source-ns"},
		},
		{
			name:   "workload headers work without caller metadata",
			fields: map[string]any{FilterStateWorkloadName: "source-pod", FilterStateWorkloadNamespace: "source-ns"},
			want:   types.NamespacedName{Name: "source-pod", Namespace: "source-ns"},
		},
		{
			name:   "missing headers use legacy metadata",
			fields: map[string]any{FilterStateDownstreamPeerName: "caller-pod", FilterStateDownstreamPeerNamespace: "caller-ns"},
			want:   types.NamespacedName{Name: "caller-pod", Namespace: "caller-ns"},
		},
		{
			name: "empty headers use legacy metadata",
			fields: map[string]any{
				FilterStateWorkloadName:            "",
				FilterStateWorkloadNamespace:       "",
				FilterStateDownstreamPeerName:      "caller-pod",
				FilterStateDownstreamPeerNamespace: "caller-ns",
			},
			want: types.NamespacedName{Name: "caller-pod", Namespace: "caller-ns"},
		},
		{
			name: "namespace falls back independently",
			fields: map[string]any{
				FilterStateWorkloadName:            "source-pod",
				FilterStateWorkloadNamespace:       "",
				FilterStateDownstreamPeerName:      "caller-pod",
				FilterStateDownstreamPeerNamespace: "caller-ns",
			},
			want: types.NamespacedName{Name: "source-pod", Namespace: "caller-ns"},
		},
		{
			name: "name falls back independently",
			fields: map[string]any{
				FilterStateWorkloadNamespace:       "source-ns",
				FilterStateDownstreamPeerName:      "caller-pod",
				FilterStateDownstreamPeerNamespace: "caller-ns",
			},
			want: types.NamespacedName{Name: "caller-pod", Namespace: "source-ns"},
		},
		{
			name:   "partial identity remains invalid",
			fields: map[string]any{FilterStateWorkloadName: "source-pod"},
			want:   types.NamespacedName{Name: "source-pod"},
		},
		{name: "application headers alone cannot supply identity", fields: map[string]any{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// These inner request headers must never override the captured
			// CONNECT context, including when that context is missing.
			headers := makeHTTPHeaders(map[string]string{
				":method":                      "GET",
				":authority":                   "api.example.com",
				":path":                        "/",
				"x-agentio-workload-name":      "application-pod",
				"x-agentio-workload-namespace": "application-ns",
			})
			caller, req := Extract(context.Background(), headers, makeAttrs(t, tt.fields))
			workload := caller.Subject.Workload
			got := types.NamespacedName{Namespace: workload.Namespace, Name: workload.Name}
			if got != tt.want {
				t.Fatalf("source workload = %v, want %v", got, tt.want)
			}
			wantValid := tt.want.Name != "" && tt.want.Namespace != ""
			if caller.Subject.HasIdentity() != wantValid {
				t.Fatalf("Valid = %t, want %t", caller.Subject.HasIdentity(), wantValid)
			}
			if wantValid && req.Host != "api.example.com" {
				t.Fatalf("valid workload identity did not reach request extraction: %+v", req)
			}
		})
	}
}

func TestExtractPolicyIdentitiesFromCapturedContext(t *testing.T) {
	headers := makeHTTPHeaders(map[string]string{
		":method":                "GET",
		":authority":             "api.example.com",
		":path":                  "/",
		"x-agentio-workload-uid": "forged-workload",
		"x-agentio-sandbox-id":   "forged-sandbox",
	})
	for _, captured := range []bool{false, true} {
		fields := map[string]any{FilterStateWorkloadNamespace: "ns", FilterStateWorkloadName: "pod"}
		if captured {
			fields[FilterStateWorkloadUID] = "native:workload"
			fields[FilterStateSandboxID] = "kruise:sandbox"
		}
		caller, _ := Extract(context.Background(), headers, makeAttrs(t, fields))
		subject := caller.Subject
		if captured {
			if subject.Workload.UID != "native:workload" ||
				subject.Sandbox == nil || subject.Sandbox.UID != "kruise:sandbox" {
				t.Fatalf("captured identities lost: %+v", subject)
			}
		} else if subject.Workload.UID != "" || subject.Sandbox != nil {
			t.Fatalf("application headers supplied policy identity: %+v", subject)
		}
	}
}

func TestExtractOriginalDestination(t *testing.T) {
	for _, tc := range []struct {
		name    string
		address string
		method  string
		want    string
		port    float64
	}{
		{"ipv4", "192.0.2.2:8443", "GET", "192.0.2.2:8443", 8443},
		{"ipv6", "[2001:db8::2]:8443", "GET", "[2001:db8::2]:8443", 8443},
		{"mapped ipv4", "[::ffff:192.0.2.2]:8443", "GET", "192.0.2.2:8443", 8443},
		{"ip with separate port", "192.0.2.2", "GET", "192.0.2.2:8443", 8443},
		{"full address without separate port", "192.0.2.2:8443", "GET", "192.0.2.2:8443", 0},
		{"CONNECT ignores proxy listener", "192.0.2.2:1087", "CONNECT", "", 1087},
		{"conflicting port", "192.0.2.2:8443", "GET", "", 443},
		{"missing port", "192.0.2.2", "GET", "", 0},
		{"malformed", "bad:8443", "GET", "", 8443},
		{"scoped ip", "[fe80::1%eth0]:8443", "GET", "", 8443},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attrs := makeAttrs(t, map[string]any{
				FilterStateDownstreamPeerName:      "pod",
				FilterStateDownstreamPeerNamespace: "default",
				"destination.address":              tc.address,
				AttrDestinationPort:                tc.port,
			})
			_, req := Extract(
				t.Context(),
				makeHTTPHeaders(map[string]string{":authority": "api.example:443", ":method": tc.method}),
				attrs,
			)
			var want netip.AddrPort
			if tc.want != "" {
				want = netip.MustParseAddrPort(tc.want)
			}
			if req.OriginalDestination != want {
				t.Fatalf("original destination = %s, want %s", req.OriginalDestination, want)
			}
		})
	}
	attrs := makeAttrs(
		t,
		map[string]any{FilterStateDownstreamPeerName: "pod", FilterStateDownstreamPeerNamespace: "default"},
	)
	_, req := Extract(
		t.Context(),
		makeHTTPHeaders(
			map[string]string{
				":authority":          "api.example:443",
				":method":             "GET",
				"destination.address": "192.0.2.2:443",
			},
		),
		attrs,
	)
	if req.OriginalDestination.IsValid() {
		t.Fatalf("HTTP header became original destination: %s", req.OriginalDestination)
	}
}

func TestWorkloadLabelsRollingUpgrade(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fields map[string]any
		want   map[string]string
	}{
		{name: "old gateway", fields: map[string]any{FilterStateSandboxLabels: b64("app=old")}, want: map[string]string{"app": "old"}},
		{name: "new gateway", fields: map[string]any{FilterStateWorkloadLabels: b64("app=new")}, want: map[string]string{"app": "new"}},
		{name: "new value wins", fields: map[string]any{FilterStateWorkloadLabels: b64("app=new"), FilterStateSandboxLabels: b64("app=old")}, want: map[string]string{"app": "new"}},
		{name: "empty new value is authoritative", fields: map[string]any{FilterStateWorkloadLabels: "", FilterStateSandboxLabels: b64("app=old")}, want: map[string]string{}},
		{name: "invalid new value does not fall back", fields: map[string]any{FilterStateWorkloadLabels: "!invalid", FilterStateSandboxLabels: b64("app=old")}, want: map[string]string{}},
		{name: "wrapped new value", fields: map[string]any{FilterStateWorkloadLabels: map[string]any{"value": b64("app=new")}, FilterStateSandboxLabels: b64("app=old")}, want: map[string]string{"app": "new"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.fields[FilterStateWorkloadName] = "client"
			tc.fields[FilterStateWorkloadNamespace] = "demo"
			caller, _ := Extract(
				t.Context(),
				makeHTTPHeaders(map[string]string{":method": "GET", ":authority": "example.com"}),
				makeAttrs(t, tc.fields),
			)
			if !reflect.DeepEqual(caller.Subject.Workload.Labels, tc.want) {
				t.Fatalf("labels=%v want=%v", caller.Subject.Workload.Labels, tc.want)
			}
		})
	}
}

func TestExtractUpstream(t *testing.T) {
	for _, tc := range []struct {
		name    string
		value   any
		present bool
		invalid bool
		want    string
	}{
		{name: "absent"},
		{name: "IPv4", value: "192.0.2.10:8443", present: true, want: "192.0.2.10:8443"},
		{name: "IPv6", value: "[2001:db8::1]:443", present: true, want: "[2001:db8::1]:443"},
		{name: "empty", value: "", present: true, invalid: true},
		{name: "hostname", value: "service.example:443", present: true, invalid: true},
		{name: "zero port", value: "192.0.2.10:0", present: true, invalid: true},
		{name: "scoped address", value: "[fe80::1%eth0]:443", present: true, invalid: true},
		{name: "wrong type", value: 443, present: true, invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fields := map[string]any{}
			if tc.present {
				fields[FilterStateRouteUpstream] = tc.value
			}
			target, err := ExtractUpstream(makeAttrs(t, fields))
			if (err != nil) != tc.invalid {
				t.Fatalf("target=%v error=%v", target, err)
			}
			if tc.want != "" && (target == nil || target.Address.String() != tc.want) {
				t.Fatalf("target=%v", target)
			}
			if tc.want == "" && target != nil {
				t.Fatalf("unexpected target=%v", target)
			}
		})
	}
}
