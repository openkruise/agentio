// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package extproc

import (
	"context"
	"net/netip"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"

	agents "github.com/openkruise/agents-api/agents/v1alpha1"
	"istio.io/istio/pkg/test"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/block"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/bypass"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/egressauthz"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/headermutation"
	"github.com/openkruise/agentio/extensions/epe/pkg/policy/profilestore"
	"github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"
	"github.com/openkruise/agentio/pkg/dns"
	"github.com/openkruise/agentio/pkg/features"
	"github.com/openkruise/agentio/pkg/registry/kubernetes/kruise"
)

func TestSandboxNativeAndE2BComposition(t *testing.T) {
	test.SetForTest(t, &features.SandboxMode, true)
	regs, err := filter.Build(bypass.Definition(), block.Definition(), headermutation.Definition())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name        string
		native      string
		network     string
		host        string
		status      int
		wantHeaders map[string]string
	}{
		{"E2B HTTP bypass before native TCP deny", `{"tcpRules":[{"name":"native","match":[{}],"action":"Deny"}]}`, `{"allowInternetAccess":false,"network":{"allowOut":["api.example.com"]}}`, "api.example.com:443", 0, nil},
		{"overlapping transforms", `{}`, `{"network":{"allowOut":["api.example.com"],"rules":{"*.example.com":[{"transform":{"headers":{"X-Team":"shared","X-Broad":"yes"}}}],"api.example.com":[{"transform":{"headers":{"x-team":"api","X-Exact":"yes"}}}]}}}`, "api.example.com.:443", 0, map[string]string{"x-team": "api", "x-broad": "yes", "x-exact": "yes"}},
		{"native block before E2B HTTP bypass", `{"rules":[{"name":"native","match":[{"domains":["api.example.com"]}],"actions":{"block":{"statusCode":451}}}]}`, `{"network":{"allowOut":["api.example.com"]}}`, "api.example.com:443", 451, nil},
		{"native TCP deny before E2B TCP allow", `{"tcpRules":[{"name":"native","match":[{}],"action":"Deny"}]}`, `{"network":{"allowOut":["10.0.0.0/8"]}}`, "10.1.2.3:443", 403, nil},
		{"native TCP allow before E2B TCP deny", `{"tcpRules":[{"name":"native","match":[{}],"action":"Allow"}]}`, `{"allowInternetAccess":false}`, "10.1.2.3:443", 0, nil},
		{"nonterminal native header continues to E2B deny", `{"rules":[{"name":"native","match":[{"domains":["*"]}],"actions":{"headerManipulation":{"set":[{"name":"x-native","value":"yes"}]}}}]}`, `{"allowInternetAccess":false}`, "10.1.2.3:443", 403, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := profilestore.MakeFakeStore(regs...)
			store.SandboxProfileSet(&agents.Sandbox{ObjectMeta: metav1.ObjectMeta{
				Name:      "sandbox",
				Namespace: "tenant",
				Annotations: map[string]string{
					kruise.AnnotationSecurityProfile: tc.native,
					kruise.AnnotationE2BNetwork:      tc.network,
				},
			}})
			if len(store.List()) != 1 {
				t.Fatal("combined Sandbox profile was not installed")
			}
			client := dns.NewClient(dns.LookupFunc(func(context.Context, string, dns.Family) (dns.LookupResult, error) {
				return dns.LookupResult{Addresses: []netip.Addr{netip.MustParseAddr("10.1.2.3")}}, nil
			}), 0)
			targets := egressauthz.NewAggregate(client)
			server := NewServer(
				ServerDeps{
					Registrations:    regs,
					Resolve:          securityprofile.NewResolver(store, regs, nil, targets),
					AuthorizeRequest: targets.Authorize,
				},
			)
			headers := makeRequestHeaders(tc.host, "/", "GET")
			headers.Headers.Headers = append(
				headers.Headers.Headers,
				&corev3.HeaderValue{Key: ":scheme", RawValue: []byte("https")},
			)
			responses, err := server.HandleRequestHeaders(
				t.Context(),
				headers,
				makeAttrsWithLabels("tenant", "sandbox", ""),
				newStreamState(),
			)
			if err != nil {
				t.Fatal(err)
			}
			if got := int(responses[0].GetImmediateResponse().GetStatus().GetCode()); got != tc.status {
				t.Fatalf("status=%d, want %d: %v", got, tc.status, responses)
			}
			mutation := responses[0].GetRequestHeaders().GetResponse().GetHeaderMutation()
			for name, want := range tc.wantHeaders {
				if got, ok := mutationSetValue(mutation, name); !ok || got != want {
					t.Errorf("%s = %q, want %q", name, got, want)
				}
			}
		})
	}
}
