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

package networking

import (
	"slices"
	"testing"
	"time"

	configv1 "github.com/openkruise/agentio/api/config/v1"

	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	previousprioritiesv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/retry/priority/previous_priorities/v3"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	networkingv1alpha3 "istio.io/api/networking/v1alpha3"

	"github.com/openkruise/agentio/pkg/model"
)

func TestRouteSettingsForStaticHostUsesEnvoyDomainPrecedence(t *testing.T) {
	settings := &configv1.HttpRoutingSettings{
		Fallback: &configv1.HttpRouteSettings{Timeout: durationpb.New(time.Second)},
		HostOverrides: []*configv1.HttpRouteOverride{
			{Hosts: []string{"*"}, Settings: &configv1.HttpRouteSettings{Timeout: durationpb.New(2 * time.Second)}},
			{Hosts: []string{"api.*"}, Settings: &configv1.HttpRouteSettings{Timeout: durationpb.New(3 * time.Second)}},
			{Hosts: []string{"*.com"}, Settings: &configv1.HttpRouteSettings{Timeout: durationpb.New(4 * time.Second)}},
			{
				Hosts:    []string{"*.example.com"},
				Settings: &configv1.HttpRouteSettings{Timeout: durationpb.New(5 * time.Second)},
			},
			{
				Hosts:    []string{"api.example.com"},
				Settings: &configv1.HttpRouteSettings{Timeout: durationpb.New(6 * time.Second)},
			},
		},
	}
	tests := []struct {
		host string
		want time.Duration
	}{
		{host: "unmatched.org", want: 2 * time.Second},
		{host: "api.other.org", want: 3 * time.Second},
		{host: "www.example.com", want: 5 * time.Second},
		{host: "API.EXAMPLE.COM", want: 6 * time.Second},
	}
	for _, test := range tests {
		t.Run(test.host, func(t *testing.T) {
			got := routeSettingsForHost(settings, test.host).GetTimeout().AsDuration()
			if got != test.want {
				t.Fatalf("route settings timeout = %s, want %s", got, test.want)
			}
		})
	}
}

func TestGatewayRouteOverridesUseOneWildcardAndIgnoreRequestPort(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		resources, err := Build(Inputs{
			LegacyGateway:    legacy,
			DiscoveryAddress: "agentiod.agentio-system.svc:15012",
			TrustDomain:      "cluster.local",
			Gateway: testGateway(&configv1.EgressGateway{
				Http: &configv1.GatewayHttpSettings{
					Routing: &configv1.HttpRoutingSettings{
						Fallback: &configv1.HttpRouteSettings{Timeout: durationpb.New(time.Second)},
						HostOverrides: []*configv1.HttpRouteOverride{
							{
								Hosts:    []string{"*", "api.example.com"},
								Settings: &configv1.HttpRouteSettings{Timeout: durationpb.New(2 * time.Second)},
							},
							{
								Hosts:    []string{"*.example.org"},
								Settings: &configv1.HttpRouteSettings{Timeout: durationpb.New(3 * time.Second)},
							},
						},
					},
				},
			}),
		})
		if err != nil {
			t.Fatal(err)
		}
		routes := messagesOf(
			t,
			resources,
			model.RouteType,
			func() *routev3.RouteConfiguration { return &routev3.RouteConfiguration{} },
		)
		for _, name := range []string{HTTPDynamicForwardProxy, TLSConnectOriginate} {
			rc := routes[name]
			if !rc.GetIgnorePortInHostMatching() {
				t.Fatalf("%s must match api.example.com:8443 and api.example.com identically", name)
			}
			seen := map[string]bool{}
			for _, vh := range rc.GetVirtualHosts() {
				for _, domain := range vh.GetDomains() {
					if seen[domain] {
						t.Fatalf("duplicate virtual-host domain %q", domain)
					}
					seen[domain] = true
					want := 2 * time.Second
					if domain == "*.example.org" {
						want = 3 * time.Second
					}
					if got := vh.GetRoutes()[1].GetRoute().GetTimeout().AsDuration(); got != want {
						t.Fatalf("domain %s timeout = %v, want %v", domain, got, want)
					}
				}
			}
			if len(seen) != 3 || !seen["*"] || !seen["api.example.com"] || !seen["*.example.org"] {
				t.Fatalf("unexpected domains: %v", seen)
			}
		}
	}
}

func TestGatewayRoutesUseSupportedAgentioRetries(t *testing.T) {
	resources, err := Build(Inputs{
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local",
		Gateway: testGateway(&configv1.EgressGateway{
			Http: &configv1.GatewayHttpSettings{
				Routing: &configv1.HttpRoutingSettings{
					Fallback: &configv1.HttpRouteSettings{Timeout: durationpb.New(12 * time.Second)},
					HostOverrides: []*configv1.HttpRouteOverride{{
						Hosts: []string{"api.example.com"},
						Settings: &configv1.HttpRouteSettings{
							Retries: &networkingv1alpha3.HTTPRetry{
								Attempts: 3,
								RetryOn:  "connect-failure,refused-stream",
							},
						},
					}},
				},
			},
		}),
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	routes := messagesOf(
		t,
		resources,
		model.RouteType,
		func() *routev3.RouteConfiguration { return &routev3.RouteConfiguration{} },
	)
	for _, name := range []string{HTTPDynamicForwardProxy, TLSConnectOriginate} {
		config := routes[name]
		configured := config.GetVirtualHosts()[0].GetRoutes()[1]
		if got := configured.GetRoute().GetTimeout().AsDuration(); got != 0 {
			t.Errorf("route %s host override inherited fallback timeout: %s", name, got)
		}
		retry := configured.GetRoute().GetRetryPolicy()
		if retry.GetHostSelectionRetryMaxAttempts() != 5 || len(retry.GetRetryHostPredicate()) != 1 ||
			retry.GetRetryHostPredicate()[0].GetName() != "envoy.retry_host_predicates.previous_hosts" {
			t.Errorf("route %s configured retry host selection = %+v", name, retry)
		}
		fallback := config.GetVirtualHosts()[1].GetRoutes()[1]
		if got := fallback.GetRoute().GetTimeout().AsDuration(); got != 12*time.Second {
			t.Errorf("route %s fallback timeout = %s, want 12s", name, got)
		}
		if retry := fallback.GetRoute().
			GetRetryPolicy(); retry.GetRetryOn() != "reset-before-request" ||
			retry.GetNumRetries().GetValue() != 2 {
			t.Errorf("route %s default retry = %+v", name, retry)
		}
	}
}

func TestForwardRouteConvertsSupportedAgentioRetryFields(t *testing.T) {
	tests := []struct {
		name              string
		retries           *networkingv1alpha3.HTTPRetry
		wantNil           bool
		wantRetryOn       string
		wantCodes         []uint32
		wantPreviousHosts bool
		wantRemote        bool
	}{
		{
			name: "numeric status and spaces",
			retries: &networkingv1alpha3.HTTPRetry{
				Attempts: 2,
				RetryOn:  " 5xx, 404, , 503,connect-failure ",
			},
			wantRetryOn:       "5xx,connect-failure,retriable-status-codes",
			wantCodes:         []uint32{404, 503},
			wantPreviousHosts: true,
		},
		{
			name:              "remote localities",
			retries:           &networkingv1alpha3.HTTPRetry{Attempts: 2, RetryRemoteLocalities: wrapperspb.Bool(true)},
			wantRetryOn:       "connect-failure,refused-stream,unavailable,cancelled,retriable-status-codes",
			wantPreviousHosts: true,
			wantRemote:        true,
		},
		{name: "attempts disabled", retries: &networkingv1alpha3.HTTPRetry{Attempts: 0}, wantNil: true},
		{
			name: "ignore previous hosts enabled",
			retries: &networkingv1alpha3.HTTPRetry{
				Attempts:                 2,
				RetryIgnorePreviousHosts: wrapperspb.Bool(true),
			},
			wantRetryOn:       "connect-failure,refused-stream,unavailable,cancelled,retriable-status-codes",
			wantPreviousHosts: true,
		},
		{
			name:        "ignore previous hosts disabled",
			retries:     &networkingv1alpha3.HTTPRetry{Attempts: 2, RetryIgnorePreviousHosts: wrapperspb.Bool(false)},
			wantRetryOn: "connect-failure,refused-stream,unavailable,cancelled,retriable-status-codes",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := forwardRoute(
				"test",
				&configv1.HttpRouteSettings{Retries: test.retries},
			).GetRoute().
				GetRetryPolicy()
			if test.wantNil {
				if policy != nil {
					t.Fatalf("retry policy = %+v, want nil", policy)
				}
				return
			}
			if policy.GetRetryOn() != test.wantRetryOn ||
				!slices.Equal(policy.GetRetriableStatusCodes(), test.wantCodes) {
				t.Errorf(
					"retry-on/codes = %q/%v, want %q/%v",
					policy.GetRetryOn(),
					policy.GetRetriableStatusCodes(),
					test.wantRetryOn,
					test.wantCodes,
				)
			}
			if got := len(policy.GetRetryHostPredicate()) == 1; got != test.wantPreviousHosts {
				t.Errorf("previous-host predicate = %v, want %v", got, test.wantPreviousHosts)
			}
			if test.wantRemote {
				config := &previousprioritiesv3.PreviousPrioritiesConfig{}
				if policy.GetRetryPriority().GetName() != "envoy.retry_priorities.previous_priorities" {
					t.Fatalf("retry priority = %+v", policy.GetRetryPriority())
				}
				if err := policy.GetRetryPriority().GetTypedConfig().UnmarshalTo(config); err != nil {
					t.Fatalf("decode retry priority: %v", err)
				}
				if config.GetUpdateFrequency() != 2 {
					t.Errorf("retry priority update frequency = %d, want 2", config.GetUpdateFrequency())
				}
			} else if policy.GetRetryPriority() != nil {
				t.Errorf("retry priority = %+v, want nil", policy.GetRetryPriority())
			}
		})
	}
}
