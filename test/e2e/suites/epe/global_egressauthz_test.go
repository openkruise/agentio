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

package epe

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/structpb"

	"github.com/openkruise/agentio/test/e2e"
	e2econfig "github.com/openkruise/agentio/test/e2e/config"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

// Headless Services provide controlled A/AAAA records in the cluster DNS. No
// external DNS service or IPv6 connectivity is needed: IPv6 is never dialed.
func TestEPEIPv4OnlyDNS(t *testing.T) {
	fixture, scope := newEgressEPE(t)
	namespace := trafficFixture.Namespace.Name()
	v4 := []string{
		trafficFixture.Server.WorkloadsOrFail(t)[0].Address,
		trafficFixture.Client.WorkloadsOrFail(t)[0].Address,
	}
	for _, name := range []string{"epe-dns-mixed", "epe-dns-v6-only"} {
		addresses := v4
		if name == "epe-dns-v6-only" {
			addresses = nil
		}
		e2econfig.New(scope).
			Eval(namespace, map[string]any{"Name": name, "IPv4": addresses}, egressEPEDNSYAML).
			ApplyOrFail(t, kube.CreateOnly)
	}
	mixed := "epe-dns-mixed." + namespace + ".svc.cluster.local"
	v6Only := "epe-dns-v6-only." + namespace + ".svc.cluster.local"
	// Prove the AAAA records actually exist before testing that EPE ignores
	// them. Port-forwarding cluster DNS avoids dependence on the host resolver.
	environment := suite.Environment(t)
	ctx, cancel := e2e.Context(t, 2*time.Minute)
	defer cancel()
	pods, err := environment.Kube.WaitReadyPods(ctx, "kube-system", "k8s-app=kube-dns", 1)
	if err != nil {
		t.Fatal(err)
	}
	dnsAddress := epeForwardPort(t, environment, "kube-system", pods[0].Name, 53)
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", dnsAddress)
		},
	}
	for _, host := range []string{mixed, v6Only} {
		harness.RetryAssertion(t, time.Minute, time.Second, func() error {
			addresses, err := resolver.LookupIP(ctx, "ip6", host+".")
			if err != nil {
				return err
			}
			if len(addresses) != 1 || addresses[0].String() != "2001:db8::1" {
				return fmt.Errorf("AAAA %s = %v", host, addresses)
			}
			return nil
		})
	}
	step := func(name string, fn func(*testing.T)) {
		t.Helper()
		if !t.Run(name, fn) {
			t.FailNow()
		}
	}
	harness.RetryAssertion(t, time.Minute, time.Second, func() error {
		addresses, err := resolver.LookupIP(t.Context(), "ip4", mixed+".")
		if err != nil {
			return err
		}
		if len(addresses) != 2 {
			return fmt.Errorf("A %s = %v, want two IPv4 endpoints", mixed, addresses)
		}
		return nil
	})
	step("matching_original_is_preserved", func(t *testing.T) {
		for _, ip := range v4 {
			target := net.JoinHostPort(ip, "18080")
			for range 8 {
				request := fixture.request(net.JoinHostPort(mixed, "18080"), "/dns", true)
				request.Attributes["envoy.filters.http.ext_proc"].Fields["destination.address"] = structpb.NewStringValue(
					target,
				)
				response, err := fixture.sendHeaders(t.Context(), request)
				if err != nil {
					t.Fatal(err)
				}
				if err := checkEPEHeaders(response, target, 0); err != nil {
					t.Fatal(err)
				}
			}
		}
	})
	step("only_ipv4_candidates_and_random_selection", func(t *testing.T) {
		seen := make(map[string]bool)
		for range 128 {
			response, err := fixture.headers(t.Context(), net.JoinHostPort(mixed, "18080"), "/dns", true)
			if err != nil {
				t.Fatal(err)
			}
			address, err := netip.ParseAddrPort(epePinnedAddress(response))
			if err != nil || address.Port() != 18080 ||
				(address.Addr().String() != v4[0] && address.Addr().String() != v4[1]) {
				t.Fatalf("unexpected DNS target: %v, %v", response, err)
			}
			seen[address.Addr().String()] = true
		}
		if len(seen) != 2 {
			t.Fatalf("selection stayed on one IPv4 endpoint: %v", seen)
		}
	})
	step("aaaa_only_domain_fails_resolution", func(t *testing.T) {
		response, err := fixture.headers(t.Context(), net.JoinHostPort(v6Only, "18080"), "/dns", true)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkEPEHeaders(response, "", 500); err != nil {
			t.Fatal(err)
		}
		if response.GetImmediateResponse().GetDetails() != "epe_request_authorization_failed" {
			t.Fatalf("unexpected resolution failure: %v", response)
		}
	})
	step("ipv6_literal_and_explicit_upstream_skip_dns", func(t *testing.T) {
		for _, ip := range []string{"2001:db8::1", "::1"} {
			target := net.JoinHostPort(ip, "18080")
			fixture.wantHeaders(t, target, "/dns", true, 0)
			request := fixture.request(net.JoinHostPort(v6Only, "18080"), "/dns", true)
			request.Attributes["envoy.filters.http.ext_proc"].Fields["filter_state['agentio.route.upstream']"] = structpb.NewStringValue(
				target,
			)
			response, err := fixture.sendHeaders(t.Context(), request)
			if err != nil {
				t.Fatal(err)
			}
			if err := checkEPEHeaders(response, target, 0); err != nil {
				t.Fatal(err)
			}
		}
	})
	denyTarget := func(cidr string) *e2econfig.Plan {
		return e2econfig.New(scope).
			Eval(namespace, map[string]string{"CIDR": cidr, "Client": trafficFixture.Client.Name()}, `
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: dns-target-policy
spec:
  selector:
    matchLabels: {app: "{{ .Client }}"}
  tcpRules:
  - name: denied-destination
    action: Deny
    match:
    - cidrs: ["{{ .CIDR }}"]
`)
	}
	// Deny one IPv4 target, keeping the other allowed: a denied original must
	// not switch to either the other IPv4 candidate or the AAAA candidate.
	step("denied_original_does_not_fall_back", func(t *testing.T) {
		denyTarget(v4[0]+"/32").ApplyOrFail(t, kube.CreateOnly)
		fixture.wantHeaders(t, net.JoinHostPort(v4[0], "18080"), "/dns", true, 403)
		request := fixture.request(net.JoinHostPort(mixed, "18080"), "/dns", true)
		request.Attributes["envoy.filters.http.ext_proc"].Fields["destination.address"] = structpb.NewStringValue(
			net.JoinHostPort(v4[0], "18080"),
		)
		response, err := fixture.sendHeaders(t.Context(), request)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkEPEHeaders(response, "", 403); err != nil {
			t.Fatal(err)
		}
		fixture.wantHeaders(t, net.JoinHostPort(v4[1], "18080"), "/dns", true, 0)
	})
	step("denied_ipv4_never_falls_back_to_aaaa", func(t *testing.T) {
		denyTarget("0.0.0.0/0").ApplyOrFail(t, kube.ReconcileOwned)
		fixture.wantHeaders(t, net.JoinHostPort(v4[1], "18080"), "/dns", true, 403)
		response, err := fixture.headers(t.Context(), net.JoinHostPort(mixed, "18080"), "/dns", true)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkEPEHeaders(response, "", 403); err != nil {
			t.Fatal(err)
		}
	})
}

const egressEPEDNSYAML = `
apiVersion: v1
kind: Service
metadata:
  name: {{ .Name }}
spec:
  clusterIP: None
  ports: [{name: http, port: 18080, protocol: TCP}]
---
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata:
  name: {{ .Name }}-v6
  labels:
    kubernetes.io/service-name: {{ .Name }}
addressType: IPv6
ports: [{name: http, port: 18080, protocol: TCP}]
endpoints:
- addresses: ["2001:db8::1"]
  conditions: {ready: true}
{{ if .IPv4 }}
---
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata:
  name: {{ .Name }}-v4
  labels:
    kubernetes.io/service-name: {{ .Name }}
addressType: IPv4
ports: [{name: http, port: 18080, protocol: TCP}]
endpoints:
{{ range .IPv4 }}
- addresses: ["{{ . }}"]
  conditions: {ready: true}
{{ end }}
{{ end }}
`
