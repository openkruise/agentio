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
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/structpb"

	"github.com/openkruise/agentio/test/e2e"
	e2econfig "github.com/openkruise/agentio/test/e2e/config"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

// Run without TrafficPolicy authorization so neither TrafficPolicy nor ztunnel
// authorization can account for a rejection from the global EPE configuration.
func TestEPEGlobalDeniedCIDRs(t *testing.T) {
	fixture, scope := newEgressEPE(t, false)
	serverIP := trafficFixture.Server.ServiceIPOrFail(t)
	clientIP := trafficFixture.Client.ServiceIPOrFail(t)
	target := net.JoinHostPort(serverIP, "80")
	otherTarget := net.JoinHostPort(clientIP, "80")
	anonymous := *fixture
	anonymous.pod, anonymous.namespace = "", ""
	otherWorkload := *fixture
	serverPod := trafficFixture.Server.WorkloadsOrFail(t)[0].Name
	otherWorkload.pod = serverPod
	callers := []*egressEPE{fixture, &anonymous, &otherWorkload}
	step := func(name string, fn func(*testing.T)) {
		t.Helper()
		if !t.Run(name, fn) {
			t.FailNow()
		}
	}
	checkDefaults := func(t *testing.T) {
		t.Helper()
		for _, host := range []string{"127.0.0.1", "127.0.0.2", "::1", "0.0.0.0", "::", "169.254.1.1", "fe80::1", "::ffff:127.0.0.1"} {
			destination := net.JoinHostPort(host, "15000")
			response, err := anonymous.headers(t.Context(), destination, "/global-egress", true)
			if err != nil {
				t.Fatal(err)
			}
			if err := checkEPEHeaders(response, destination, 403); err != nil {
				t.Fatal(err)
			}
			if response.GetImmediateResponse().GetDetails() != "epe_egress_denied" {
				t.Fatalf("unexpected rejection: %v", response)
			}
		}
		// Only invoke ext_proc; never send an actual request to cloud metadata.
		anonymous.wantHeaders(t, "100.100.100.200:80", "/global-egress", true, 0)
	}
	gateway := func(t *testing.T, status int) {
		t.Helper()
		harness.RetryAssertion(t, 2*time.Minute, time.Second, func() error {
			ctx, cancel := e2e.Context(t, 15*time.Second)
			defer cancel()
			stdout, stderr, err := trafficFixture.Client.Exec(ctx, []string{
				"curl", "-sS", "--max-time", "10", "-w", "\n%{http_code}",
				"http://" + trafficFixture.Server.Address() + "/global-egress",
			})
			if err != nil {
				return fmt.Errorf("gateway: stdout=%q stderr=%q: %w", stdout, stderr, err)
			}
			if !strings.HasSuffix(stdout, "\n"+strconv.Itoa(status)) {
				return fmt.Errorf("gateway: stdout=%q stderr=%q, want status %d", stdout, stderr, status)
			}
			want := "Hostname=" + serverPod
			if status == 403 {
				want = `"code":"epe_egress_denied"`
			}
			if !strings.Contains(stdout, want) {
				return fmt.Errorf("gateway response %q lacks %q", stdout, want)
			}
			return nil
		})
	}
	step("defaults_without_trafficpolicy_or_identity", func(t *testing.T) {
		for _, caller := range callers {
			caller.wantHeaders(t, target, "/global-egress", true, 0)
		}
		checkDefaults(t)
	})
	// A profile bypass must not bypass destination authorization.
	e2econfig.New(scope).YAML(trafficFixture.Namespace.Name(), `
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: epe-global-bypass
spec:
  selector: {}
  rules:
  - name: bypass
    match:
    - domains: ["*"]
      paths: [{type: Exact, value: /global-egress}]
    actions:
      bypass: true
  - name: unreachable-block
    match:
    - domains: ["*"]
      paths: [{type: Exact, value: /global-egress}]
    actions:
      block: {statusCode: 451, body: bypass-was-not-applied}
  - name: convergence-marker
    match:
    - domains: ["*"]
      paths: [{type: Exact, value: /global-egress-profile-ready}]
    actions:
      block: {statusCode: 452, body: profile-ready}
`).ApplyOrFail(t, kube.CreateOnly)
	fixture.wantHeaders(t, target, "/global-egress-profile-ready", true, 452)
	applyEPEProviderConfig(t, scope, "epe-egressauthz")
	gateway(t, 200)
	base := egressEPEConfig(
		scope,
		"epe-egressauthz",
		fmt.Sprintf("egressAuthorization: {deniedCIDRs: [%s/32]}", serverIP),
	)
	primary := egressEPEConfig(
		scope,
		"epe-egressauthz-primary",
		fmt.Sprintf("egressAuthorization: {deniedCIDRs: [%s/32]}", clientIP),
	)
	step("create_global_deny_for_all_callers", func(t *testing.T) {
		base.ApplyOrFail(t, kube.CreateOnly)
		for _, caller := range callers {
			caller.wantHeaders(t, target, "/global-egress", true, 403)
		}
		checkDefaults(t)
		gateway(t, 403)
	})
	step("primary_replaces_user_entries", func(t *testing.T) {
		primary.ApplyOrFail(t, kube.CreateOnly)
		fixture.wantHeaders(t, otherTarget, "/global-egress", true, 403)
		fixture.wantHeaders(t, target, "/global-egress", true, 0)
		checkDefaults(t)
		gateway(t, 200)
	})
	step("empty_list_retains_mandatory_denies", func(t *testing.T) {
		egressEPEConfig(
			scope,
			"epe-egressauthz-primary",
			"egressAuthorization: {deniedCIDRs: []}",
		).ApplyOrFail(t, kube.ReconcileOwned)
		fixture.wantHeaders(t, otherTarget, "/global-egress", true, 0)
		checkDefaults(t)
		gateway(t, 200)
	})
	step("delete_primary_restores_base", func(t *testing.T) {
		primary.DeleteOrFail(t)
		fixture.wantHeaders(t, target, "/global-egress", true, 403)
		gateway(t, 403)
	})
	step("delete_base_restores_defaults", func(t *testing.T) {
		base.DeleteOrFail(t)
		fixture.wantHeaders(t, target, "/global-egress", true, 0)
		checkDefaults(t)
		gateway(t, 200)
	})
}

func egressEPEConfig(scope *kube.ResourceScope, name, content string) *e2econfig.Plan {
	return e2econfig.New(scope).Eval(resolvedAgentioConfig.Namespace, map[string]string{
		"Name":   name,
		"Config": content,
	}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .Name }}
data:
  config: {{ printf "%q" .Config }}
`)
}

// Headless Services provide controlled A/AAAA records in the cluster DNS. No
// external DNS service or IPv6 connectivity is needed: IPv6 is never dialed.
func TestEPEIPv4OnlyDNS(t *testing.T) {
	fixture, scope := newEgressEPE(t, false)
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
	step("ipv6_literal_and_explicit_upstream_still_authorized", func(t *testing.T) {
		for _, ip := range []string{"2001:db8::1", "::1"} {
			target := net.JoinHostPort(ip, "18080")
			status := 0
			if ip == "::1" {
				status = 403
			}
			fixture.wantHeaders(t, target, "/dns", true, status)
			request := fixture.request(net.JoinHostPort(v6Only, "18080"), "/dns", true)
			request.Attributes["envoy.filters.http.ext_proc"].Fields["filter_state['agentio.route.upstream']"] = structpb.NewStringValue(
				target,
			)
			response, err := fixture.sendHeaders(t.Context(), request)
			if err != nil {
				t.Fatal(err)
			}
			if err := checkEPEHeaders(response, target, status); err != nil {
				t.Fatal(err)
			}
		}
	})
	// Deny one IPv4 target, keeping the other allowed: a denied original must
	// not switch to either the other IPv4 candidate or the AAAA candidate.
	step("denied_original_does_not_fall_back", func(t *testing.T) {
		egressEPEConfig(
			scope,
			"epe-egressauthz",
			fmt.Sprintf("egressAuthorization: {deniedCIDRs: [%s/32]}", v4[0]),
		).ApplyOrFail(t, kube.CreateOnly)
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
		egressEPEConfig(
			scope,
			"epe-egressauthz",
			"egressAuthorization: {deniedCIDRs: [0.0.0.0/0]}",
		).ApplyOrFail(t, kube.ReconcileOwned)
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
