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

package gateway

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	utilexec "k8s.io/client-go/util/exec"

	"github.com/openkruise/agentio/test/e2e"
	"github.com/openkruise/agentio/test/e2e/components/echo"
	"github.com/openkruise/agentio/test/e2e/components/echo/check"
	e2econfig "github.com/openkruise/agentio/test/e2e/config"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/network"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

const tcpSecurityProfileYAML = `
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: tcp-address-policy
spec:
  priority: {{ .Priority }}
  selector:
    matchLabels: {app: "{{ .App }}"}
  tcpRules:
  - name: selected-address
    match: [{cidrs: ["{{ .CIDR }}"], ports: [{{ .Port }}]}]
    action: {{ .Action }}
`

func TestSandboxTLSWithoutSNI(t *testing.T) {
	environment, scope := rig.BeginScenario(t)
	applyTCPPassthrough(t, environment, scope, "[]")
	src, target := trafficFixture.Client, trafficFixture.Server
	address := target.ServiceIPOrFail(t)
	backend := target.WorkloadsOrFail(t)[0].Name
	call := func(denied bool) error {
		ctx, cancel := e2e.Context(t, 15*time.Second)
		defer cancel()
		// A literal IP URL makes curl omit SNI; the HTTP payload must remain encrypted at the gateway.
		stdout, stderr, err := src.Exec(ctx, []string{"curl", "-ksS", "--noproxy", "*", "--http1.1",
			"--connect-timeout", "5", "--max-time", "10", "-H", "Connection: close", "-w", "\n%{http_code}",
			"https://" + net.JoinHostPort(address, "443") + "/"})
		if denied {
			exit, ok := errors.AsType[utilexec.ExitError](err)
			if ok && (exit.ExitStatus() == 35 || exit.ExitStatus() == 56) && strings.TrimSpace(stdout) == "000" {
				return nil
			}
			return errors.Join(fmt.Errorf("want TLS reset, got stdout=%q stderr=%q", stdout, stderr), err)
		}
		if err != nil || !strings.HasSuffix(strings.TrimSpace(stdout), "\n200") ||
			!strings.Contains(stdout, "Hostname="+backend+"\n") {
			return errors.Join(
				fmt.Errorf("want original TLS backend %s and 200, got stdout=%q stderr=%q", backend, stdout, stderr),
				err,
			)
		}
		return nil
	}
	harness.RetryAssertion(t, 2*time.Minute, time.Second, func() error { return call(false) })
	var active *e2econfig.Plan
	for index, tc := range []struct {
		name      string
		domain    string
		tlsAction string
		tcpAction string
		port      int
		denied    bool
	}{
		{"exact SNI does not match absence", target.Address(), "Deny", "Allow", 443, false},
		{"suffix wildcard does not match absence", "*.example.com", "Deny", "Allow", 443, false},
		{"TLS deny all includes absent SNI", "*", "Deny", "Allow", 443, true},
		{"TLS passthrough skips own TCP deny", "*", "Passthrough", "Deny", 443, false},
		{"TLS port mismatch falls through", "*", "Deny", "Allow", 8443, false},
		{"unmatched TLS uses TCP deny", target.Address(), "Deny", "Deny", 443, true},
		{"unmatched TLS uses TCP allow", target.Address(), "Deny", "Allow", 443, false},
	} {
		if !t.Run(tc.name, func(t *testing.T) {
			active = e2econfig.New(scope).Eval(src.Namespace(), map[string]any{
				"App":       src.Name(),
				"Domain":    tc.domain,
				"TLSAction": tc.tlsAction,
				"TCPAction": tc.tcpAction,
				"Port":      tc.port,
			}, `
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: no-sni-policy
spec:
  selector:
    matchLabels: {app: "{{ .App }}"}
  rules:
  - name: tls
    match: [{domains: ["{{ .Domain }}"], ports: [{{ .Port }}]}]
    actions: {tls: {action: "{{ .TLSAction }}"}}
  tcpRules:
  - name: tcp
    match: [{cidrs: ["0.0.0.0/0", "::/0"]}]
    action: "{{ .TCPAction }}"
`)
			mode := kube.ReconcileOwned
			if index == 0 {
				mode = kube.CreateOnly
			}
			active.ApplyOrFail(t, mode)
			harness.RetryAssertion(t, 2*time.Minute, time.Second, func() error { return call(tc.denied) })
		}) {
			return
		}
	}
	active.DeleteOrFail(t)
	harness.RetryAssertion(t, 2*time.Minute, time.Second, func() error { return call(false) })
}

func TestSandboxTLSTCPResolvedDestination(t *testing.T) {
	environment, scope := rig.BeginScenario(t)
	applyTCPPassthrough(t, environment, scope, "[]")
	src, original, target := trafficFixture.Client, trafficFixture.Server, trafficFixture.AnotherServer
	originalIP := original.ServiceIPOrFail(t)
	cidr, err := network.HostCIDR(target.ServiceIPOrFail(t))
	if err != nil {
		t.Fatal(err)
	}
	e2econfig.New(scope).Eval(src.Namespace(), map[string]any{"App": src.Name()}, `
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: tls-passthrough-policy
spec:
  priority: 20
  selector:
    matchLabels: {app: "{{ .App }}"}
  rules:
  - name: passthrough
    match: [{domains: ["*"]}]
    actions: {tls: {action: Passthrough}}
  tcpRules:
  - name: deny-other
    match: [{cidrs: ["0.0.0.0/0", "::/0"]}]
    action: Deny
`).ApplyOrFail(t, kube.CreateOnly)
	targetName := target.WorkloadsOrFail(t)[0].Name
	originalName := original.WorkloadsOrFail(t)[0].Name
	call := func(t *testing.T, host, backend string, denied bool) error {
		ctx, cancel := e2e.Context(t, 15*time.Second)
		defer cancel()
		// Fix the original address while letting the gateway resolve a different SNI.
		stdout, stderr, err := src.Exec(ctx, []string{"curl", "-ksS", "--noproxy", "*", "--http1.1",
			"--connect-timeout", "5", "--max-time", "10", "--resolve", host + ":443:" + originalIP,
			"-H", "Connection: close", "-w", "\n%{http_code}", "https://" + host + "/"})
		if denied {
			exit, ok := errors.AsType[utilexec.ExitError](err)
			if ok && (exit.ExitStatus() == 35 || exit.ExitStatus() == 56) && strings.TrimSpace(stdout) == "000" {
				return nil
			}
			return errors.Join(fmt.Errorf("want TLS reset, got stdout=%q stderr=%q", stdout, stderr), err)
		}
		if err != nil || !strings.HasSuffix(strings.TrimSpace(stdout), "\n200") ||
			!strings.Contains(stdout, "Hostname="+backend+"\n") {
			return errors.Join(
				fmt.Errorf("want TLS backend %s and 200, got stdout=%q stderr=%q", backend, stdout, stderr),
				err,
			)
		}
		return nil
	}
	harness.RetryAssertion(
		t,
		2*time.Minute,
		time.Second,
		func() error { return call(t, target.Address(), targetName, false) },
	)
	var active *e2econfig.Plan
	for index, tc := range []struct {
		name     string
		action   string
		priority int
		port     int
		denied   bool
	}{
		{"higher TCP deny checks SNI-resolved address", "Deny", 10, 443, true},
		{"port miss permits SNI target", "Deny", 10, 8443, false},
		{"restore deny", "Deny", 10, 443, true},
		{"TCP allow permits SNI target", "Allow", 10, 443, false},
		{"restore deny before priority change", "Deny", 10, 443, true},
		{"higher SNI passthrough skips own and lower TCP deny", "Deny", 30, 443, false},
		{"restore deny before deletion", "Deny", 10, 443, true},
	} {
		if !t.Run(tc.name, func(t *testing.T) {
			active = e2econfig.New(scope).Eval(src.Namespace(), map[string]any{
				"App":      src.Name(),
				"CIDR":     cidr,
				"Port":     tc.port,
				"Action":   tc.action,
				"Priority": tc.priority,
			}, tcpSecurityProfileYAML)
			mode := kube.ReconcileOwned
			if index == 0 {
				mode = kube.CreateOnly
			}
			active.ApplyOrFail(t, mode)
			harness.RetryAssertion(t, 2*time.Minute, time.Second, func() error {
				if err := call(t, original.Address(), originalName, false); err != nil {
					return err
				}
				return call(t, target.Address(), targetName, tc.denied)
			})
		}) {
			return
		}
	}
	active.DeleteOrFail(t)
	harness.RetryAssertion(
		t,
		2*time.Minute,
		time.Second,
		func() error { return call(t, target.Address(), targetName, false) },
	)
}

func TestSandboxServerFirstSecurityProfile(t *testing.T) {
	environment, scope := rig.BeginScenario(t)
	server := echo.Deploy(t, environment, echo.Config{
		Name:      "tcp-policy-server-first",
		Namespace: trafficFixture.Namespace.Name(),
		Ports: []echo.Port{
			{Name: "tcp", Protocol: echo.TCP, ServicePort: 9092, WorkloadPort: 19092, ServerFirst: true},
			{Name: "control", Protocol: echo.TCP, ServicePort: 9093, WorkloadPort: 19093, ServerFirst: true},
		},
	})
	address := server.WorkloadsOrFail(t)[0].Address
	cidr, err := network.HostCIDR(address)
	if err != nil {
		t.Fatal(err)
	}
	applyTCPPassthrough(t, environment, scope, fmt.Sprintf(`[{"cidrs":[%q],"ports":[19092,19093]}]`, cidr))
	request := echo.CallOptions{Protocol: echo.TCP,
		Address:     address,
		Port:        19092,
		ServerFirst: true,
		Count:       1,
		Timeout:     5 * time.Second,
		Retry:       harness.FixedRetry(2*time.Minute, time.Second)}
	control := request
	control.Port = 19093
	src := trafficFixture.Client
	src.CallOrFail(t, request.WithCheck(check.OK()))
	src.CallOrFail(t, control.WithCheck(check.OK()))
	rejected := check.And(check.Error(), func(result echo.Result, err error) error {
		attempt := result.Attempts[len(result.Attempts)-1]
		message := err.Error() + attempt.Stdout + attempt.Stderr
		if strings.Contains(message, "EOF") || strings.Contains(message, "connection reset by peer") {
			return nil
		}
		return fmt.Errorf("want closed TCP connection, got %w", err)
	})
	var active *e2econfig.Plan
	for index, tc := range []struct {
		name   string
		action string
		app    string
		port   int
		denied bool
	}{
		{"deny despite skipped sniffing", "Deny", src.Name(), 19092, true},
		{"allow update", "Allow", src.Name(), 19092, false},
		{"deny update", "Deny", src.Name(), 19092, true},
		{"port mismatch", "Deny", src.Name(), 19094, false},
		{"restore matching port", "Deny", src.Name(), 19092, true},
		{"selector removed", "Deny", "not-the-client", 19092, false},
		{"selector restored", "Deny", src.Name(), 19092, true},
	} {
		if !t.Run(tc.name, func(t *testing.T) {
			active = e2econfig.New(scope).Eval(src.Namespace(), map[string]any{
				"App":      tc.app,
				"CIDR":     cidr,
				"Port":     tc.port,
				"Action":   tc.action,
				"Priority": 10,
			}, tcpSecurityProfileYAML)
			mode := kube.ReconcileOwned
			if index == 0 {
				mode = kube.CreateOnly
			}
			active.ApplyOrFail(t, mode)
			checker := check.OK()
			if tc.denied {
				checker = rejected
			}
			src.CallOrFail(t, request.WithCheck(checker))
			src.CallOrFail(t, control.WithCheck(check.OK()))
		}) {
			return
		}
	}
	active.DeleteOrFail(t)
	src.CallOrFail(t, request.WithCheck(check.OK()))
}
