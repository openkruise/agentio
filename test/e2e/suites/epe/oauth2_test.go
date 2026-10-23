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
	"bufio"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/test/e2e"
	"github.com/openkruise/agentio/test/e2e/components/echo"
	e2econfig "github.com/openkruise/agentio/test/e2e/config"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

// TestEPEOAuth2DeviceFlow traverses the injected proxy, real Envoy gateway,
// production EPE and an HTTP credential service. Authorization remains pending
// until the test driver approves it; the client receives only placeholder tokens.
func TestEPEOAuth2DeviceFlow(t *testing.T) {
	environment, scope := rig.BeginScenario(t)
	ctx, cancel := e2e.Context(t, 8*time.Minute)
	defer cancel()
	const name = "epe-oauth2"
	const caller = "epe-oauth2-client"
	namespace := resolvedAgentioConfig.Namespace
	callerNamespace := trafficFixture.Namespace.Name()
	host := name + "-http." + namespace + ".svc.cluster.local"

	// Give the HTTPS origin a test CA with a matching DNS SAN. The EnvoyFilter
	// below trusts it only in this scenario; downstream curl trusts Agentio's CA.
	cert := newEPECertificate(t, nil, "")
	cert.Leaf.DNSNames = []string{host}
	cert.Leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	der, err := x509.CreateCertificate(rand.Reader, cert.Leaf, cert.Leaf, cert.Leaf.PublicKey, cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	cert.Certificate = [][]byte{der}
	e2econfig.New(scope).EvalFile(namespace, map[string]any{
		"Name":         name,
		"Namespace":    namespace,
		"Host":         host,
		"FixtureImage": resolvedAgentioConfig.ExtProcImage,
		"EPEImage":     resolvedAgentioConfig.EPEImage,
		"Certificate":  string(epeCertificatePEM(cert)),
		"Key":          string(epePrivateKeyPEM(t, cert)),
	}, "testdata/oauth2.yaml").ApplyOrFail(t, kube.CreateOnly)
	e2econfig.New(scope).Eval(callerNamespace, map[string]any{
		"Caller":     caller,
		"EchoImage":  echo.DefaultImage,
		"ProxyImage": resolvedAgentioConfig.ZtunnelImage,
	}, providerCallerYAML).ApplyOrFail(t, kube.CreateOnly)
	for _, fixture := range []struct {
		namespace string
		selector  string
	}{
		{namespace, "app=" + name}, {namespace, "app=" + name + "-http"}, {callerNamespace, "app=" + caller},
	} {
		if _, err := environment.Kube.WaitReadyPods(ctx, fixture.namespace, fixture.selector, 1); err != nil {
			t.Fatal(err)
		}
	}
	observer := "http://" + epeForwardPort(t, environment, namespace, name+"-http", 8080)
	admin := "http://" + epeForwardPort(t, environment, namespace, name, 15000)
	applyEPEProviderConfig(t, scope, name, host)
	e2econfig.New(scope).
		EvalFile(callerNamespace, map[string]any{"Name": name, "Caller": caller, "Host": host}, "testdata/oauth2-profile.yaml").
		ApplyOrFail(t, kube.CreateOnly)
	harness.RetryAssertion(t, time.Minute, time.Second, func() error {
		var listing struct {
			Profiles []struct {
				Name string `json:"name"`
			} `json:"profiles"`
		}
		if err := readCalloutJSON(ctx, admin+"/debug/profiles", &listing); err != nil {
			return err
		}
		for _, p := range listing.Profiles {
			if p.Name == name {
				return nil
			}
		}
		return fmt.Errorf("EPE has not compiled the OAuth2 profile")
	})
	// Pass only the public MITM trust bundle to curl. The workload mTLS CA is
	// separate and cannot verify certificates issued for intercepted HTTPS.
	roots, err := environment.Cluster.Kube.CoreV1().
		Secrets(namespace).
		Get(ctx, "agentio-mitm-ca", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	request := func(path, body, contentType string) (status int, headers http.Header, result map[string]any, err error) {
		args := []string{"curl", "--silent", "--show-error", "--max-time", "15", "--noproxy", "*",
			"--include", "--http1.1", "--cacert", "/dev/stdin", "--resolve", host + ":443:192.0.2.1",
			"--header", "Authorization: Bearer unused", "https://" + host + path}
		if contentType != "" {
			args = append(args, "--header", "Content-Type: "+contentType, "--data-binary", body)
		}
		stdout, stderr, err := environment.Kube.Exec(
			ctx,
			callerNamespace,
			caller,
			"app",
			args,
			strings.NewReader(string(roots.Data["root-cert.pem"])),
		)
		if err != nil {
			return 0, nil, nil, fmt.Errorf("OAuth2 curl: %w: %s", err, stderr)
		}
		if strings.Contains(stdout, "oauth2-fixture-private-") {
			return 0, nil, nil, fmt.Errorf("private fixture credential entered a client response")
		}
		response, err := http.ReadResponse(bufio.NewReader(strings.NewReader(stdout)), nil)
		if err != nil {
			return 0, nil, nil, err
		}
		defer func() { err = errors.Join(err, response.Body.Close()) }()
		result = map[string]any{}
		err = json.NewDecoder(response.Body).Decode(&result)
		return response.StatusCode, response.Header, result, err
	}
	control := func(t *testing.T, path string) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, observer+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if err := response.Body.Close(); err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("fixture control %s: %s", path, response.Status)
		}
	}
	observations := func(t *testing.T) oauth2Observation {
		t.Helper()
		var out oauth2Observation
		if err := readCalloutJSON(ctx, observer+"/observations", &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	check := func(t *testing.T, path, body, format string, status int) map[string]any {
		t.Helper()
		got, headers, out, err := request(path, body, format)
		if err != nil {
			t.Fatal(err)
		}
		if got != status {
			t.Fatalf("%s status=%d body=%v, want %d", path, got, out, status)
		}
		if path != "/resource" && (headers.Get("Cache-Control") != "no-store" || headers.Get("Pragma") != "no-cache") {
			t.Fatalf("cacheable OAuth response: %v", headers)
		}
		return out
	}
	step := func(name string, fn func(*testing.T)) {
		t.Helper()
		if !t.Run(name, fn) {
			t.FailNow()
		}
	}
	const form = "application/x-www-form-urlencoded"
	const deviceGrant = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=fixture-session&client_secret=must-not-reach-provider"
	wantPlaceholders := func(t *testing.T, out map[string]any) {
		t.Helper()
		if out["access_token"] != "unused" || out["refresh_token"] != "unused" || out["token_type"] != "Bearer" ||
			out["scope"] != "fixture.read" ||
			out["code"] != float64(0) {
			t.Fatalf("token response: %v", out)
		}
	}
	resource := func(t *testing.T) {
		t.Helper()
		out := check(t, "/resource", "", "", 200)
		if out["authenticated"] != true || out["data"] != "fixture document" {
			t.Fatalf("protected resource: %v", out)
		}
	}
	step("https_gateway_ready", func(t *testing.T) {
		harness.RetryAssertion(t, time.Minute, time.Second, func() error {
			status, _, body, err := request("/probe", "", "")
			if err != nil {
				return err
			}
			if status != 200 || body["ready"] != true {
				return fmt.Errorf("HTTPS origin not reachable: %d %v", status, body)
			}
			return nil
		})
	})
	step("unauthorized_resource_stops_before_origin", func(t *testing.T) {
		out := check(t, "/resource", "", "", 401)
		if out["error"] != "invalid_token" || out["code"] != float64(99991663) || observations(t).OriginCalls != 0 {
			t.Fatalf("unauthorized resource: %v", out)
		}
	})
	step("device_authorization", func(t *testing.T) {
		out := check(
			t,
			"/device",
			"scope=fixture.read&client_id=untrusted&client_secret=must-not-reach-provider",
			form,
			200,
		)
		if out["device_code"] != "fixture-session" || out["user_code"] != "FIXTURE-CODE" ||
			out["verification_uri"] != "https://approve.example.test/device" {
			t.Fatalf("device response: %v", out)
		}
	})
	for _, pending := range []struct {
		name   string
		status int
		code   string
	}{
		{"standard_pending", 400, "authorization_pending"}, {"http200_pending", 200, "authorization_pending"}, {"http200_slow_down", 200, "slow_down"},
	} {
		step(pending.name, func(t *testing.T) {
			control(t, fmt.Sprintf("/pending?status=%d&error=%s", pending.status, pending.code))
			// Two successive replies prove waiting remains nonterminal until approval.
			for range 2 {
				status, headers, out, err := request("/token", deviceGrant, form)
				if err != nil {
					t.Fatal(err)
				}
				if status != pending.status || out["error"] != pending.code || headers.Get("Retry-After") != "1" ||
					out["code"] != float64(20050) ||
					out["access_token"] != nil ||
					out["refresh_token"] != nil {
					t.Fatalf("pending response: status=%d headers=%v body=%v", status, headers, out)
				}
			}
		})
	}
	step("approved_login_and_injection", func(t *testing.T) {
		control(t, "/authorize")
		wantPlaceholders(t, check(t, "/token", deviceGrant, form, 200))
		resource(t)
	})
	step("form_and_json_refresh_keep_placeholders", func(t *testing.T) {
		for _, refresh := range []struct {
			format string
			body   string
		}{
			{form, "grant_type=refresh_token&refresh_token=unused&client_secret=must-not-reach-provider"},
			{"application/json; charset=utf-8", `{"grant_type":"refresh_token","refresh_token":"unused","client_secret":"must-not-reach-provider"}`},
		} {
			wantPlaceholders(t, check(t, "/token", refresh.body, refresh.format, 200))
			resource(t)
		}
	})
	step("authorization_loss_is_observed_without_caching", func(t *testing.T) {
		control(t, "/pending?status=400&error=authorization_pending")
		out := check(t, "/resource", "", "", 401)
		if out["error"] != "invalid_token" {
			t.Fatalf("authorization loss: %v", out)
		}
		observed := observations(t)
		if observed.OriginCalls != 3 || observed.RejectedCalls != 0 || observed.BypassCalls != 0 ||
			observed.Calls["CreateOAuth2DeviceSession"] != 1 ||
			observed.Calls["PollOAuth2DeviceSession"] != 7 ||
			observed.Calls["GetOAuth2DeviceAccessToken"] != 7 {
			t.Fatalf("actual HTTP hops: %+v", observed)
		}
	})
}

type oauth2Observation struct {
	Calls         map[string]int `json:"calls"`
	OriginCalls   int            `json:"originCalls"`
	RejectedCalls int            `json:"rejectedCalls"`
	BypassCalls   int            `json:"bypassCalls"`
}
