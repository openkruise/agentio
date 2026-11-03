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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/openkruise/agentio/test/e2e"
	e2econfig "github.com/openkruise/agentio/test/e2e/config"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

// TestEPEHTTPCallout drives curl -> ztunnel -> Envoy -> EPE -> HTTP provider
// and origin, using candidate images and public CRDs in the sidecar test environment.
// Port-forwarding is used only to inspect observations and readiness.
func TestEPEHTTPCallout(t *testing.T) {
	environment, scope := rig.BeginScenario(t)
	namespace := resolvedAgentioConfig.Namespace
	const name = "epe-httpcallout"
	ctx, cancel := e2e.Context(t, 8*time.Minute)
	defer cancel()
	e2econfig.New(scope).Eval(namespace, map[string]any{
		"Name":         name,
		"Namespace":    namespace,
		"EPEImage":     resolvedAgentioConfig.EPEImage,
		"FixtureImage": resolvedAgentioConfig.ExtProcImage,
	}, httpCalloutDatapathYAML).ApplyOrFail(t, kube.CreateOnly)
	for _, selector := range []string{"app=" + name, "app=" + name + "-http"} {
		if _, err := environment.Kube.WaitReadyPods(ctx, namespace, selector, 1); err != nil {
			t.Fatal(err)
		}
	}
	admin := "http://" + epeForwardPort(t, environment, namespace, name, 15000)
	observer := "http://" + epeForwardPort(t, environment, namespace, name+"-http", 8080)
	origin := "http://" + name + "-http." + namespace + ".svc.cluster.local:8080"
	applyEPEProviderConfig(t, scope, name)

	for _, tc := range []struct {
		name           string
		kind           string
		provider       string
		request        string
		response       string
		strategy       string
		status         int
		body           string
		requestCalled  bool
		responseCalled bool
		originCalled   bool
	}{
		{"dual-body", "SecurityProfile", "mutate", `{"headers":{"enabled":true,"filter":{"allowList":["X-Visible"]}},"body":{"enabled":true,"maxBytes":3}}`, `{"headers":{"enabled":true,"filter":{"denyList":["Set-Cookie"]}},"body":{"enabled":true,"maxBytes":5}}`, "Block", 200, "changed by callout", true, true, true},
		{"global-metadata", "GlobalSecurityProfile", "continue", `{}`, `{}`, "Block", 200, "12345", true, true, true},
		{"deny", "SecurityProfile", "deny", `{}`, "", "Allow", 403, "blocked by callout", true, false, false},
		{"error-block", "SecurityProfile", "error", `{}`, "", "Block", 500, "", true, false, false},
		{"error-allow", "SecurityProfile", "error", `{}`, "", "Allow", 200, "12345", true, false, true},
		{"error-ignore", "SecurityProfile", "error", `{}`, "", "Ignore", 200, "12345", true, false, true},
		{"request-limit", "SecurityProfile", "mutate", `{"body":{"enabled":true,"maxBytes":2}}`, "", "Block", 500, "", false, false, false},
		{"response-limit", "SecurityProfile", "continue", `{}`, `{"body":{"enabled":true,"maxBytes":4}}`, "Block", 500, "", true, false, true},
	} {
		if !t.Run(tc.name, func(t *testing.T) {
			path := "/origin/" + tc.name
			profileName := name + "-" + tc.name
			action := map[string]any{
				"provider":     map[string]string{"name": tc.provider},
				"failStrategy": tc.strategy,
				"request":      json.RawMessage(tc.request),
			}
			if tc.response != "" {
				action["response"] = json.RawMessage(tc.response)
			}
			encoded, err := json.Marshal(action)
			if err != nil {
				t.Fatal(err)
			}
			profileNamespace := trafficFixture.Namespace.Name()
			if tc.kind == "GlobalSecurityProfile" {
				profileNamespace = ""
			}
			e2econfig.New(scope).Eval(profileNamespace, map[string]any{
				"Kind":   tc.kind,
				"Name":   profileName,
				"Client": trafficFixture.Client.Name(),
				"Path":   path,
				"Action": string(encoded),
			}, httpCalloutProfileYAML).ApplyOrFail(t, kube.CreateOnly)
			// Wait on the compiled store, not the API object: a rejected or not-yet-
			// observed profile must never make a fail-open case pass accidentally.
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
					if p.Name == profileName {
						return nil
					}
				}
				return fmt.Errorf("EPE has not compiled %s", profileName)
			})
			request := func() (err error) {
				stdout, stderr, err := trafficFixture.Client.Exec(ctx, []string{
					"curl",
					"--silent",
					"--show-error",
					"--max-time",
					"15",
					"--noproxy",
					"*",
					"--include",
					"--raw",
					"--header",
					"x-visible: visible",
					"--header",
					"authorization: request-secret",
					"--data-binary",
					"abc",
					origin + path,
				})
				if err != nil {
					return fmt.Errorf("curl: %w: %s", err, stderr)
				}
				response, err := http.ReadResponse(bufio.NewReader(strings.NewReader(stdout)), nil)
				if err != nil {
					return fmt.Errorf("parse HTTP response: %w: %s", err, stdout)
				}
				defer func() { err = errors.Join(err, response.Body.Close()) }()
				body, err := io.ReadAll(response.Body)
				if err != nil {
					return err
				}
				if response.StatusCode != tc.status || tc.body != "" && string(body) != tc.body {
					return fmt.Errorf("status/body = %d %q, want %d %q", response.StatusCode, body, tc.status, tc.body)
				}
				if tc.status == 200 && response.Header.Get("X-Origin-Policy") != profileName {
					return fmt.Errorf("origin did not receive the profile's header mutation: %s", stdout)
				}
				if tc.name == "dual-body" && response.Header.Get("X-Callout-Verdict") != "clean" {
					return fmt.Errorf("response mutation missing: %s", stdout)
				}
				return nil
			}
			if tc.name == "dual-body" {
				// The first positive result also proves gateway configuration convergence.
				harness.RetryAssertion(t, time.Minute, time.Second, request)
			} else if err := request(); err != nil {
				t.Fatal(err)
			}
			var observation struct {
				Invocations map[string]struct {
					Request struct {
						Headers map[string]string `json:"headers"`
						Body    *string           `json:"body"`
					} `json:"request"`
					Response *struct {
						Headers map[string]string `json:"headers"`
						Body    *string           `json:"body"`
					} `json:"response"`
				} `json:"invocations"`
				OriginCalls   int         `json:"originCalls"`
				OriginBody    string      `json:"originBody"`
				OriginHeaders http.Header `json:"originHeaders"`
			}
			if err := readCalloutJSON(
				ctx,
				observer+"/observations?path="+url.QueryEscape(path),
				&observation,
			); err != nil {
				t.Fatal(err)
			}
			_, requestSeen := observation.Invocations["request"]
			_, responseSeen := observation.Invocations["response"]
			if requestSeen != tc.requestCalled || responseSeen != tc.responseCalled ||
				(observation.OriginCalls > 0) != tc.originCalled {
				t.Fatalf(
					"HTTP hops: request=%t response=%t origin=%d; want %t/%t/%t",
					requestSeen,
					responseSeen,
					observation.OriginCalls,
					tc.requestCalled,
					tc.responseCalled,
					tc.originCalled,
				)
			}
			if tc.name == "dual-body" {
				request := observation.Invocations["request"].Request
				response := observation.Invocations["response"]
				if len(request.Headers) != 1 || request.Headers["x-visible"] != "visible" || request.Body == nil ||
					*request.Body != "abc" {
					t.Fatalf("request disclosure: %+v", request)
				}
				if response.Response == nil || response.Response.Body == nil || *response.Response.Body != "12345" ||
					response.Response.Headers["set-cookie"] != "" ||
					response.Response.Headers["x-public"] != "public" ||
					response.Request.Body != nil ||
					len(response.Request.Headers) != 0 {
					t.Fatalf("response disclosure: %+v", response)
				}
				if observation.OriginBody != "changed by callout" ||
					observation.OriginHeaders.Get("X-Callout-Verdict") != "clean" {
					t.Fatalf("origin did not receive request mutations: %+v", observation)
				}
			} else {
				for phase, invocation := range observation.Invocations {
					if len(invocation.Request.Headers) != 0 || invocation.Request.Body != nil ||
						invocation.Response != nil &&
							(len(invocation.Response.Headers) != 0 || invocation.Response.Body != nil) {
						t.Fatalf("%s disclosed content in a metadata-only callout: %+v", phase, invocation)
					}
				}
				if tc.originCalled && observation.OriginBody != "abc" {
					t.Fatalf("origin body=%q, want unchanged abc", observation.OriginBody)
				}
			}
		}) {
			t.FailNow()
		}
	}
	t.Run(
		"transport-lifecycle",
		func(t *testing.T) { testDeployedCalloutTransport(t, environment, scope, name, admin, observer, origin) },
	)
}

func readCalloutJSON(ctx context.Context, endpoint string, out any) (err error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, response.Body.Close()) }()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", endpoint, response.Status)
	}
	return json.NewDecoder(response.Body).Decode(out)
}

const httpCalloutProfileYAML = `
apiVersion: agents.kruise.io/v1alpha1
kind: {{ .Kind }}
metadata:
  name: {{ .Name }}
spec:
  selector:
    matchLabels: {app: {{ .Client }}}
  rules:
  - name: scan
    match:
    - domains: ["*"]
      paths: [{type: Exact, value: {{ .Path }}}]
    actions:
      headerManipulation:
        set: [{name: x-policy, value: {{ .Name }}}]
      httpCallout: {{ .Action }}
`

const httpCalloutDatapathYAML = `
apiVersion: v1
kind: Service
metadata:
  name: {{ .Name }}-http
spec:
  selector: {app: {{ .Name }}-http}
  ports: [{name: http, port: 8080, targetPort: 8080}]
---
apiVersion: v1
kind: Pod
metadata:
  name: {{ .Name }}-http
  labels: {app: {{ .Name }}-http, agentio.kruise.io/dataplane-mode: none}
spec:
  containers:
  - name: http
    image: {{ .FixtureImage }}
    args: ["-http-callout-port=8080", "-h2c", "-http2-max-streams=4"]
    readinessProbe:
      tcpSocket: {port: 8080}
      periodSeconds: 1
    resources:
      requests: {cpu: 10m, memory: 32Mi}
      limits: {cpu: 500m, memory: 128Mi}
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .Name }}
data:
  config: |
    extensionProviders:
    - name: transport
      httpCallout: {url: "http://{{ .Name }}-http.{{ .Namespace }}.svc.cluster.local:8080/continue", timeout: 30s, protocol: HTTP2, http2: {maxConcurrentStreams: 32}, connectionPool: {maxConnections: 8}}
    - name: mutate
      httpCallout: {url: "http://{{ .Name }}-http.{{ .Namespace }}.svc.cluster.local:8080/mutate", timeout: 2s}
    - name: continue
      httpCallout: {url: "http://{{ .Name }}-http.{{ .Namespace }}.svc.cluster.local:8080/continue", timeout: 2s}
    - name: deny
      httpCallout: {url: "http://{{ .Name }}-http.{{ .Namespace }}.svc.cluster.local:8080/respond", timeout: 2s}
    - name: error
      httpCallout: {url: "http://{{ .Name }}-http.{{ .Namespace }}.svc.cluster.local:8080/status", timeout: 2s}
---
apiVersion: v1
kind: Service
metadata:
  name: {{ .Name }}
spec:
  selector: {app: {{ .Name }}}
  ports: [{name: grpc, port: 9002, targetPort: 9002}]
---
apiVersion: v1
kind: Pod
metadata:
  name: {{ .Name }}
  labels: {app: {{ .Name }}, agentio.kruise.io/dataplane-mode: none}
spec:
  serviceAccountName: agentio-epe
  containers:
  - name: epe
    image: {{ .EPEImage }}
    args:
    - -epe-config={{ .Name }}
    - -epe-config-primary={{ .Name }}-primary
    - -namespace={{ .Namespace }}
    - -fail-closed-on-missing-identity=true
    - -enable-debug=true
    - --xds-address=agentiod.{{ .Namespace }}.svc:15012
    - --xds-root-path=/var/run/xds-root/root-cert.pem
    - --xds-token-path=/var/run/xds-token/token
    env:
    - name: POD_NAME
      valueFrom: {fieldRef: {fieldPath: metadata.name}}
    - name: POD_NAMESPACE
      valueFrom: {fieldRef: {fieldPath: metadata.namespace}}
    - name: POD_UID
      valueFrom: {fieldRef: {fieldPath: metadata.uid}}
    - name: POD_IP
      valueFrom: {fieldRef: {fieldPath: status.podIP}}
    volumeMounts:
    - {name: roots, mountPath: /var/run/xds-root, readOnly: true}
    - {name: token, mountPath: /var/run/xds-token, readOnly: true}
    readinessProbe:
      grpc: {port: 9003}
      periodSeconds: 1
    resources:
      requests: {cpu: 100m, memory: 128Mi}
      limits: {cpu: "1", memory: 512Mi}
  volumes:
  - name: roots
    configMap: {name: agentio-ca-root-cert}
  - name: token
    projected:
      sources:
      - serviceAccountToken:
          audience: agentio-ca
          expirationSeconds: 3600
          path: token
`
