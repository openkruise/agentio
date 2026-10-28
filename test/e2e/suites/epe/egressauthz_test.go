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
	"strconv"
	"strings"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/openkruise/agentio/test/e2e"
	e2econfig "github.com/openkruise/agentio/test/e2e/config"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

// TestEPEXDSTrafficPolicyLifecycle exercises Kubernetes -> native Workload and
// TrafficPolicy xDS -> EPE authorization. Calling ext_proc directly isolates
// EPE enforcement from the caller's ztunnel, which also consumes TrafficPolicy.
func TestEPEXDSTrafficPolicyLifecycle(t *testing.T) {
	fixture, scope := newEgressEPE(t, true)
	target := net.JoinHostPort(trafficFixture.Server.ServiceIPOrFail(t), "80")
	fixture.wantHeaders(t, target, "/xds-lifecycle", true, 0)

	policy := func(action, app string) *e2econfig.Plan {
		return e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
			"Action":      action,
			"App":         app,
			"Destination": trafficFixture.Server.ServiceIPOrFail(t),
		}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: epe-xds-lifecycle
spec:
  priority: 100
  selector:
    matchLabels: {app: "{{ .App }}"}
  egress:
    rules:
    - action: {{ .Action }}
      to: [{cidr: "{{ .Destination }}"}]
      ports: [{port: 80}]
`)
	}
	step := func(name string, fn func(*testing.T)) {
		t.Helper()
		if !t.Run(name, fn) {
			t.FailNow()
		}
	}
	initial := policy("reject", trafficFixture.Client.Name())
	step("missing_identity_is_rejected_by_xds", func(t *testing.T) {
		request := fixture.request(target, "/xds-lifecycle", true)
		request.Attributes = nil
		response, err := fixture.sendHeaders(t.Context(), request)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkEPEHeaders(response, target, 403); err != nil {
			t.Fatal(err)
		}
	})
	step("create_reject", func(t *testing.T) {
		initial.ApplyOrFail(t, kube.CreateOnly)
		fixture.wantHeaders(t, target, "/xds-lifecycle", true, 403)
	})
	step("update_allow", func(t *testing.T) {
		policy("allow", trafficFixture.Client.Name()).ApplyOrFail(t, kube.ReconcileOwned)
		fixture.wantHeaders(t, target, "/xds-lifecycle", true, 0)
	})
	step("destination_and_port", func(t *testing.T) {
		for _, denied := range []string{
			net.JoinHostPort(trafficFixture.Server.ServiceIPOrFail(t), "81"),
			net.JoinHostPort(trafficFixture.Client.ServiceIPOrFail(t), "80"),
		} {
			response, err := fixture.headers(t.Context(), denied, "/xds-lifecycle", true)
			if err != nil {
				t.Fatal(err)
			}
			if err := checkEPEHeaders(response, denied, 403); err != nil {
				t.Fatal(err)
			}
		}
	})
	step("dns_target_is_pinned", func(t *testing.T) {
		response, err := fixture.headers(
			t.Context(),
			net.JoinHostPort(trafficFixture.Server.Address(), "80"),
			"/xds-lifecycle",
			true,
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkEPEHeaders(response, target, 0); err != nil {
			t.Fatal(err)
		}
	})
	step("global_deny_wins_over_xds_allow", func(t *testing.T) {
		global := egressEPEConfig(scope, "epe-egressauthz", fmt.Sprintf(
			"egressAuthorization: {deniedCIDRs: [%s/32]}", trafficFixture.Server.ServiceIPOrFail(t)))
		global.ApplyOrFail(t, kube.CreateOnly)
		fixture.wantHeaders(t, target, "/xds-lifecycle", true, 403)
		global.DeleteOrFail(t)
		fixture.wantHeaders(t, target, "/xds-lifecycle", true, 0)
	})
	step("update_reject", func(t *testing.T) {
		policy("reject", trafficFixture.Client.Name()).ApplyOrFail(t, kube.ReconcileOwned)
		fixture.wantHeaders(t, target, "/xds-lifecycle", true, 403)
	})
	step("workload_binding_removed", func(t *testing.T) {
		policy("reject", "not-the-client").ApplyOrFail(t, kube.ReconcileOwned)
		fixture.wantHeaders(t, target, "/xds-lifecycle", true, 0)
	})
	step("workload_binding_restored", func(t *testing.T) {
		policy("reject", trafficFixture.Client.Name()).ApplyOrFail(t, kube.ReconcileOwned)
		fixture.wantHeaders(t, target, "/xds-lifecycle", true, 403)
	})
	step("delete", func(t *testing.T) {
		initial.DeleteOrFail(t)
		fixture.wantHeaders(t, target, "/xds-lifecycle", true, 0)
	})
}

// TestEPERequestPhases keeps a body obligation across header bypass. It also
// proves a header block wins and destination authorization need not wait for
// body input, including when the headers declare an empty body.
func TestEPERequestPhases(t *testing.T) {
	fixture, scope := newEgressEPE(t, true)
	target := net.JoinHostPort(trafficFixture.Server.ServiceIPOrFail(t), "80")
	e2econfig.New(scope).YAML(trafficFixture.Namespace.Name(), `
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: epe-request-phases
spec:
  selector: {}
  rules:
  - name: body-check
    match:
    - domains: ["*"]
      paths: [{type: Prefix, value: /epe-phases}]
    actions:
      mcpToolPolicy:
        defaultAction: deny
        denyResponse: {statusCode: 452, body: epe-body-denied}
        rules:
        - method: tools/call
          toolNames: [allowed-tool]
          action: allow
  - name: header-block
    match:
    - domains: ["*"]
      paths: [{type: Exact, value: /epe-phases/block}]
    actions:
      block: {statusCode: 451, body: epe-header-denied}
  - name: header-bypass
    match:
    - domains: ["*"]
      paths: [{type: Prefix, value: /epe-phases}]
    actions:
      bypass: true
  - name: skipped-block
    match:
    - domains: ["*"]
      paths: [{type: Prefix, value: /epe-phases}]
    actions:
      block: {statusCode: 453, body: epe-bypass-broken}
`).ApplyOrFail(t, kube.CreateOnly)
	// This barrier proves the profile is active before negative assertions.
	fixture.wantHeaders(t, target, "/epe-phases/block", false, 451)

	deny := e2econfig.New(scope).YAML(trafficFixture.Namespace.Name(), `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: epe-phases-deny
spec:
  priority: 100
  selector:
    matchLabels: {app: client}
  egress:
    rules:
    - action: reject
      to: [{cidr: "0.0.0.0/0"}, {cidr: "::/0"}]
`)
	deny.ApplyOrFail(t, kube.CreateOnly)
	fixture.wantHeaders(t, target, "/epe-phases", false, 403)
	// These assertions run after the deny has converged, without retrying.
	for _, tc := range []struct {
		name   string
		path   string
		end    bool
		status int
	}{
		{"deny_before_body", "/epe-phases", false, 403},
		{"deny_before_empty_body", "/epe-phases", true, 403},
		{"header_block_precedes_authorization", "/epe-phases/block", false, 451},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response, err := fixture.headers(t.Context(), target, tc.path, tc.end)
			if err != nil {
				t.Fatal(err)
			}
			if err := checkEPEHeaders(response, target, tc.status); err != nil {
				t.Fatal(err)
			}
		})
	}
	deny.DeleteOrFail(t)
	fixture.wantHeaders(t, target, "/epe-phases", false, 0)

	for _, tc := range []struct {
		name   string
		tool   string
		status int
	}{
		{"body_allow_after_bypass", "allowed-tool", 0},
		{"body_deny_after_bypass", "denied-tool", 452},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			stream, err := fixture.client.Process(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := stream.Send(fixture.request(target, "/epe-phases", false)); err != nil {
				t.Fatal(err)
			}
			headers, err := stream.Recv()
			if err != nil {
				t.Fatal(err)
			}
			if err := checkEPEHeaders(headers, target, 0); err != nil {
				t.Fatal(err)
			}
			if headers.GetModeOverride().GetRequestBodyMode().String() != "BUFFERED" {
				t.Fatalf("body obligation was lost after bypass: %v", headers)
			}
			body := []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":%q}}`, tc.tool))
			if err := stream.Send(&extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestBody{
				RequestBody: &extprocv3.HttpBody{Body: body, EndOfStream: true},
			}}); err != nil {
				t.Fatal(err)
			}
			response, err := stream.Recv()
			if err != nil {
				t.Fatal(err)
			}
			if tc.status != 0 {
				if err := checkEPEHeaders(response, target, tc.status); err != nil {
					t.Fatal(err)
				}
			} else if response.GetRequestBody() == nil || epePinnedAddress(response) != target {
				t.Fatalf("body completion lost authorized target: %v", response)
			}
		})
	}

	// Exercise the same rules through the production gateway and real backend.
	// No TrafficPolicy denies here: a ztunnel denial must not stand in for EPE.
	applyEPEProviderConfig(t, scope, "epe-egressauthz")
	callEPEPathOrFail(t, trafficFixture.Client, trafficFixture.Server,
		"/epe-phases/block", 451, "epe-header-denied")
	for _, tc := range []struct {
		tool   string
		status int
		body   string
	}{
		{"allowed-tool", 200, "Hostname=" + trafficFixture.Server.WorkloadsOrFail(t)[0].Name},
		{"denied-tool", 452, "epe-body-denied"},
	} {
		t.Run("gateway_"+tc.tool, func(t *testing.T) {
			body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":%q}}`, tc.tool)
			ctx, cancel := e2e.Context(t, 15*time.Second)
			defer cancel()
			stdout, stderr, err := trafficFixture.Client.Exec(ctx, []string{
				"curl", "-sS", "--max-time", "10", "-X", "POST",
				"-H", "content-type: application/json", "-H", "mcp-protocol-version: 2025-11-25",
				"--data-binary", body, "-w", "\n%{http_code}",
				"http://" + trafficFixture.Server.Address() + "/epe-phases",
			})
			if err != nil || !strings.HasSuffix(stdout, "\n"+strconv.Itoa(tc.status)) ||
				!strings.Contains(stdout, tc.body) {
				t.Fatalf("gateway response: stdout=%q stderr=%q error=%v", stdout, stderr, err)
			}
		})
	}
}

type egressEPE struct {
	client    extprocv3.ExternalProcessorClient
	pod       string
	namespace string
}

func newEgressEPE(t *testing.T, enableXDS bool) (*egressEPE, *kube.ResourceScope) {
	t.Helper()
	environment, scope := rig.BeginScenario(t)
	namespace := resolvedAgentioConfig.Namespace
	const name = "epe-egressauthz"
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		logs, err := environment.Kube.Logs(ctx, namespace, name, "epe", nil)
		t.Logf("egress EPE logs (%v):\n%s", err, logs)
	})
	if enableXDS {
		rig.ApplyConfig(t, scope, map[string]any{"Namespace": namespace}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    xdsClients:
    - principal: spiffe://cluster.local/ns/{{ .Namespace }}/sa/agentio-epe
      resources: [Workload, TrafficPolicy]
`)
	}
	e2econfig.New(scope).Eval(namespace, map[string]any{
		"Namespace": namespace,
		"Image":     resolvedAgentioConfig.EPEImage,
		"EnableXDS": enableXDS,
	}, egressEPEYAML).ApplyOrFail(t, kube.CreateOnly)
	ctx, cancel := e2e.Context(t, 2*time.Minute)
	defer cancel()
	if _, err := environment.Kube.WaitReadyPods(ctx, namespace, "app="+name, 1); err != nil {
		t.Fatal(err)
	}
	conn, err := grpc.NewClient(epeForwardPort(t, environment, namespace, name, 9002),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	})
	workload := trafficFixture.Client.WorkloadsOrFail(t)[0]
	return &egressEPE{
		client:    extprocv3.NewExternalProcessorClient(conn),
		pod:       workload.Name,
		namespace: trafficFixture.Namespace.Name(),
	}, scope
}

func (f *egressEPE) request(target, path string, end bool) *extprocv3.ProcessingRequest {
	attrs := &structpb.Struct{Fields: map[string]*structpb.Value{
		"filter_state['agentio.workload.name']":      structpb.NewStringValue(f.pod),
		"filter_state['agentio.workload.namespace']": structpb.NewStringValue(f.namespace),
	}}
	return &extprocv3.ProcessingRequest{
		Attributes: map[string]*structpb.Struct{"envoy.filters.http.ext_proc": attrs},
		Request: &extprocv3.ProcessingRequest_RequestHeaders{RequestHeaders: &extprocv3.HttpHeaders{
			EndOfStream: end,
			Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
				{Key: ":method", RawValue: []byte("POST")},
				{Key: ":scheme", RawValue: []byte("http")},
				{Key: ":authority", RawValue: []byte(target)},
				{Key: ":path", RawValue: []byte(path)},
				{Key: "content-type", RawValue: []byte("application/json")},
				{Key: "mcp-protocol-version", RawValue: []byte("2025-11-25")},
			}},
		}},
	}
}

func (f *egressEPE) headers(ctx context.Context, target, path string, end bool) (*extprocv3.ProcessingResponse, error) {
	return f.sendHeaders(ctx, f.request(target, path, end))
}

func (f *egressEPE) sendHeaders(
	ctx context.Context,
	request *extprocv3.ProcessingRequest,
) (*extprocv3.ProcessingResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	stream, err := f.client.Process(ctx)
	if err != nil {
		return nil, err
	}
	if err := stream.Send(request); err != nil {
		return nil, err
	}
	// Do not send a body or close the send side: a response proves the header
	// decision does not depend on receiving body data or EOF.
	return stream.Recv()
}

func (f *egressEPE) wantHeaders(t *testing.T, target, path string, end bool, status int) {
	t.Helper()
	harness.RetryAssertion(t, 2*time.Minute, time.Second, func() error {
		response, err := f.headers(t.Context(), target, path, end)
		if err != nil {
			return err
		}
		return checkEPEHeaders(response, target, status)
	})
}

func checkEPEHeaders(response *extprocv3.ProcessingResponse, target string, status int) error {
	if status != 0 {
		if int(response.GetImmediateResponse().GetStatus().GetCode()) != status ||
			response.GetDynamicMetadata() != nil {
			return fmt.Errorf("want local rejection %d without target metadata, got %v", status, response)
		}
		return nil
	}
	if response.GetRequestHeaders() == nil || epePinnedAddress(response) != target {
		return fmt.Errorf("want allowed headers pinned to %s, got %v", target, response)
	}
	return nil
}

func epePinnedAddress(response *extprocv3.ProcessingResponse) string {
	return response.GetDynamicMetadata().GetFields()["agentio.route"].GetStructValue().
		GetFields()["upstream"].GetStructValue().GetFields()["address"].GetStringValue()
}

// The fixture uses the EPE identity for ADS and Kubernetes watches.
const egressEPEYAML = `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: epe-egressauthz-{{ .Namespace }}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: agentio-epe-{{ .Namespace }}
subjects:
- kind: ServiceAccount
  name: agentio-epe
  namespace: {{ .Namespace }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: epe-egressauthz
  namespace: {{ .Namespace }}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: agentio-epe
subjects:
- kind: ServiceAccount
  name: agentio-epe
  namespace: {{ .Namespace }}
---
apiVersion: v1
kind: Service
metadata:
  name: epe-egressauthz
spec:
  selector: {app: epe-egressauthz}
  ports: [{name: grpc, port: 9002, targetPort: 9002}]
---
apiVersion: v1
kind: Pod
metadata:
  name: epe-egressauthz
  labels:
    app: epe-egressauthz
    agentio.kruise.io/dataplane-mode: none
spec:
  serviceAccountName: agentio-epe
  containers:
  - name: epe
    image: {{ .Image }}
    args:
    - --epe-config=epe-egressauthz
    - --epe-config-primary=epe-egressauthz-primary
    - --namespace={{ .Namespace }}
    {{- if .EnableXDS }}
    - --enable-xds-egressauthz
    - --xds-address=agentiod.{{ .Namespace }}.svc:15012
    - --xds-root-path=/var/run/xds-root/root-cert.pem
    - --xds-token-path=/var/run/xds-token/token
    {{- end }}
    env:
    - name: POD_NAME
      valueFrom: {fieldRef: {fieldPath: metadata.name}}
    - name: POD_NAMESPACE
      valueFrom: {fieldRef: {fieldPath: metadata.namespace}}
    - name: POD_UID
      valueFrom: {fieldRef: {fieldPath: metadata.uid}}
    - name: POD_IP
      valueFrom: {fieldRef: {fieldPath: status.podIP}}
    readinessProbe:
      grpc: {port: 9003, service: readiness}
      periodSeconds: 1
    volumeMounts:
    - {name: roots, mountPath: /var/run/xds-root, readOnly: true}
    - {name: token, mountPath: /var/run/xds-token, readOnly: true}
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
