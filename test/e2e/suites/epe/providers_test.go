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
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/openkruise/agentio/test/e2e"
	agentiocomponent "github.com/openkruise/agentio/test/e2e/components/agentio"
	"github.com/openkruise/agentio/test/e2e/components/echo"
	e2econfig "github.com/openkruise/agentio/test/e2e/config"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

// This uses the released SecurityProfile credential action. Its provider name
// identifies the remote credential; EPEConfig selects the local connection.
// Traffic traverses the injected ztunnel, production Envoy gateway, EPE process,
// credential fixture and echo origin. No Registry or filter is called in-process.
func TestEPECredentialProviderConfigUpdates(t *testing.T) {
	rig.RequireLive(t)
	if resolvedAgentioConfig.Profile != agentiocomponent.ProfileSidecar {
		t.Skip("sandbox token fixture requires a dedicated sidecar; scheduled only in sidecar-auto")
	}
	environment, scope := rig.BeginScenario(t)
	const name = "epe-provider-watch"
	const caller = "epe-provider-caller"
	namespace := resolvedAgentioConfig.Namespace
	callerNamespace := trafficFixture.Namespace.Name()
	ctx, cancel := e2e.Context(t, 8*time.Minute)
	defer cancel()

	// The isolated EPE uses the chart's service account and the candidate EPE
	// image, with a ConfigMap enabled at startup. Other suite tests keep their
	// ordinary EPE deployment and configuration.
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		logCtx, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		pods, err := environment.Cluster.Kube.CoreV1().
			Pods(namespace).
			List(logCtx, metav1.ListOptions{LabelSelector: "app=" + name})
		if err != nil {
			t.Log(err)
			return
		}
		for _, pod := range pods.Items {
			logs, err := environment.Kube.Logs(logCtx, namespace, pod.Name, "epe", nil)
			t.Logf("EPE %s logs (error=%v):\n%s", pod.Name, err, logs)
		}
	})
	endpoint := "http://credential-provider." + namespace + ".svc.cluster.local:8080/credentials/"
	config := func(defaultProvider, aEndpoint string) string {
		raw := fmt.Sprintf(`extensionProviders:
- name: a
  credentialProvider: {url: %q, timeout: 2s}
- name: b
  credentialProvider: {url: %q, timeout: 2s}
`, endpoint+aEndpoint, endpoint+"b")
		if defaultProvider != "" {
			raw += "defaultProviders: {credentialProvider: " + defaultProvider + "}\n"
		}
		return raw
	}
	applyConfig := func(t *testing.T, raw string, mode kube.Mode) kube.ResourceRecord {
		t.Helper()
		record, err := scope.ApplyInNamespace(ctx, namespace, &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata":   map[string]any{"name": name},
			"data":       map[string]any{"config": raw},
		}}, mode)
		if err != nil {
			t.Fatal(err)
		}
		return record
	}
	var cm kube.ResourceRecord
	e2econfig.New(scope).Eval(namespace, map[string]any{
		"Name":           name,
		"Namespace":      namespace,
		"EPEImage":       resolvedAgentioConfig.EPEImage,
		"ProviderImage":  resolvedAgentioConfig.ExtProcImage,
		"EnvironmentURL": endpoint + "environment",
	}, providerFixturesYAML).ApplyOrFail(t, kube.CreateOnly)
	sandbox, err := scope.ApplyInNamespace(ctx, callerNamespace, &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "agents.kruise.io/v1alpha1",
		"kind":       "Sandbox",
		"metadata":   map[string]any{"name": caller},
		"spec":       map[string]any{},
	}}, kube.CreateOnly)
	if err != nil {
		t.Fatal(err)
	}
	e2econfig.New(scope).Eval(callerNamespace, map[string]any{
		"Caller":     caller,
		"SandboxUID": string(sandbox.UID),
		"SandboxID":  "kruise:" + callerNamespace + "--" + caller,
		"EchoImage":  echo.DefaultImage,
		"ProxyImage": resolvedAgentioConfig.ZtunnelImage,
	}, providerCallerYAML).ApplyOrFail(t, kube.CreateOnly)
	for _, fixture := range []struct {
		namespace string
		selector  string
	}{
		{namespace, "app=credential-provider"}, {namespace, "app=" + name}, {callerNamespace, "app=" + caller},
	} {
		if _, err := environment.Kube.WaitReadyPods(ctx, fixture.namespace, fixture.selector, 1); err != nil {
			t.Fatal(err)
		}
	}
	callerPod, err := environment.Cluster.Kube.CoreV1().Pods(callerNamespace).Get(ctx, caller, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	sandboxes := environment.Cluster.Dynamic.Resource(sandbox.GVR).Namespace(callerNamespace)
	sandboxObject, err := sandboxes.Get(ctx, caller, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := unstructured.SetNestedField(
		sandboxObject.Object,
		string(callerPod.UID),
		"status",
		"podInfo",
		"podUID",
	); err != nil {
		t.Fatal(err)
	}
	if _, err := sandboxes.UpdateStatus(ctx, sandboxObject, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	pods, err := environment.Kube.ReadyPods(ctx, namespace, "app="+name)
	if err != nil || len(pods) != 1 {
		t.Fatalf("expected one ready EPE: %v, %d pods", err, len(pods))
	}
	initialPod := pods[0]
	if restartCount(initialPod) != 0 {
		t.Fatal("EPE restarted during initial configuration")
	}
	applyEPEProviderConfig(t, scope, name)
	e2econfig.New(scope).YAML(callerNamespace, `
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: epe-provider-inject
spec:
  selector:
    matchLabels: {app: epe-provider-caller}
  rules:
  - name: inject
    match:
    - domains: ["*"]
      paths:
      - {type: Exact, value: /epe-provider}
    actions:
      tokenTransformation:
        failStrategy: Block
        credentialRef:
          credentialProvider: {name: remote-e2e}
        apiKey:
          targetHeaders:
            names: [x-provider-token]
          value:
            template: 'Bearer {{ .Token }}'
`).ApplyOrFail(t, kube.CreateOnly)

	// The origin echoes received headers. Only its actual RequestHeader line
	// satisfies this check; the supplied request value is deliberately different.
	request := func(t *testing.T, status int, token string) {
		t.Helper()
		harness.RetryAssertion(t, time.Minute, time.Second, func() error {
			out, stderr, err := environment.Kube.Exec(ctx, callerNamespace, caller, "app", []string{
				"curl", "--silent", "--show-error", "--max-time", "10", "--noproxy", "*",
				"--header", "x-provider-token: must-be-replaced",
				"--write-out", "\nEPE_STATUS=%{http_code}\n",
				"http://" + trafficFixture.Server.Address() + "/epe-provider",
			}, nil)
			if err != nil {
				return fmt.Errorf("request: %w: %s", err, stderr)
			}
			if !strings.HasSuffix(out, fmt.Sprintf("\nEPE_STATUS=%d\n", status)) {
				return fmt.Errorf("want status %d, response: %s", status, out)
			}
			if status == 200 {
				for line := range strings.SplitSeq(out, "\n") {
					if strings.EqualFold(strings.TrimSpace(line), "RequestHeader=X-Provider-Token:Bearer "+token) {
						return nil
					}
				}
				return fmt.Errorf("origin did not receive token %q: %s", token, out)
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
	step("environment_default", func(t *testing.T) { request(t, 200, "environment-1") })
	step("empty_default_disables_selection", func(t *testing.T) {
		cm = applyConfig(t, `defaultProviders: {credentialProvider: ""}`, kube.CreateOnly)
		request(t, 403, "")
	})
	step("callout_only_preserves_environment", func(t *testing.T) {
		// Recover from the disabled default so success requires observing this
		// update. Adding only a callout must retain the environment's cache.
		cm = applyConfig(t, fmt.Sprintf(`extensionProviders:
- name: scanner
  httpCallout: {url: %q}
`, endpoint+"callout"), kube.ReconcileOwned)
		request(t, 200, "environment-1")
	})
	step("select_a", func(t *testing.T) {
		cm = applyConfig(t, config("a", "a"), kube.ReconcileOwned)
		request(t, 200, "a-1")
	})
	step("select_b", func(t *testing.T) {
		cm = applyConfig(t, config("b", "a"), kube.ReconcileOwned)
		request(t, 200, "b-1")
	})
	step("switch_back_reuses_cache", func(t *testing.T) {
		cm = applyConfig(t, config("a", "a"), kube.ReconcileOwned)
		request(t, 200, "a-1")
	})
	step("endpoint_update_invalidates_cache", func(t *testing.T) {
		cm = applyConfig(t, config("a", "c"), kube.ReconcileOwned)
		request(t, 200, "c-1")
	})
	step("invalid_update_retains_last_good", func(t *testing.T) {
		const invalidTimeout = "invalid-provider-e2e-timeout"
		invalid := strings.ReplaceAll(config("b", "c"), "timeout: 2s", "timeout: "+invalidTimeout)
		cm = applyConfig(t, invalid, kube.ReconcileOwned)
		// Wait for rejection, so unchanged traffic cannot pass just because the
		// ConfigMap event has not yet reached EPE.
		harness.RetryAssertion(t, 30*time.Second, time.Second, func() error {
			logs, err := environment.Kube.Logs(ctx, namespace, initialPod.Name, "epe", nil)
			if err != nil {
				return err
			}
			if !strings.Contains(logs, "retain last-known-good configuration") ||
				!strings.Contains(logs, invalidTimeout) {
				return fmt.Errorf("EPE has not rejected the invalid update")
			}
			return nil
		})
		request(t, 200, "c-1")
	})
	step("missing_default_fails_closed", func(t *testing.T) {
		cm = applyConfig(t, config("missing", "c"), kube.ReconcileOwned)
		request(t, 403, "")
	})
	step("valid_update_recovers", func(t *testing.T) {
		cm = applyConfig(t, config("b", "c"), kube.ReconcileOwned)
		request(t, 200, "b-1")
	})
	step("provider_deletion_fails_closed", func(t *testing.T) {
		cm = applyConfig(t, "extensionProviders: []\ndefaultProviders: {credentialProvider: b}\n", kube.ReconcileOwned)
		request(t, 403, "")
	})
	step("configmap_deletion_restores_environment", func(t *testing.T) {
		if err := scope.Delete(ctx, cm); err != nil {
			t.Fatal(err)
		}
		request(t, 200, "environment-2")
	})
	step("configmap_recreation_recovers", func(t *testing.T) {
		applyConfig(t, config("a", "c"), kube.CreateOnly)
		request(t, 200, "c-2")
	})
	finalPods, err := environment.Kube.ReadyPods(ctx, namespace, "app="+name)
	if err != nil || len(finalPods) != 1 || finalPods[0].UID != initialPod.UID || restartCount(finalPods[0]) != 0 {
		t.Fatalf("configuration changes must not replace or restart EPE: pods=%v, error=%v", finalPods, err)
	}
	t.Logf("all updates used EPE pod %s, UID %s, zero container restarts", initialPod.Name, initialPod.UID)
}

func restartCount(pod corev1.Pod) int32 {
	var count int32
	for _, status := range pod.Status.ContainerStatuses {
		count += status.RestartCount
	}
	return count
}

const providerFixturesYAML = `
apiVersion: v1
kind: Service
metadata:
  name: credential-provider
spec:
  selector: {app: credential-provider}
  ports: [{name: http, port: 8080, targetPort: 8080}]
---
apiVersion: v1
kind: Pod
metadata:
  name: credential-provider
  labels: {app: credential-provider, agentio.kruise.io/dataplane-mode: none}
spec:
  containers:
  - name: provider
    image: {{ .ProviderImage }}
    args: ["-credential-provider-port=8080"]
    readinessProbe:
      tcpSocket: {port: 8080}
      periodSeconds: 1
    resources:
      requests: {cpu: 10m, memory: 32Mi}
      limits: {cpu: 500m, memory: 128Mi}
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
    - {name: IDENTITY_PROVIDER_URL, value: {{ .EnvironmentURL | printf "%q" }}}
    - {name: CREDENTIAL_PROVIDER_MTLS_SOURCE, value: none}
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

const providerCallerYAML = `
apiVersion: v1
kind: Secret
metadata:
  name: epe-provider-token
stringData:
  sandbox.token: '{"requestId":"epe-e2e","accessToken":"epe-e2e-access","sandboxClientId":"epe-e2e-client"}'
  sandbox.json: '{"sandboxId":{{ .SandboxID | printf "%q" }}}'
---
apiVersion: v1
kind: Pod
metadata:
  name: {{ .Caller }}
  labels: {app: {{ .Caller }}}
  ownerReferences:
  - apiVersion: agents.kruise.io/v1alpha1
    kind: Sandbox
    name: {{ .Caller }}
    uid: {{ .SandboxUID | printf "%q" }}
    controller: true
spec:
  containers:
  - name: app
    image: {{ .EchoImage }}
    args: ["--port=18080"]
    readinessProbe:
      tcpSocket: {port: 18080}
      periodSeconds: 1
  # Admission fills in the production proxy settings, retaining this mount.
  - name: agentio-proxy
    image: {{ .ProxyImage }}
    env:
    - {name: SANDBOX_TOKEN_ENABLED, value: "true"}
    volumeMounts:
    - {name: provider-token, mountPath: /var/opt/sandbox/agent-token, readOnly: true}
    # Restore a registered Sandbox, as after a proxy restart; xDS still checks its host binding.
    - {name: provider-registration, mountPath: /var/lib/ztunnel/sandbox/sandbox.json, subPath: sandbox.json, readOnly: true}
  volumes:
  - name: provider-token
    secret:
      secretName: epe-provider-token
      items: [{key: sandbox.token, path: sandbox.token}]
  - name: provider-registration
    secret:
      secretName: epe-provider-token
      items: [{key: sandbox.json, path: sandbox.json}]
`
