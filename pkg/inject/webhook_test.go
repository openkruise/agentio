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

// The testdata ztunnel template uses this package's injection settings;
// values.json supplies concrete test substitutions.

package inject

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	jsonpatch "gopkg.in/evanphx/json-patch.v4"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func newTestWebhook(t *testing.T, mode NativeSidecarMode) *Webhook {
	t.Helper()
	template, err := os.ReadFile("testdata/ztunnel-injection-template.yaml")
	if err != nil {
		t.Fatal(err)
	}
	values, err := os.ReadFile("testdata/values.json")
	if err != nil {
		t.Fatal(err)
	}
	configYAML := map[string]any{
		"policy":           "enabled",
		"defaultTemplates": []string{"ztunnel"},
		"templates": map[string]string{
			"ztunnel": string(template),
		},
	}
	rawConfig, err := json.Marshal(configYAML)
	if err != nil {
		t.Fatal(err)
	}
	config, err := UnmarshalConfig(rawConfig)
	if err != nil {
		t.Fatalf("parse vendored injection config: %v", err)
	}
	return newTestWebhookWithValues(t, mode, config, string(values))
}

func newTestWebhookWithValues(t *testing.T, mode NativeSidecarMode, config Config, values string) *Webhook {
	t.Helper()
	webhook, err := NewWebhook(WebhookParameters{Mux: http.NewServeMux(), NativeSidecarMode: mode, EnableClientTrust: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := webhook.UpdateConfig(&config, values); err != nil {
		t.Fatalf("update injection config: %v", err)
	}
	return webhook
}

func testPod() *corev1.Pod {
	controller := true
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "hello-6d8f7c9b5d-",
			Namespace:    "demo",
			Labels:       map[string]string{"app": "hello", "pod-template-hash": "6d8f7c9b5d"},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1",
				Kind:       "ReplicaSet",
				Name:       "hello-6d8f7c9b5d",
				Controller: &controller,
			}},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "hello",
				Image: "docker.io/library/nginx:1.27",
				Ports: []corev1.ContainerPort{{ContainerPort: 8080}},
				ReadinessProbe: &corev1.Probe{
					ProbeHandler: corev1.ProbeHandler{
						HTTPGet: &corev1.HTTPGetAction{Path: "/healthz", Port: intstr.FromInt32(8080)},
					},
				},
			}},
		},
	}
}

func injectTestPod(t *testing.T, webhook *Webhook, pod *corev1.Pod) *corev1.Pod {
	t.Helper()
	response, raw := admitTestPod(t, webhook, pod)
	if !response.Allowed {
		t.Fatalf("injection denied: %v", response.Result)
	}
	if response.Patch == nil {
		return pod
	}
	patch, err := jsonpatch.DecodePatch(response.Patch)
	if err != nil {
		t.Fatalf("decode patch: %v", err)
	}
	patched, err := patch.Apply(raw)
	if err != nil {
		t.Fatalf("apply patch: %v", err)
	}
	result := &corev1.Pod{}
	if err := json.Unmarshal(patched, result); err != nil {
		t.Fatal(err)
	}
	return result
}

func admitTestPod(t *testing.T, webhook *Webhook, pod *corev1.Pod) (*admissionv1.AdmissionResponse, []byte) {
	t.Helper()
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	review := &admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Request: &admissionv1.AdmissionRequest{
			UID:       types.UID("test-uid"),
			Namespace: pod.Namespace,
			Object:    runtime.RawExtension{Raw: raw},
		},
	}
	response := webhook.inject(review, "/inject")
	if response == nil {
		t.Fatal("nil admission response")
	}
	return response, raw
}

func containerNames(containers []corev1.Container) []string {
	names := make([]string, 0, len(containers))
	for _, c := range containers {
		names = append(names, c.Name)
	}
	return names
}

func TestInjectZtunnelTemplate(t *testing.T) {
	webhook := newTestWebhook(t, NativeSidecarModeDisabled)
	patched := injectTestPod(t, webhook, testPod())

	if got, want := containerNames(patched.Spec.Containers), []string{"hello", "agentio-proxy"}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("containers = %v, want %v", got, want)
	}
	if got, want := containerNames(patched.Spec.InitContainers), []string{InitContainerName}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("initContainers = %v, want %v", got, want)
	}

	initContainer := FindContainer(InitContainerName, patched.Spec.InitContainers)
	if got, want := initContainer.Image, "docker.io/agentio/proxyv2:test"; got != want {
		t.Fatalf("agentio-init image = %q, want %q", got, want)
	}
	args := strings.Join(initContainer.Args, " ")
	for _, want := range []string{"istio-iptables", "-p 15001", "-z 15006", "-u 1337", "-m REDIRECT", "-i *", "-b *"} {
		if !strings.Contains(args, want) {
			t.Fatalf("agentio-init args %q missing %q", args, want)
		}
	}
	if caps := initContainer.SecurityContext.Capabilities; caps == nil || len(caps.Add) != 1 || caps.Add[0] != "NET_ADMIN" {
		t.Fatalf("agentio-init capabilities = %+v, want NET_ADMIN", initContainer.SecurityContext.Capabilities)
	}

	sidecar := FindSidecar(patched)
	if sidecar == nil || sidecar.Name != "agentio-proxy" {
		t.Fatalf("proxy container = %+v, want agentio-proxy", sidecar)
	}
	if got, want := sidecar.Image, "docker.io/agentio/ztunnel:test"; got != want {
		t.Fatalf("ztunnel image = %q, want %q", got, want)
	}
	if got, want := strings.Join(sidecar.Args, " "), "proxy ztunnel"; got != want {
		t.Fatalf("ztunnel args = %q, want %q", got, want)
	}
	env := map[string]string{}
	for _, e := range sidecar.Env {
		env[e.Name] = e.Value
	}
	if got, want := env["CA_ADDRESS"], "agentiod.agentio-system.svc.cluster.local:15012"; got != want {
		t.Fatalf("CA_ADDRESS = %q, want %q", got, want)
	}
	if got, want := env["ENABLE_SIDECAR_MODE"], "true"; got != want {
		t.Fatalf("ENABLE_SIDECAR_MODE = %q, want %q", got, want)
	}
	if _, ok := env[KubeAppProberEnvName]; !ok {
		t.Fatalf("ztunnel env missing %s after probe rewrite", KubeAppProberEnvName)
	}

	volumes := map[string]corev1.Volume{}
	for _, v := range patched.Spec.Volumes {
		volumes[v.Name] = v
	}
	trustVolume, ok := volumes["agentiod-ca-cert"]
	if !ok || trustVolume.ConfigMap == nil || trustVolume.ConfigMap.Name != "agentio-ca-root-cert" {
		t.Fatalf("agentiod-ca-cert volume = %+v, want ConfigMap agentio-ca-root-cert", trustVolume)
	}
	tokenVolume, ok := volumes["agentio-token"]
	if !ok || tokenVolume.Projected == nil ||
		tokenVolume.Projected.Sources[0].ServiceAccountToken.Audience != "agentio-ca" {
		t.Fatalf("agentio-token volume = %+v, want projected token with audience agentio-ca", tokenVolume)
	}

	status := patched.Annotations["sidecar.istio.io/status"]
	if !strings.Contains(status, InitContainerName) || !strings.Contains(status, "agentio-proxy") {
		t.Fatalf("status annotation %q missing injected container names", status)
	}
	if got, want := patched.Annotations["prometheus.io/port"], "15020"; got != want {
		t.Fatalf("prometheus.io/port = %q, want %q", got, want)
	}
	if value, found := patched.Annotations["istio.io/rev"]; found {
		t.Fatalf("injected Pod has legacy revision annotation %q", value)
	}
	statusFields := map[string]any{}
	if err := json.Unmarshal([]byte(status), &statusFields); err != nil {
		t.Fatalf("parse status annotation: %v", err)
	}
	if value, found := statusFields["revision"]; found {
		t.Fatalf("status annotation has legacy revision field %v", value)
	}
	for _, legacyLabel := range []string{
		"security.istio.io/tlsMode",
		"networking.istio.io/tunnel",
		"service.istio.io/canonical-name",
		"service.istio.io/canonical-revision",
	} {
		if value, found := patched.Labels[legacyLabel]; found {
			t.Fatalf("injected Pod has legacy label %s=%q", legacyLabel, value)
		}
	}

	hello := FindContainer("hello", patched.Spec.Containers)
	if got := hello.ReadinessProbe.HTTPGet; got.Port.IntValue() != 15020 || got.Path != "/app-health/hello/readyz" {
		t.Fatalf("rewritten readiness probe = %+v, want port 15020 path /app-health/hello/readyz", got)
	}
}

func TestInjectPreservesControllerMetadata(t *testing.T) {
	webhook := newTestWebhook(t, NativeSidecarModeDisabled)
	patched := injectTestPod(t, webhook, testPod())

	wantLabels := map[string]string{
		"app":               "hello",
		"pod-template-hash": "6d8f7c9b5d",
	}
	if !reflect.DeepEqual(patched.Labels, wantLabels) {
		t.Fatalf("labels = %v, want %v", patched.Labels, wantLabels)
	}
	if len(patched.OwnerReferences) != 1 {
		t.Fatalf("ownerReferences = %v, want one ReplicaSet owner", patched.OwnerReferences)
	}
	owner := patched.OwnerReferences[0]
	if owner.APIVersion != "apps/v1" || owner.Kind != "ReplicaSet" || owner.Name != "hello-6d8f7c9b5d" ||
		owner.Controller == nil || !*owner.Controller {
		t.Fatalf("ownerReference = %+v, want controlling ReplicaSet hello-6d8f7c9b5d", owner)
	}
}

func TestInjectSelectsRequestedTemplates(t *testing.T) {
	config, err := UnmarshalConfig([]byte(`policy: enabled
defaultTemplates: [default]
aliases:
  bundle: [proxy, init]
templates:
  default: |
    spec:
      containers:
      - name: default-template
        image: default
  proxy: |
    spec:
      containers:
      - name: agentio-proxy
        image: proxy
  init: |
    spec:
      initContainers:
      - name: selected-init
        image: init
`))
	if err != nil {
		t.Fatal(err)
	}
	webhook := newTestWebhookWithValues(t, NativeSidecarModeDisabled, config, `{}`)

	for _, tt := range []struct {
		name       string
		annotation string
	}{
		{name: "comma-separated", annotation: "proxy, init"},
		{name: "alias", annotation: "bundle"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pod := testPod()
			pod.Annotations = map[string]string{"inject.agentio.kruise.io/templates": tt.annotation}
			patched := injectTestPod(t, webhook, pod)

			if FindContainer("agentio-proxy", patched.Spec.Containers) == nil {
				t.Fatalf("containers = %v, want selected proxy template", containerNames(patched.Spec.Containers))
			}
			if FindContainer("selected-init", patched.Spec.InitContainers) == nil {
				t.Fatalf("initContainers = %v, want selected init template", containerNames(patched.Spec.InitContainers))
			}
			if FindContainer("default-template", patched.Spec.Containers) != nil {
				t.Fatalf("containers = %v, default template must not run when templates are specified", containerNames(patched.Spec.Containers))
			}
		})
	}
}

func TestInjectRejectsUnknownRequestedTemplate(t *testing.T) {
	webhook := newTestWebhook(t, NativeSidecarModeDisabled)
	pod := testPod()
	pod.Annotations = map[string]string{"inject.agentio.kruise.io/templates": "missing"}

	response, _ := admitTestPod(t, webhook, pod)
	if response.Allowed {
		t.Fatal("unknown requested template was allowed")
	}
	if response.Result == nil || !strings.Contains(response.Result.Message, `requested template "missing" not found`) {
		t.Fatalf("response = %+v, want missing-template error", response.Result)
	}
}

func TestFindSidecarAcceptsCurrentAndLegacyNames(t *testing.T) {
	for _, name := range []string{"agentio-proxy", "istio-proxy"} {
		t.Run(name, func(t *testing.T) {
			pod := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: name}}}}
			if got := FindSidecar(pod); got == nil || got.Name != name {
				t.Fatalf("FindSidecar() = %+v, want %q", got, name)
			}
		})
	}
}

func TestInjectPreservesLegacyProxyContainerOverride(t *testing.T) {
	webhook := newTestWebhook(t, NativeSidecarModeDisabled)
	pod := testPod()
	pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{Name: "istio-proxy"})
	patched := injectTestPod(t, webhook, pod)

	if legacy := FindContainer("istio-proxy", patched.Spec.Containers); legacy == nil {
		t.Fatalf("legacy proxy override was not preserved: %+v", patched.Spec.Containers)
	}
	if current := FindContainer("agentio-proxy", patched.Spec.Containers); current != nil {
		t.Fatalf("legacy proxy override produced a second proxy: %+v", patched.Spec.Containers)
	}
}

func TestInjectNativeSidecar(t *testing.T) {
	webhook := newTestWebhook(t, NativeSidecarModeEnabled)
	patched := injectTestPod(t, webhook, testPod())

	if got, want := containerNames(patched.Spec.Containers), []string{"hello"}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("containers = %v, want %v", got, want)
	}
	if got, want := containerNames(patched.Spec.InitContainers), []string{InitContainerName, "agentio-proxy"}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("initContainers = %v, want %v", got, want)
	}
	sidecar := FindContainer("agentio-proxy", patched.Spec.InitContainers)
	if sidecar.RestartPolicy == nil || *sidecar.RestartPolicy != corev1.ContainerRestartPolicyAlways {
		t.Fatalf("native sidecar restartPolicy = %v, want Always", sidecar.RestartPolicy)
	}
}

func TestInjectUsesStatusPortFromInjectorValues(t *testing.T) {
	template, err := os.ReadFile("testdata/ztunnel-injection-template.yaml")
	if err != nil {
		t.Fatal(err)
	}
	config, err := UnmarshalConfig([]byte(fmt.Sprintf(`policy: enabled
defaultTemplates: [ztunnel]
templates:
  ztunnel: |
%s`, indentLines(string(template), "    "))))
	if err != nil {
		t.Fatal(err)
	}
	values, err := os.ReadFile("testdata/values.json")
	if err != nil {
		t.Fatal(err)
	}
	customValues := strings.Replace(string(values), `"statusPort": 15020`, `"statusPort": 16020`, 1)
	webhook := newTestWebhookWithValues(t, NativeSidecarModeDisabled, config, customValues)
	patched := injectTestPod(t, webhook, testPod())

	if got := patched.Annotations["prometheus.io/port"]; got != "16020" {
		t.Fatalf("prometheus.io/port = %q, want 16020", got)
	}
	hello := FindContainer("hello", patched.Spec.Containers)
	if got := hello.ReadinessProbe.HTTPGet.Port.IntValue(); got != 16020 {
		t.Fatalf("rewritten readiness probe port = %d, want 16020", got)
	}
}

func TestInjectUsesConfiguredTokenAudience(t *testing.T) {
	for _, path := range []string{"testdata/ztunnel-injection-template.yaml", "../../manifests/charts/agentio/files/ztunnel-injection-template.yaml"} {
		for _, audience := range []string{"istio-ca", "custom-audience", ""} {
			t.Run(path+"/"+audience, func(t *testing.T) {
				template, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				config, err := UnmarshalConfig([]byte("policy: enabled\ndefaultTemplates: [ztunnel]\ntemplates:\n  ztunnel: |\n" + indentLines(string(template), "    ")))
				if err != nil {
					t.Fatal(err)
				}
				values, err := os.ReadFile("testdata/values.json")
				if err != nil {
					t.Fatal(err)
				}
				custom := strings.Replace(string(values), `"aud": "agentio-ca"`, `"aud": "`+audience+`"`, 1)
				webhook := newTestWebhookWithValues(t, NativeSidecarModeDisabled, config, custom)
				pod := injectTestPod(t, webhook, testPod())
				want := audience
				if want == "" {
					want = "agentio-ca"
				}
				for _, volume := range pod.Spec.Volumes {
					if volume.Name == "agentio-token" && volume.Projected != nil {
						if got := volume.Projected.Sources[0].ServiceAccountToken.Audience; got != want {
							t.Fatalf("projected token audience = %q, want %q", got, want)
						}
						return
					}
				}
				t.Fatal("projected agentio-token volume missing")
			})
		}
	}
}

func TestInjectSkipsExplicitOptOut(t *testing.T) {
	webhook := newTestWebhook(t, NativeSidecarModeDisabled)
	pod := testPod()
	pod.Labels["agentio.kruise.io/dataplane-mode"] = "none"
	raw, _ := json.Marshal(pod)
	review := &admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{UID: "u", Namespace: pod.Namespace, Object: runtime.RawExtension{Raw: raw}},
	}
	response := webhook.inject(review, "/inject")
	if !response.Allowed || response.Patch != nil {
		t.Fatalf("opt-out pod response = %+v, want allowed without patch", response)
	}
}

func TestInjectRequiredForSidecarDataplaneMode(t *testing.T) {
	metadata := metav1.ObjectMeta{
		Namespace: "demo",
		Labels: map[string]string{
			"agentio.kruise.io/dataplane-mode": "sidecar",
		},
	}
	if !injectRequired(nil, &Config{Policy: InjectionPolicyDisabled}, &corev1.PodSpec{}, metadata) {
		t.Fatal("sidecar dataplane mode did not enable injection")
	}
}

func TestInjectRejectsBeforeConfigLoaded(t *testing.T) {
	webhook, err := NewWebhook(WebhookParameters{Mux: http.NewServeMux(), NativeSidecarMode: NativeSidecarModeDisabled})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(testPod())
	review := &admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{UID: "u", Namespace: "demo", Object: runtime.RawExtension{Raw: raw}},
	}
	response := webhook.inject(review, "/inject")
	if response.Allowed {
		t.Fatal("expected rejection while injection config is not loaded")
	}
}

func TestReinjectionIsIdempotent(t *testing.T) {
	webhook := newTestWebhook(t, NativeSidecarModeDisabled)
	once := injectTestPod(t, webhook, testPod())
	twice := injectTestPod(t, webhook, once.DeepCopy())

	if got, want := fmt.Sprint(containerNames(twice.Spec.Containers)), fmt.Sprint(containerNames(once.Spec.Containers)); got != want {
		t.Fatalf("re-injected containers = %v, want %v", got, want)
	}
	if got, want := fmt.Sprint(containerNames(twice.Spec.InitContainers)), fmt.Sprint(containerNames(once.Spec.InitContainers)); got != want {
		t.Fatalf("re-injected initContainers = %v, want %v", got, want)
	}
	count := 0
	for _, c := range twice.Spec.Containers {
		if c.Name == ProxyContainerName {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("proxy count after re-injection = %d, want 1", count)
	}
}

func TestServeInjectHTTPContract(t *testing.T) {
	webhook := newTestWebhook(t, NativeSidecarModeDisabled)

	pod := testPod()
	raw, _ := json.Marshal(pod)
	review := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Request: &admissionv1.AdmissionRequest{
			UID:       "http-uid",
			Namespace: pod.Namespace,
			Object:    runtime.RawExtension{Raw: raw},
		},
	}
	body, _ := json.Marshal(review)

	request := httptest.NewRequest(http.MethodPost, "/inject", strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	webhook.serveInject(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	out := admissionv1.AdmissionReview{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Response == nil || !out.Response.Allowed || out.Response.UID != "http-uid" || out.Response.Patch == nil {
		t.Fatalf("response = %+v, want allowed patch echoing request UID", out.Response)
	}

	badType := httptest.NewRequest(http.MethodPost, "/inject", strings.NewReader(string(body)))
	badType.Header.Set("Content-Type", "text/plain")
	recorder = httptest.NewRecorder()
	webhook.serveInject(recorder, badType)
	if recorder.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("bad content type status = %d, want 415", recorder.Code)
	}

	empty := httptest.NewRequest(http.MethodPost, "/inject", strings.NewReader(""))
	empty.Header.Set("Content-Type", "application/json")
	recorder = httptest.NewRecorder()
	webhook.serveInject(recorder, empty)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("empty body status = %d, want 400", recorder.Code)
	}
}
