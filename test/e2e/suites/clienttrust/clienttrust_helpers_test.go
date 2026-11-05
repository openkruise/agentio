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

package clienttrust

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/utils/ptr"

	"github.com/openkruise/agentio/test/e2e"
	agentiocomponent "github.com/openkruise/agentio/test/e2e/components/agentio"
	"github.com/openkruise/agentio/test/e2e/components/namespace"
	e2econfig "github.com/openkruise/agentio/test/e2e/config"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

const (
	annotationPrefix   = "sidecar.agentio.kruise.io/"
	bundleEnv          = "AGENTIO_TRUST_BUNDLE"
	revisionAnnotation = "test.client-trust.agentio.kruise.io/revision"
	defaultBundlePath  = "/etc/agentio/client-ca/ca-bundle.pem"
)

var caVariables = []string{"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "CURL_CA_BUNDLE"}

type scenario struct {
	env            *e2e.Environment
	scope          *kube.ResourceScope
	namespace      string
	injector       *corev1.ConfigMap
	originalValues map[string]any
	values         map[string]any
	templates      map[string]any
}

func newScenario(t *testing.T) *scenario {
	t.Helper()
	environment, scope := rig.BeginScenario(t)
	ns := namespace.Create(t, environment, namespace.Config{Prefix: "client-trust", Labels: map[string]string{harness.DataplaneModeLabel: "sidecar"}})
	ctx, cancel := e2e.Context(t, time.Minute)
	defer cancel()
	configMaps, err := environment.Cluster.Kube.CoreV1().ConfigMaps(rig.Config.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: "app=sidecar-injector,app.kubernetes.io/instance=" + rig.Config.ReleaseName,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(configMaps.Items) != 1 {
		t.Fatalf("expected one owned injector ConfigMap, got %d", len(configMaps.Items))
	}
	s := &scenario{env: environment, scope: scope, namespace: ns.Name(), injector: configMaps.Items[0].DeepCopy()}
	s.originalValues = decode(t, s.injector.Data["values"])
	s.values = clone(t, s.originalValues)
	s.templates = decode(t, s.injector.Data["config"])
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		for _, ns := range []string{s.namespace, rig.Config.Namespace} {
			events, err := s.env.Cluster.Kube.CoreV1().Events(ns).List(ctx, metav1.ListOptions{})
			if err == nil {
				s.save(t, ns+"-events", events)
			}
		}
		// Preserve the failing configuration with the harness's retained scenario.
		if t.Failed() {
			return
		}
		if err := s.patch(ctx, map[string]string{"values": s.injector.Data["values"], "config": s.injector.Data["config"]}); err != nil {
			t.Errorf("restore injector configuration: %v", err)
			return
		}
		current, err := s.env.Cluster.Kube.CoreV1().ConfigMaps(s.injector.Namespace).Get(ctx, s.injector.Name, metav1.GetOptions{})
		if err != nil {
			t.Error(err)
			return
		}
		for _, key := range []string{"values", "config"} {
			if current.Data[key] != s.injector.Data[key] {
				t.Errorf("injector %s was not restored", key)
			}
		}
	})
	rig.ApplyConfig(t, scope, map[string]any{"Namespace": rig.Config.Namespace}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    egressPolicies:
    - gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
    egressGateways:
    - name: egress-gateway
      namespace: {{ .Namespace }}
`)
	s.configure(t, baseSettings())
	s.applyTLSProfile(t, s.namespace)
	return s
}

func (s *scenario) applyTLSProfile(t *testing.T, namespaceName string) {
	t.Helper()
	// The production suite enables SNI traffic policy. This profile selects
	// traffic for termination without a Gateway tlsTermination configuration.
	e2econfig.New(s.scope).YAML(namespaceName, `
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: client-trust-termination
spec:
  priority: 10
  selector:
    matchLabels:
      test.agentio.io/client-trust: "true"
  rules:
  - name: terminate-example
    match:
    - domains: [example.com]
      schemes: [https]
    actions:
      bypass: true
`).ApplyOrFail(t, kube.CreateOnly)
}

func baseSettings() map[string]any {
	return map[string]any{"enabled": true, "env": slices.Clone(caVariables), "envConflictPolicy": "Preserve"}
}

func decode(t *testing.T, data string) map[string]any {
	t.Helper()
	var value map[string]any
	if err := yaml.Unmarshal([]byte(data), &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func clone(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var copy map[string]any
	if err := json.Unmarshal(data, &copy); err != nil {
		t.Fatal(err)
	}
	return copy
}

func (s *scenario) patch(ctx context.Context, data map[string]string) error {
	patch, err := json.Marshal(map[string]any{"data": data})
	if err != nil {
		return err
	}
	_, err = s.env.Cluster.Kube.CoreV1().ConfigMaps(s.injector.Namespace).Patch(ctx, s.injector.Name, types.MergePatchType, patch, metav1.PatchOptions{})
	return err
}

func (s *scenario) configure(t *testing.T, settings map[string]any) {
	t.Helper()
	s.values = clone(t, s.originalValues)
	s.values["clientTrust"] = clone(t, settings)
	s.publish(t)
}

func (s *scenario) publish(t *testing.T) {
	t.Helper()
	marker := string(uuid.NewUUID())
	annotations, _ := s.templates["injectedAnnotations"].(map[string]any)
	if annotations == nil {
		annotations = map[string]any{}
		s.templates["injectedAnnotations"] = annotations
	}
	annotations[revisionAnnotation] = marker
	data := map[string]string{}
	for key, value := range map[string]any{"values": s.values, "config": s.templates} {
		encoded, err := yaml.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		data[key] = string(encoded)
	}
	ctx, cancel := e2e.Context(t, 20*time.Second)
	err := s.patch(ctx, data)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	s.save(t, "injector-"+marker, data)
	// Template and values are installed atomically from one ConfigMap revision.
	// The annotation works even with clientTrust disabled or env: [].
	harness.RetryAssertion(t, time.Minute, time.Second, func() error {
		ctx, cancel := e2e.Context(t, 10*time.Second)
		defer cancel()
		pod, _, err := s.env.Kube.AdmitPod(ctx, s.pod("revision-check"))
		if err != nil {
			return err
		}
		if pod.Annotations[revisionAnnotation] != marker {
			return fmt.Errorf("injector has not loaded revision %s", marker)
		}
		return nil
	})
}

func (s *scenario) pod(name string) *corev1.Pod {
	return &corev1.Pod{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"}, ObjectMeta: metav1.ObjectMeta{
		Name: name, Namespace: s.namespace, Labels: map[string]string{"app": name, "test.agentio.io/client-trust": "true"},
		Annotations: map[string]string{annotationPrefix + "native-sidecar": "true"},
	}, Spec: corev1.PodSpec{
		// Idle client fixtures have no state to drain during scenario cleanup.
		TerminationGracePeriodSeconds: ptr.To[int64](5),
		Containers:                    []corev1.Container{{Name: "app-main", Image: clientImage, ImagePullPolicy: corev1.PullIfNotPresent}, {Name: "app-metrics", Image: clientImage, ImagePullPolicy: corev1.PullIfNotPresent}},
		InitContainers:                []corev1.Container{{Name: "bootstrap", Image: clientImage, ImagePullPolicy: corev1.PullIfNotPresent, Command: []string{"sh", "-c", `test -r "$SSL_CERT_FILE"`}}},
	}}
}

func (s *scenario) admit(t *testing.T, pod *corev1.Pod) (*corev1.Pod, []string) {
	t.Helper()
	ctx, cancel := e2e.Context(t, 20*time.Second)
	defer cancel()
	admitted, warnings, err := s.env.Kube.AdmitPod(ctx, pod)
	s.save(t, pod.Name+"-admission", map[string]any{"pod": admitted, "warnings": warnings, "error": fmt.Sprint(err)})
	if err != nil {
		t.Fatalf("admit %s: %v", pod.Name, err)
	}
	return admitted, warnings
}

func (s *scenario) createPod(t *testing.T, pod *corev1.Pod) *corev1.Pod {
	t.Helper()
	data, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	e2econfig.New(s.scope).YAML(pod.Namespace, string(data)).ApplyOrFail(t, kube.CreateOnly)
	ctx, cancel := e2e.Context(t, 2*time.Minute)
	defer cancel()
	ready, err := s.env.Kube.WaitReadyPods(ctx, pod.Namespace, "app="+pod.Name, 1)
	if err != nil {
		t.Fatalf("wait for %s/%s: %v", pod.Namespace, pod.Name, err)
	}
	if err := agentiocomponent.VerifyFirewallBackend(ctx, s.env, rig.Config); err != nil {
		t.Fatal(err)
	}
	s.save(t, pod.Name+"-pod", ready[0])
	return &ready[0]
}

func (s *scenario) save(t *testing.T, name string, value any) {
	t.Helper()
	if err := s.env.Artifacts.WriteJSON(t.Name()+"/"+name+".json", value); err != nil {
		t.Errorf("save diagnostics: %v", err)
	}
}

func envVariable(container corev1.Container, name string) *corev1.EnvVar {
	for _, variable := range container.Env {
		if variable.Name == name {
			return &variable
		}
	}
	return nil
}

func checkSelected(pod *corev1.Pod, names []string) error {
	for _, c := range append(slices.Clone(pod.Spec.Containers), pod.Spec.InitContainers...) {
		selected := slices.Contains(names, c.Name)
		for _, key := range append(slices.Clone(caVariables), bundleEnv) {
			variable := envVariable(c, key)
			if (variable != nil) != selected {
				return fmt.Errorf("container %s variable %s present=%v, selected=%v", c.Name, key, variable != nil, selected)
			}
			if selected && (variable.Value == "" || variable.ValueFrom != nil) {
				return fmt.Errorf("container %s: %s is not a bundle path", c.Name, key)
			}
		}
	}
	return nil
}

func (s *scenario) selected(t *testing.T, pod *corev1.Pod, names ...string) (*corev1.Pod, []string) {
	t.Helper()
	admitted, warnings := s.admit(t, pod)
	if err := checkSelected(admitted, names); err != nil {
		t.Fatal(err)
	}
	return admitted, warnings
}

type httpResult struct {
	Status int    `json:"status"`
	Error  string `json:"error"`
}
type processResult struct {
	Exit   int    `json:"exit"`
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
}
type probeResult struct {
	Env      map[string]*string `json:"env"`
	Requests httpResult         `json:"requests"`
	HTTPX    httpResult         `json:"httpx"`
	Custom   httpResult         `json:"custom_client"`
	TLS      struct {
		Issuer any    `json:"issuer"`
		Error  string `json:"error"`
	} `json:"tls"`
	Node processResult `json:"node"`
	Curl processResult `json:"curl"`
}

func (s *scenario) probe(t *testing.T, pod *corev1.Pod, container, host string) probeResult {
	t.Helper()
	ctx, cancel := e2e.Context(t, 2*time.Minute)
	defer cancel()
	stdout, stderr, err := s.env.Kube.Exec(ctx, pod.Namespace, pod.Name, container, []string{"python", "/opt/clienttrust/probe.py", host}, nil)
	s.save(t, pod.Name+"-"+container+"-"+host, map[string]any{"stdout": stdout, "stderr": stderr, "error": fmt.Sprint(err)})
	if err != nil {
		t.Fatalf("client probe failed: %v; stderr=%s", err, stderr)
	}
	var result probeResult
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("parse client result: %v; stdout=%s", err, stdout)
	}
	return result
}

func checkHTTPS(result probeResult, host string, trusted bool) error {
	if !trusted && host == "example.com" {
		if !strings.Contains(result.Requests.Error, "CERTIFICATE_VERIFY_FAILED") || !strings.Contains(result.HTTPX.Error, "CERTIFICATE_VERIFY_FAILED") || result.TLS.Error == "" || result.Node.Exit != 1 || result.Curl.Exit != 60 {
			return fmt.Errorf("clients did not reject untrusted MITM certificate: %+v", result)
		}
		if result.Env[bundleEnv] != nil {
			return fmt.Errorf("unselected client received builtin bundle variable")
		}
		return nil
	}
	if result.Requests.Status != 200 || result.HTTPX.Status != 200 || result.TLS.Error != "" || result.Curl.Exit != 0 || result.Curl.Stdout != "200" {
		return fmt.Errorf("verified HTTPS failed: %+v", result)
	}
	var node struct {
		Status     int  `json:"status"`
		Authorized bool `json:"authorized"`
	}
	if err := json.Unmarshal([]byte(result.Node.Stdout), &node); err != nil {
		return err
	}
	if result.Node.Exit != 0 || node.Status != 200 || !node.Authorized {
		return fmt.Errorf("Node TLS verification failed: %+v", result.Node)
	}
	if strings.Contains(fmt.Sprint(result.TLS.Issuer), "Agentio MITM Root CA") != (host == "example.com") {
		return fmt.Errorf("unexpected TLS issuer for %s: %v", host, result.TLS.Issuer)
	}
	if trusted && result.Custom.Status != 200 {
		return fmt.Errorf("custom bundle client failed: %+v", result.Custom)
	}
	return nil
}

func (s *scenario) verifiedHTTPS(t *testing.T, pod *corev1.Pod, container string, trusted bool) {
	t.Helper()
	for _, host := range []string{"example.com", "example.org"} {
		harness.RetryAssertion(t, 2*time.Minute, time.Second, func() error {
			return checkHTTPS(s.probe(t, pod, container, host), host, trusted)
		})
	}
}

func assertEnvironment(t *testing.T, c corev1.Container, names []string, path string) {
	t.Helper()
	want := map[string]corev1.EnvVar{}
	for _, name := range append(slices.Clone(names), bundleEnv) {
		want[name] = corev1.EnvVar{Name: name, Value: path}
	}
	got := map[string]corev1.EnvVar{}
	for _, variable := range c.Env {
		if _, duplicate := got[variable.Name]; duplicate {
			t.Fatalf("duplicate environment variable %s", variable.Name)
		}
		got[variable.Name] = variable
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("environment=%+v, want=%+v", c.Env, want)
	}
}
