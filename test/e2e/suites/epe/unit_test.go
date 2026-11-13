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
	"bytes"
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"text/template"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"

	agentiocomponent "github.com/openkruise/agentio/test/e2e/components/agentio"
	"github.com/openkruise/agentio/test/e2e/kube"
)

func TestSetupOrder(t *testing.T) {
	digest := "registry.example/test@sha256:" + strings.Repeat("b", 64)
	setups := suiteSetupGraph(agentiocomponent.Config{
		Namespace:         "agentio-system",
		AgentiodImage:     digest,
		ZtunnelImage:      digest,
		ProxyInitImage:    digest,
		GatewayImage:      digest,
		EPEImage:          digest,
		ExtProcImage:      digest,
		ForwardProxyImage: digest,
	})
	names := make([]string, len(setups))
	for index := range setups {
		names[index] = setups[index].name
	}
	want := []string{
		"agentio", "agentio-baseline", "traffic-policy-namespace", "traffic-policy-client",
		"traffic-policy-server", "fixture-readiness",
	}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("setup order = %v, want %v", names, want)
	}
}

func TestWaitForPrometheusMetricsRetriesTransientConnectionFailure(t *testing.T) {
	attempts := 0
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	output, err := waitForPrometheusMetrics(ctx, func(context.Context) (string, string, error) {
		attempts++
		if attempts == 1 {
			return "", "connection reset by peer", errors.New("exit code 56")
		}
		return "# HELP epe_ready EPE readiness.\n# TYPE epe_ready gauge\n", "", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Fatalf("metrics requests = %d, want 2", attempts)
	}
	if !strings.Contains(output, "# HELP epe_ready") {
		t.Fatalf("metrics output = %q", output)
	}
}

func TestEgressEPEFixtureXDSArguments(t *testing.T) {
	manifest := template.Must(template.New("epe").Option("missingkey=error").Parse(egressEPEYAML))
	var rendered bytes.Buffer
	if err := manifest.Execute(&rendered, map[string]any{
		"Namespace": "agentio-system",
		"Image":     "registry.example/epe@sha256:" + strings.Repeat("b", 64),
	}); err != nil {
		t.Fatal(err)
	}
	objects, err := kube.DecodeYAML(&rendered)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, object := range objects {
		if object.GetKind() != "Pod" {
			continue
		}
		found = true
		var pod corev1.Pod
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(object.Object, &pod); err != nil {
			t.Fatal(err)
		}
		args := pod.Spec.Containers[0].Args
		if slices.Contains(args, "--enable-xds-egressauthz") {
			t.Fatalf("removed TrafficPolicy authorization argument: %v", args)
		}
		if !slices.Contains(args, "--xds-address=agentiod.agentio-system.svc:15012") ||
			pod.Spec.ServiceAccountName != "agentio-epe" {
			t.Fatalf("fixture must configure EPE WDS: args=%v account=%s", args, pod.Spec.ServiceAccountName)
		}
	}
	if !found {
		t.Fatal("fixture did not render a Pod")
	}
}

func TestCredentialProviderFixtureSandboxMode(t *testing.T) {
	manifest := template.Must(template.New("provider").Option("missingkey=error").Parse(providerFixturesYAML))
	var rendered bytes.Buffer
	if err := manifest.Execute(&rendered, map[string]any{
		"Name":           "epe-provider-watch",
		"Namespace":      "agentio-system",
		"EPEImage":       "registry.example/epe:test",
		"ProviderImage":  "registry.example/provider:test",
		"EnvironmentURL": "http://credential-provider:8080/credentials/environment",
	}); err != nil {
		t.Fatal(err)
	}
	objects, err := kube.DecodeYAML(&rendered)
	if err != nil {
		t.Fatal(err)
	}
	for _, object := range objects {
		if object.GetKind() != "Pod" || object.GetName() != "epe-provider-watch" {
			continue
		}
		var pod corev1.Pod
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(object.Object, &pod); err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(pod.Spec.Containers[0].Env, corev1.EnvVar{Name: "AGENTIO_SANDBOX_MODE", Value: "true"}) {
			t.Fatal("credential-provider EPE must enable Sandbox mode for its Sandbox caller")
		}
		return
	}
	t.Fatal("fixture did not render the credential-provider EPE Pod")
}
