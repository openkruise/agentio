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

package echo

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/openkruise/agentio/test/e2e"
	"github.com/openkruise/agentio/test/e2e/cluster"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/retry"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestManifestsUsePinnedImagePortsAndGRPCReadiness(t *testing.T) {
	objects, err := manifests(Config{Name: "server", Namespace: "sandbox"})
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 3 {
		t.Fatalf("manifest count = %d", len(objects))
	}
	deployment := objectByKind(t, objects, "Deployment")
	containers, _, err := unstructured.NestedSlice(deployment.Object, "spec", "template", "spec", "containers")
	if err != nil || len(containers) != 1 {
		t.Fatalf("containers = %#v, err = %v", containers, err)
	}
	container := containers[0].(map[string]any)
	if container["image"] != DefaultImage {
		t.Fatalf("image = %v", container["image"])
	}
	args := strings.Join(stringSlice(t, container["args"]), " ")
	for _, want := range []string{
		"--port=18080", "--port=18443", "--tls=18443", "--port=18085", "--grpc=17070", "--tcp=19090", "--tcp=16060", "--udp=19200",
		"--crt=/cert.crt", "--key=/cert.key", "--ca=/root-cert.pem",
	} {
		if !strings.Contains(args, want) {
			t.Fatalf("args %q missing %q", args, want)
		}
	}
	readiness := container["readinessProbe"].(map[string]any)
	if readiness["httpGet"] == nil {
		t.Fatalf("readiness = %#v", readiness)
	}
	service := objectByKind(t, objects, "Service")
	ports, _, _ := unstructured.NestedSlice(service.Object, "spec", "ports")
	if len(ports) != len(DefaultPorts()) || !servicePortHasProtocol(ports, "udp", "UDP") {
		t.Fatalf("service ports = %#v", ports)
	}
}

func TestManifestsDeriveDefaultPortsAndCapabilities(t *testing.T) {
	objects, err := manifests(Config{
		Name:         "client",
		Namespace:    "sandbox",
		Capabilities: []corev1.Capability{"NET_ADMIN", "NET_RAW"},
	})
	if err != nil {
		t.Fatal(err)
	}
	service := objectByKind(t, objects, "Service")
	rawPorts, _, err := unstructured.NestedSlice(service.Object, "spec", "ports")
	if err != nil {
		t.Fatal(err)
	}
	wantPorts := []Port{
		{Name: "http", Protocol: HTTP, ServicePort: 80, WorkloadPort: 18080},
		{Name: "https", Protocol: HTTPS, ServicePort: 443, WorkloadPort: 18443, TLS: true},
		{Name: "http2", Protocol: HTTP2, ServicePort: 85, WorkloadPort: 18085},
		{Name: "grpc", Protocol: GRPC, ServicePort: 7070, WorkloadPort: 17070},
		{Name: "tcp", Protocol: TCP, ServicePort: 9090, WorkloadPort: 19090},
		{Name: "udp", Protocol: UDP, ServicePort: 9200, WorkloadPort: 19200},
		{Name: "tcp-server", Protocol: TCP, ServicePort: 9091, WorkloadPort: 16060},
		{Name: "auto-http", Protocol: HTTP, ServicePort: 81, WorkloadPort: 18081},
		{Name: "auto-https", Protocol: HTTPS, ServicePort: 9443, WorkloadPort: 19443, TLS: true},
		{Name: "http-instance", Protocol: HTTP, ServicePort: 82, WorkloadPort: 18082},
	}
	if len(rawPorts) != len(wantPorts) {
		t.Fatalf("Service ports = %#v, want %d entries", rawPorts, len(wantPorts))
	}
	for index, want := range wantPorts {
		got := rawPorts[index].(map[string]any)
		protocol := "TCP"
		if want.Protocol == UDP {
			protocol = "UDP"
		}
		if got["name"] != want.Name || got["port"] != int64(want.ServicePort) || got["targetPort"] != int64(want.WorkloadPort) || got["protocol"] != protocol {
			t.Fatalf("Service port %d = %#v, want %+v with protocol %s", index, got, want, protocol)
		}
	}
	deployment := objectByKind(t, objects, "Deployment")
	containers, _, _ := unstructured.NestedSlice(deployment.Object, "spec", "template", "spec", "containers")
	container := containers[0].(map[string]any)
	args := strings.Join(stringSlice(t, container["args"]), " ")
	for _, want := range []string{
		"--port=18080", "--port=18443", "--tls=18443", "--port=18085", "--grpc=17070",
		"--tcp=19090", "--udp=19200", "--tcp=16060", "--port=18081", "--port=19443",
		"--tls=19443", "--port=18082",
	} {
		if !strings.Contains(args, want) {
			t.Fatalf("args %q missing %q", args, want)
		}
	}
	security := container["securityContext"].(map[string]any)
	capabilities := security["capabilities"].(map[string]any)
	if got := stringSlice(t, capabilities["add"]); !reflect.DeepEqual(got, []string{"NET_ADMIN", "NET_RAW"}) {
		t.Fatalf("capabilities = %v", got)
	}
}

func TestManifestsUseCustomPortsInsteadOfDefaults(t *testing.T) {
	objects, err := manifests(Config{
		Name:      "server",
		Namespace: "sandbox",
		Ports:     []Port{{Name: "custom-tcp", Protocol: TCP, ServicePort: 1234, WorkloadPort: 4321}},
	})
	if err != nil {
		t.Fatal(err)
	}
	service := objectByKind(t, objects, "Service")
	ports, _, _ := unstructured.NestedSlice(service.Object, "spec", "ports")
	if len(ports) != 1 {
		t.Fatalf("custom Service ports = %#v", ports)
	}
	port := ports[0].(map[string]any)
	if port["name"] != "custom-tcp" || port["port"] != int64(1234) || port["targetPort"] != int64(4321) {
		t.Fatalf("custom Service port = %#v", port)
	}
	deployment := objectByKind(t, objects, "Deployment")
	containers, _, _ := unstructured.NestedSlice(deployment.Object, "spec", "template", "spec", "containers")
	args := strings.Join(stringSlice(t, containers[0].(map[string]any)["args"]), " ")
	if !strings.Contains(args, "--tcp=4321") || strings.Contains(args, "--port=18080") {
		t.Fatalf("custom args = %q", args)
	}
}

func TestManifestsRejectInvalidPortModels(t *testing.T) {
	tests := []struct {
		name  string
		ports []Port
		want  string
	}{
		{name: "duplicate name", ports: []Port{{Name: "same", Protocol: HTTP, ServicePort: 80, WorkloadPort: 18080}, {Name: "same", Protocol: TCP, ServicePort: 90, WorkloadPort: 19090}}, want: "duplicate port name"},
		{name: "duplicate service port", ports: []Port{{Name: "one", Protocol: HTTP, ServicePort: 80, WorkloadPort: 18080}, {Name: "two", Protocol: TCP, ServicePort: 80, WorkloadPort: 19090}}, want: "duplicate service port"},
		{name: "duplicate workload port", ports: []Port{{Name: "one", Protocol: HTTP, ServicePort: 80, WorkloadPort: 18080}, {Name: "two", Protocol: TCP, ServicePort: 90, WorkloadPort: 18080}}, want: "duplicate workload port"},
		{name: "unsupported protocol", ports: []Port{{Name: "bad", Protocol: "smtp", ServicePort: 25, WorkloadPort: 1025}}, want: "unsupported protocol"},
		{name: "TLS on HTTP", ports: []Port{{Name: "bad", Protocol: HTTP, ServicePort: 80, WorkloadPort: 18080, TLS: true}}, want: "TLS requires HTTPS"},
		{name: "HTTPS without TLS", ports: []Port{{Name: "bad", Protocol: HTTPS, ServicePort: 443, WorkloadPort: 18443}}, want: "HTTPS requires TLS"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := manifests(Config{Name: "server", Namespace: "sandbox", Ports: tc.ports})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("manifests() error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestInstanceFindsNormalizedPortByName(t *testing.T) {
	instance := Instance{config: normalizedConfig(Config{})}
	port, found := instance.Port("auto-https")
	if !found || port.ServicePort != 9443 || port.WorkloadPort != 19443 || !port.TLS {
		t.Fatalf("auto-https = %+v, found = %t", port, found)
	}
	if _, found := instance.Port("missing"); found {
		t.Fatal("missing port was reported present")
	}
}

func TestInstanceBuildsCallOptionsForNamedPort(t *testing.T) {
	instance := Instance{config: normalizedConfig(Config{Name: "server", Namespace: "sandbox"})}
	options, err := instance.CallOptions("https")
	if err != nil {
		t.Fatal(err)
	}
	if options.Protocol != HTTPS || options.Address != instance.Address() || options.Port != 443 {
		t.Fatalf("options = %+v", options)
	}
	if _, err := instance.CallOptions("missing"); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing port error = %v", err)
	}

	checker := Checker(func(Result, error) error { return nil })
	checked := options.WithCheck(checker)
	if checked.Check == nil || options.Check != nil {
		t.Fatalf("WithCheck() mutated original or omitted checker: original=%+v checked=%+v", options, checked)
	}
	address := CallOptionsForAddress(TCP, "10.0.0.2", 19090)
	if address.Protocol != TCP || address.Address != "10.0.0.2" || address.Port != 19090 {
		t.Fatalf("address options = %+v", address)
	}
}

func TestConfigRejectsMutableImage(t *testing.T) {
	for _, image := range []string{"repo/app:latest", "repo/app:v1", "repo/app@sha256:short"} {
		_, err := manifests(Config{Name: "server", Namespace: "sandbox", Image: image})
		if err == nil || !strings.Contains(err.Error(), "immutable") {
			t.Fatalf("image %q: error = %v", image, err)
		}
	}
}

func TestCommandArgsForProtocolsAndGRPC(t *testing.T) {
	tests := []struct {
		protocol Protocol
		address  string
		want     []string
	}{
		{HTTP, "server", []string{"/usr/local/bin/client", "http://server:80", "--count", "2", "--timeout", "3s", "--header", "Host:server"}},
		{HTTPS, "server", []string{"/usr/local/bin/client", "https://server:443", "--count", "2", "--timeout", "3s", "--insecure-skip-verify", "--header", "Host:server"}},
		{HTTP2, "server", []string{"/usr/local/bin/client", "http://server:85", "--count", "2", "--timeout", "3s", "--http2", "--header", "Host:server"}},
		{GRPC, "server", []string{"/usr/local/bin/client", "grpc://server:7070", "--count", "2", "--timeout", "3s", "--header", "Host:server"}},
		{TCP, "10.0.0.1", []string{"/usr/local/bin/client", "tcp://10.0.0.1:9090", "--count", "2", "--timeout", "3s"}},
		{UDP, "server", []string{"/usr/local/bin/client", "udp://server:9200", "--count", "2", "--timeout", "3s"}},
	}
	for _, tc := range tests {
		t.Run(string(tc.protocol), func(t *testing.T) {
			got, err := commandArgs(CallOptions{Protocol: tc.protocol, Address: tc.address, Count: 2, Timeout: 3 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("args = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestCommandArgsPacesRequestsOnOneGRPCConnection(t *testing.T) {
	got, err := commandArgs(CallOptions{
		Protocol: GRPC,
		Address:  "server",
		Port:     7070,
		Count:    21,
		QPS:      1,
		Timeout:  30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/usr/local/bin/client", "grpc://server:7070",
		"--count", "21", "--timeout", "30s", "--qps", "1", "--header", "Host:server",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %#v, want %#v", got, want)
	}
}

func TestCommandArgsFollowRedirects(t *testing.T) {
	args, err := commandArgs(CallOptions{
		Protocol:        HTTP,
		Address:         "server",
		Count:           1,
		Timeout:         time.Second,
		FollowRedirects: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(args, "--follow-redirects") {
		t.Fatalf("args = %#v, want --follow-redirects", args)
	}
}

func TestCommandArgsServerName(t *testing.T) {
	args, err := commandArgs(CallOptions{
		Protocol:   HTTPS,
		Address:    "server",
		Count:      1,
		Timeout:    time.Second,
		ServerName: "example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !containsSubsequence(args, []string{"--server-name", "example.com"}) {
		t.Fatalf("args = %#v, want --server-name example.com", args)
	}
}

func TestCommandArgsPreserveProtocolFlagsWithExplicitPortAndPath(t *testing.T) {
	tests := []struct {
		name    string
		options CallOptions
		wantURL string
		wantArg string
	}{
		{
			name:    "https",
			options: CallOptions{Protocol: HTTPS, Address: "example.org", Port: 9443, Path: "/ready", Count: 1, Timeout: time.Second},
			wantURL: "https://example.org:9443/ready",
			wantArg: "--insecure-skip-verify",
		},
		{
			name:    "http2",
			options: CallOptions{Protocol: HTTP2, Address: "server", Port: 85, Path: "/", Count: 1, Timeout: time.Second},
			wantURL: "http://server:85/",
			wantArg: "--http2",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			args, err := commandArgs(tc.options)
			if err != nil {
				t.Fatal(err)
			}
			if args[1] != tc.wantURL || !containsString(args, tc.wantArg) {
				t.Fatalf("args = %#v, want URL %q and %q", args, tc.wantURL, tc.wantArg)
			}
		})
	}
}

func TestCommandArgsPreservePathQuery(t *testing.T) {
	args, err := commandArgs(CallOptions{
		Protocol: HTTP,
		Address:  "server",
		Port:     80,
		Path:     "/?delay=5s",
		Count:    1,
		Timeout:  time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := args[1], "http://server:80/?delay=5s"; got != want {
		t.Fatalf("URL = %q, want %q", got, want)
	}
}

func TestCommandArgsDefaultHostMatchesAgentio(t *testing.T) {
	tests := []struct {
		name    string
		options CallOptions
		want    string
		absent  string
	}{
		{
			name:    "dns address uses bare authority",
			options: CallOptions{Protocol: HTTP, Address: "server.sandbox.svc.cluster.local", Port: 80, Count: 1, Timeout: time.Second},
			want:    "Host:server.sandbox.svc.cluster.local",
		},
		{
			name: "explicit host wins case insensitively",
			options: CallOptions{
				Protocol: HTTP,
				Address:  "server.sandbox.svc.cluster.local",
				Port:     80,
				Count:    1,
				Timeout:  time.Second,
				Headers:  map[string]string{"host": "override.example"},
			},
			want:   "host:override.example",
			absent: "Host:server.sandbox.svc.cluster.local",
		},
		{
			name:    "ip address keeps client authority",
			options: CallOptions{Protocol: HTTP, Address: "192.0.2.1", Port: 80, Count: 1, Timeout: time.Second},
			absent:  "Host:192.0.2.1",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			args, err := commandArgs(tc.options)
			if err != nil {
				t.Fatal(err)
			}
			if tc.want != "" && !containsSubsequence(args, []string{"--header", tc.want}) {
				t.Fatalf("args = %#v, want header %q", args, tc.want)
			}
			if tc.absent != "" && containsSubsequence(args, []string{"--header", tc.absent}) {
				t.Fatalf("args = %#v, do not want header %q", args, tc.absent)
			}
		})
	}
}

func TestCallRetriesAndPreservesFailedAttempt(t *testing.T) {
	calls := 0
	instance := Instance{
		config: Config{CallTimeout: time.Second, Converge: 1},
		pods:   []string{"client-pod"},
		exec: func(context.Context, string, string, string, []string) (string, string, error) {
			calls++
			if calls == 1 {
				return "", "connection refused", errors.New("exit 1")
			}
			return "[0] StatusCode=200\n[0] Hostname=server-a\n", "", nil
		},
	}
	result, err := instance.Call(context.Background(), CallOptions{
		Protocol: HTTP,
		Address:  "server",
		Count:    1,
		Retry:    retry.Policy{Timeout: time.Second, Delay: time.Millisecond, Backoff: 1, MaxDelay: time.Millisecond},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Attempts) != 2 || result.Attempts[0].Error == "" || result.Error != "" {
		t.Fatalf("result = %+v", result)
	}
	if len(result.Responses) != 1 || result.Responses[0].StatusCode != 200 {
		t.Fatalf("responses = %+v", result.Responses)
	}
}

func TestCallCheckerParticipatesInRetry(t *testing.T) {
	calls := 0
	instance := Instance{
		config: Config{CallTimeout: time.Second, Converge: 1},
		pods:   []string{"client-pod"},
		exec: func(context.Context, string, string, string, []string) (string, string, error) {
			calls++
			status := 503
			if calls > 1 {
				status = 200
			}
			return fmt.Sprintf("[0] StatusCode=%d\n[0] Hostname=server-a\n", status), "", nil
		},
	}
	result, err := instance.Call(context.Background(), CallOptions{
		Protocol: HTTP,
		Address:  "server",
		Count:    1,
		Retry:    retry.Policy{Timeout: time.Second, Delay: time.Millisecond, Backoff: 1, MaxDelay: time.Millisecond},
		Check: func(result Result, err error) error {
			if err != nil {
				return err
			}
			if len(result.Responses) != 1 || result.Responses[0].StatusCode != 200 {
				return fmt.Errorf("status is not 200: %+v", result.Responses)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(result.Attempts) != 2 || result.Responses[0].StatusCode != 200 {
		t.Fatalf("calls = %d, result = %+v", calls, result)
	}
}

func TestCallCheckerAcceptsExpectedError(t *testing.T) {
	calls := 0
	instance := Instance{
		config: Config{CallTimeout: time.Second, Converge: 1},
		pods:   []string{"client-pod"},
		exec: func(context.Context, string, string, string, []string) (string, string, error) {
			calls++
			return "", "connection refused", errors.New("exit 1")
		},
	}
	result, err := instance.Call(context.Background(), CallOptions{
		Protocol: HTTP,
		Address:  "server",
		Count:    1,
		Retry:    retry.Policy{Timeout: time.Second, Delay: time.Millisecond, Backoff: 1, MaxDelay: time.Millisecond},
		Check: func(_ Result, err error) error {
			if err == nil {
				return errors.New("expected call error")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || len(result.Attempts) != 1 || !strings.Contains(result.Error, "connection refused") {
		t.Fatalf("calls = %d, result = %+v", calls, result)
	}
}

func TestCallOrFailUsesTestingDeadlineContext(t *testing.T) {
	instance := Instance{
		config: Config{CallTimeout: time.Second, Converge: 1},
		pods:   []string{"client-pod"},
		exec: func(context.Context, string, string, string, []string) (string, string, error) {
			return "[0] StatusCode=200\n[0] Hostname=server-a\n", "", nil
		},
	}
	result := instance.CallOrFail(t, CallOptions{
		Protocol: HTTP,
		Address:  "server",
		Count:    1,
		Check: func(result Result, err error) error {
			if err != nil || len(result.Responses) != 1 || result.Responses[0].StatusCode != 200 {
				return fmt.Errorf("unexpected result: %+v, %v", result, err)
			}
			return nil
		},
	})
	if len(result.Responses) != 1 {
		t.Fatalf("result = %+v", result)
	}
}

func TestDeployReturnsReadyHandleAndCleansResources(t *testing.T) {
	environment, dynamicClient := echoEnvironment(t)
	var deployed Instance
	t.Run("scope", func(t *testing.T) {
		deployed = Deploy(t, environment, Config{Name: "server", Namespace: "sandbox"})
		if deployed.Address() != "server.sandbox.svc.cluster.local" || !reflect.DeepEqual(deployed.Pods(), []string{"server-pod"}) {
			t.Fatalf("instance = %+v", deployed)
		}
	})
	for _, resource := range []schema.GroupVersionResource{serviceAccountGVR, serviceGVR, deploymentGVR} {
		_, err := dynamicClient.Resource(resource).Namespace("sandbox").Get(context.Background(), "server", metav1.GetOptions{})
		if !apierrors.IsNotFound(err) {
			t.Fatalf("resource %s remains after cleanup: %v", resource.Resource, err)
		}
	}
}

func TestApplyReturnsReadyHandleAndCleanup(t *testing.T) {
	environment, dynamicClient := echoEnvironment(t)
	instance, cleanup, err := Apply(context.Background(), environment, Config{Name: "server", Namespace: "sandbox"})
	if err != nil {
		t.Fatal(err)
	}
	if instance.Address() != "server.sandbox.svc.cluster.local" || !reflect.DeepEqual(instance.Pods(), []string{"server-pod"}) || cleanup == nil {
		t.Fatalf("instance = %+v, cleanup present = %t", instance, cleanup != nil)
	}
	if err := cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, resource := range []schema.GroupVersionResource{serviceAccountGVR, serviceGVR, deploymentGVR} {
		_, err := dynamicClient.Resource(resource).Namespace("sandbox").Get(context.Background(), "server", metav1.GetOptions{})
		if !apierrors.IsNotFound(err) {
			t.Fatalf("resource %s remains after cleanup: %v", resource.Resource, err)
		}
	}
}

func TestServiceIPReturnsRoutableClusterIP(t *testing.T) {
	environment, _ := echoEnvironment(t)
	instance, cleanup, err := Apply(context.Background(), environment, Config{Name: "server", Namespace: "sandbox"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cleanup(context.Background()) })
	if _, err := environment.Cluster.Kube.CoreV1().Services("sandbox").Create(context.Background(), &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "server", Namespace: "sandbox"},
		Spec:       corev1.ServiceSpec{ClusterIP: "10.96.0.42"},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	address, err := instance.ServiceIP(context.Background())
	if err != nil || address != "10.96.0.42" {
		t.Fatalf("ServiceIP() = %q, %v", address, err)
	}
}

func TestWorkloadsRefreshesReadyPodNamesAndIPs(t *testing.T) {
	environment, _ := echoEnvironment(t)
	instance, cleanup, err := Apply(context.Background(), environment, Config{Name: "server", Namespace: "sandbox"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cleanup(context.Background()) })
	pods := environment.Cluster.Kube.CoreV1().Pods("sandbox")
	if err := pods.Delete(context.Background(), "server-pod", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, pod := range []*corev1.Pod{
		readyPod("server-b", "10.0.0.3", true),
		readyPod("server-a", "10.0.0.2", true),
		readyPod("server-pending", "10.0.0.4", false),
	} {
		if _, err := pods.Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	workloads, err := instance.Workloads(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []Workload{{Name: "server-a", Address: "10.0.0.2"}, {Name: "server-b", Address: "10.0.0.3"}}
	if !reflect.DeepEqual(workloads, want) {
		t.Fatalf("workloads = %+v, want %+v", workloads, want)
	}
}

func TestExecUsesFirstCurrentReadyWorkload(t *testing.T) {
	var gotPod string
	var gotArgs []string
	instance := Instance{
		config: Config{Namespace: "sandbox"},
		workloads: func(context.Context) ([]Workload, error) {
			return []Workload{{Name: "client-a", Address: "10.0.0.2"}}, nil
		},
		exec: func(_ context.Context, _, pod, container string, args []string) (string, string, error) {
			if container != "app" {
				t.Fatalf("container = %q", container)
			}
			gotPod = pod
			gotArgs = append([]string(nil), args...)
			return "pong", "", nil
		},
	}
	wantArgs := []string{"ping", "-c", "1", "-W", "3", "10.0.0.9"}
	stdout, stderr, err := instance.Exec(context.Background(), wantArgs)
	if err != nil || stdout != "pong" || stderr != "" {
		t.Fatalf("Exec() = %q, %q, %v", stdout, stderr, err)
	}
	if gotPod != "client-a" || !reflect.DeepEqual(gotArgs, wantArgs) {
		t.Fatalf("pod = %q, args = %v", gotPod, gotArgs)
	}
}

func echoEnvironment(t *testing.T) (*e2e.Environment, *dynamicfake.FakeDynamicClient) {
	t.Helper()
	dynamicClient := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	dynamicClient.PrependReactor("create", "*", func(action ktesting.Action) (bool, runtime.Object, error) {
		object := action.(ktesting.CreateAction).GetObject().DeepCopyObject().(*unstructured.Unstructured)
		object.SetUID(types.UID("uid-" + action.GetResource().Resource))
		if object.GetKind() == "Deployment" {
			if err := unstructured.SetNestedField(object.Object, int64(1), "status", "availableReplicas"); err != nil {
				return true, nil, err
			}
		}
		if err := dynamicClient.Tracker().Create(action.GetResource(), object, object.GetNamespace()); err != nil {
			return true, nil, err
		}
		return true, object, nil
	})
	mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{{Group: "", Version: "v1"}, {Group: "apps", Version: "v1"}})
	mapper.Add(serviceAccountGVK, meta.RESTScopeNamespace)
	mapper.Add(serviceGVK, meta.RESTScopeNamespace)
	mapper.Add(deploymentGVK, meta.RESTScopeNamespace)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "server-pod", Namespace: "sandbox", Labels: map[string]string{"app": "server"}}, Status: corev1.PodStatus{Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
	typed := kubernetesfake.NewSimpleClientset(pod)
	clusterHandle := &cluster.Cluster{Dynamic: dynamicClient, Mapper: mapper, Kube: typed}
	client := kube.NewClient("run-1", clusterHandle, kube.NewLedger()).WithTestID(t.Name())
	return &e2e.Environment{RunID: "run-1", Cluster: clusterHandle, Kube: client}, dynamicClient
}

var (
	serviceAccountGVK = schema.GroupVersionKind{Group: "", Version: "v1", Kind: "ServiceAccount"}
	serviceAccountGVR = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "serviceaccounts"}
	serviceGVK        = schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Service"}
	serviceGVR        = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "services"}
	deploymentGVK     = schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"}
	deploymentGVR     = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
)

func objectByKind(t *testing.T, objects []*unstructured.Unstructured, kind string) *unstructured.Unstructured {
	t.Helper()
	for _, object := range objects {
		if object.GetKind() == kind {
			return object
		}
	}
	t.Fatalf("kind %q not found", kind)
	return nil
}

func stringSlice(t *testing.T, value any) []string {
	t.Helper()
	values := value.([]any)
	result := make([]string, len(values))
	for i, item := range values {
		result[i] = item.(string)
	}
	return result
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func containsSubsequence(values, target []string) bool {
	for index := range values {
		if index+len(target) > len(values) {
			break
		}
		if reflect.DeepEqual(values[index:index+len(target)], target) {
			return true
		}
	}
	return false
}

func servicePortHasProtocol(ports []any, name, protocol string) bool {
	for _, value := range ports {
		port := value.(map[string]any)
		if port["name"] == name && port["protocol"] == protocol {
			return true
		}
	}
	return false
}

func readyPod(name, address string, ready bool) *corev1.Pod {
	status := corev1.ConditionFalse
	if ready {
		status = corev1.ConditionTrue
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "sandbox", Labels: map[string]string{"app": "server"}},
		Status: corev1.PodStatus{
			PodIP:      address,
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: status}},
		},
	}
}
