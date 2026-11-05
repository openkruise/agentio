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

package gatewaydeployer

import (
	"context"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	discoveryfake "k8s.io/client-go/discovery/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/openkruise/agentio/pkg/kube"
)

func testOptions() Options {
	return Options{
		ClusterID:             "test",
		SystemNamespace:       "agentio-system",
		InjectorConfigMapName: "agentio-sidecar-injector",
		TrustDomain:           "cluster.local",
		ClusterDomain:         "cluster.local",
		CAAddress:             "agentiod.agentio-system.svc:15012",
		LeaseName:             "test-gateway-deployer",
	}
}

// TestNewConstructsClientsAndProvider exercises the cheap parts of New
// against the process-wide fake Kubernetes client. Fake discovery does not
// expose a parseable server version, so New must fall back to the default
// version rather than erroring.
func TestNewConstructsClientsAndProvider(t *testing.T) {
	deployer, err := New(kube.NewFakeClient(), testOptions())
	if err != nil {
		t.Fatalf("New() error = %v, want nil (client construction must not dial the API server)", err)
	}
	if deployer.kubeVersion != defaultKubeVersion {
		t.Fatalf(
			"kubeVersion = %d, want default %d when discovery is unreachable",
			deployer.kubeVersion,
			defaultKubeVersion,
		)
	}
	if deployer.provider == nil {
		t.Fatal("expected a non-nil template provider")
	}
}

func TestDeployerHasNoEmbeddedEgressGatewayConfiguration(t *testing.T) {
	deployer, err := New(kube.NewFakeClient(), testOptions())
	if err != nil {
		t.Fatal(err)
	}
	gw := gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "egress", Namespace: "demo", UID: "uid-egress"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "agentio-egress",
			Listeners: []gatewayv1.Listener{
				{Name: "mesh", Port: 15008, Protocol: gatewayv1.ProtocolType("HBONE")},
			},
		},
	}
	input := buildTemplateInput(gw, builtinClasses["agentio-egress"], "test", parityKubeVersion, "")
	if _, err := deployer.provider.Renderer().Render("egress-gateway", input); err == nil {
		t.Fatal("egress gateway rendered without an injector ConfigMap")
	}
}

func TestDeployerLoadsEgressGatewayTemplateAndValuesFromInjectorConfigMap(t *testing.T) {
	client := kube.NewFakeClient(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "agentio-sidecar-injector", Namespace: "agentio-system"},
		Data: map[string]string{
			"config": `defaultTemplates: [ztunnel]
templates:
  ztunnel: |
    ignored by the gateway deployer
  egress-gateway: |
    apiVersion: v1
    kind: Service
    metadata:
      name: {{ .DeploymentName }}
      annotations:
        config-source: {{ .Values.global.hub }}
`,
			"values": `global:
  hub: injector.example
`,
		},
	})
	deployer, err := New(client, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	for _, informer := range deployer.informers {
		informer.Start(ctx.Done())
	}

	waitForSource := func(want string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			docs, renderErr := deployer.provider.Renderer().
				Render("egress-gateway", TemplateInput{DeploymentName: "egress"})
			if renderErr == nil && len(docs) == 1 && strings.Contains(docs[0], "config-source: "+want) {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("egress gateway renderer did not load %q from the injector ConfigMap", want)
	}
	waitForSource("injector.example")

	configMap, err := client.Kube().
		CoreV1().
		ConfigMaps("agentio-system").
		Get(ctx, "agentio-sidecar-injector", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	configMap.Data["values"] = "global:\n  hub: updated.example\n"
	configMap.ResourceVersion = "updated"
	if _, err := client.Kube().
		CoreV1().
		ConfigMaps("agentio-system").
		Update(ctx, configMap, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	waitForSource("updated.example")
}

func TestNewRendersAgentioDiscoveryAddress(t *testing.T) {
	deployer, err := New(kube.NewFakeClient(), testOptions())
	if err != nil {
		t.Fatal(err)
	}
	values, err := os.ReadFile("testdata/gateway-values.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := deployer.provider.updateFromInjectorConfig(
		testInjectorConfigWithEgressTemplate(t),
		string(values),
	); err != nil {
		t.Fatal(err)
	}
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "egress", Namespace: "demo", UID: "uid-egress"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "agentio-egress",
			Listeners: []gatewayv1.Listener{
				{Name: "mesh", Port: 15008, Protocol: gatewayv1.ProtocolType("HBONE")},
			},
		},
	}
	input := buildTemplateInput(*gw, builtinClasses["agentio-egress"], "test-cluster", parityKubeVersion, "")
	docs, err := deployer.provider.Renderer().Render("egress-gateway", input)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(docs, "\n---\n")
	want := "name: AGENTIO_XDS_ADDRESS\n          value: \"agentiod.agentio-system.svc:15012\""
	if !strings.Contains(got, want) {
		t.Fatalf("rendered proxy config does not target the Agentio control plane; want %s in:\n%s", want, got)
	}
}

func TestParseKubeVersion(t *testing.T) {
	tests := []struct {
		major, minor string
		want         int
		wantErr      bool
	}{
		{major: "1", minor: "33", want: 133},
		{major: "1", minor: "24+", want: 124},
		{major: "abc", minor: "33", wantErr: true},
		{major: "1", minor: "xyz", wantErr: true},
	}
	for _, tc := range tests {
		got, err := parseKubeVersion(tc.major, tc.minor)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseKubeVersion(%q, %q) expected error, got %d", tc.major, tc.minor, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseKubeVersion(%q, %q) unexpected error: %v", tc.major, tc.minor, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseKubeVersion(%q, %q) = %d, want %d", tc.major, tc.minor, got, tc.want)
		}
	}
}

// runControllers returns promptly when the leader context is cancelled.
func TestRunControllersStopsWithLeaderContext(t *testing.T) {
	deployer, err := New(kube.NewFakeClient(), testOptions())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		deployer.runControllers(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("runControllers did not stop after leader context cancellation")
	}
}

func TestSleepContextReturnsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		sleepContext(ctx, time.Minute)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("sleepContext did not return promptly after context cancellation")
	}
}

// newTestDeployerWithGatewayCRD builds a Deployer through the same shared
// client constructor used in production. Discovery reports the Gateway API's
// v1 gateways resource as installed so its fallback CRD check can also be used
// by tests that exercise Run.
func newTestDeployerWithGatewayCRD(t *testing.T) *Deployer {
	t.Helper()
	client := kube.NewFakeClient()
	client.Kube().Discovery().(*discoveryfake.FakeDiscovery).Resources = []*metav1.APIResourceList{
		{
			GroupVersion: gatewayv1.GroupVersion.String(),
			APIResources: []metav1.APIResource{{Name: "gateways", Kind: "Gateway"}},
		},
	}
	deployer, err := New(client, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	return deployer
}

// Verifies two consecutive runControllers cycles do not accumulate informer goroutines.
func TestRunControllersDoesNotLeakInformersAcrossLeaseCycles(t *testing.T) {
	deployer := newTestDeployerWithGatewayCRD(t)

	runOneCycle := func() {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			deployer.runControllers(ctx)
			close(done)
		}()
		// Give the cycle a moment to pass waitForGatewayCRD and start its
		// informer factories before cancelling.
		time.Sleep(100 * time.Millisecond)
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("runControllers did not stop after leader context cancellation")
		}
	}

	settle := func() int {
		// Allow stopped informers' goroutines to actually exit; runtime
		// goroutine teardown is not synchronous with channel close.
		var last int
		for range 20 {
			runtime.GC()
			time.Sleep(50 * time.Millisecond)
			last = runtime.NumGoroutine()
		}
		return last
	}

	baseline := settle()
	runOneCycle()
	afterFirst := settle()
	runOneCycle()
	afterSecond := settle()

	// Slack absorbs goroutine-count noise; a real per-cycle leak would exceed it.
	const slack = 15
	if afterSecond > baseline+slack {
		t.Fatalf(
			"goroutine count grew across two runControllers cycles: baseline=%d afterFirst=%d afterSecond=%d (slack=%d)",
			baseline,
			afterFirst,
			afterSecond,
			slack,
		)
	}
}

// stubCrdWatcher stands in for kclient.CrdWatcher so tests can dictate whether
// the Gateway CRD exists and record which resource waitForGatewayCRD asks
// about. WaitForCRD mirrors the real semantics: true when the CRD is present,
// otherwise block until stop closes and return false.
type stubCrdWatcher struct {
	found     bool
	requested schema.GroupVersionResource
}

func (s *stubCrdWatcher) HasSynced() bool { return true }

func (s *stubCrdWatcher) KnownOrCallback(gvr schema.GroupVersionResource, _ func(stop <-chan struct{})) bool {
	s.requested = gvr
	return s.found
}

func (s *stubCrdWatcher) WaitForCRD(gvr schema.GroupVersionResource, stop <-chan struct{}) bool {
	s.requested = gvr
	if s.found {
		return true
	}
	<-stop
	return false
}

func (s *stubCrdWatcher) Run(<-chan struct{}) {}

// TestWaitForGatewayCRDUsesInjectedWatcher proves an injected CrdWatcher
// replaces discovery polling: the watcher's answer wins even when discovery
// reports no Gateway API resources at all, and the watcher is asked about the
// v1 gateways resource.
func TestWaitForGatewayCRDUsesInjectedWatcher(t *testing.T) {
	newDeployer := func(watcher *stubCrdWatcher) *Deployer {
		// Discovery deliberately reports nothing: only the watcher may say the
		// CRD exists.
		return &Deployer{
			client: &clientWithWatcher{
				Client:  kube.NewFakeClient(),
				watcher: watcher,
			},
			options: testOptions(),
		}
	}

	t.Run("watcher reports the CRD present", func(t *testing.T) {
		watcher := &stubCrdWatcher{found: true}
		if got := newDeployer(watcher).waitForGatewayCRD(make(chan struct{})); got != true {
			t.Fatalf("waitForGatewayCRD = %v, want true from the injected watcher", got)
		}
		if want := (schema.GroupVersionResource{Group: gatewayv1.GroupName, Version: "v1", Resource: "gateways"}); watcher.requested != want {
			t.Fatalf("watcher was asked about %v, want %v", watcher.requested, want)
		}
	})

	t.Run("stop closes before the CRD appears", func(t *testing.T) {
		watcher := &stubCrdWatcher{found: false}
		stop := make(chan struct{})
		close(stop)
		if got := newDeployer(watcher).waitForGatewayCRD(stop); got != false {
			t.Fatalf("waitForGatewayCRD = %v, want false once stop closes first", got)
		}
	})
}

type clientWithWatcher struct {
	kube.Client
	watcher kube.CrdWatcher
}

func (c *clientWithWatcher) CrdWatcher() kube.CrdWatcher {
	return c.watcher
}
