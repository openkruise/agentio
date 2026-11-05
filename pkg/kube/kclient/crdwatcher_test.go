// Copyright Istio Authors
// Modifications Copyright 2026 The Kruise Authors
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

package kclient_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/Masterminds/semver/v3"
	"go.uber.org/atomic"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	metadatafake "k8s.io/client-go/metadata/fake"

	"github.com/openkruise/agentio/internal/testutil"
	"github.com/openkruise/agentio/pkg/kube/kclient"
)

// Only resource+group matter: the CRD name is rendered "<resource>.<group>".
var (
	virtualServiceGVR   = schema.GroupVersionResource{Group: "networking.istio.io", Version: "v1", Resource: "virtualservices"}
	gatewayClassGVR     = schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gatewayclasses"}
	serviceAccountGVR   = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "serviceaccounts"}
	grpcRouteGVR        = schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "grpcroutes"}
	tlsRouteGVR         = schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1alpha2", Resource: "tlsroutes"}
	ingressGVR          = schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "ingresses"}
	wasmPluginGVR       = schema.GroupVersionResource{Group: "extensions.istio.io", Version: "v1alpha1", Resource: "wasmplugins"}
	telemetryGVR        = schema.GroupVersionResource{Group: "telemetry.istio.io", Version: "v1", Resource: "telemetries"}
	backendTLSPolicyGVR = schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1alpha3", Resource: "backendtlspolicies"}
)

const bundleVersionAnnotation = "gateway.networking.k8s.io/bundle-version"

// newTestWatcher builds a CrdWatcher over a fake metadata client and returns
// both, so tests can inject CRDs via makeCRD and drive the watcher with Run.
func newTestWatcher(t *testing.T, opts kclient.CrdWatcherOptions) (kclient.CrdWatcher, *metadatafake.FakeMetadataClient, chan struct{}) {
	t.Helper()
	fmc := metadatafake.NewSimpleMetadataClient(newTestScheme())
	w := kclient.NewCrdWatcher(fmc, opts)
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	return w, fmc, stop
}

func newTestScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	// The metadata fake stores PartialObjectMetadata for every GVR through the
	// resource actions; registering the meta types plus the fake List
	// workaround (see metadatafake.NewSimpleMetadataClient) is enough for the
	// tracker to list and watch them.
	metav1.AddToGroupVersion(s, schema.GroupVersion{Version: "v1"})
	return s
}

// makeCRD injects a CustomResourceDefinition for the GVR into the fake metadata
// client's tracker. It creates the CRD or updates an existing bundle version.
func makeCRD(t *testing.T, fmc *metadatafake.FakeMetadataClient, g schema.GroupVersionResource, annotations map[string]string) {
	t.Helper()
	obj := &metav1.PartialObjectMetadata{
		ObjectMeta: metav1.ObjectMeta{
			Name:        fmt.Sprintf("%s.%s", g.Resource, g.Group),
			Annotations: annotations,
		},
	}
	crdGVR := schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}
	resource := fmc.Resource(crdGVR)
	md, ok := resource.(metadatafake.MetadataClient)
	if !ok {
		t.Fatalf("fake metadata client does not expose MetadataClient for %v", crdGVR)
	}
	if _, err := md.CreateFake(obj, metav1.CreateOptions{}); err != nil {
		if _, uerr := md.UpdateFake(obj, metav1.UpdateOptions{}); uerr != nil {
			t.Fatalf("create/update fake CRD %s: create=%v update=%v", obj.Name, err, uerr)
		}
	}
}

// runWatcher starts the watcher and blocks until it has synced, so subsequent
// assertions observe a fully-populated CRD cache.
func runWatcher(t *testing.T, w kclient.CrdWatcher, stop <-chan struct{}) {
	t.Helper()
	go w.Run(stop)
	testutil.WaitFor(t, 10*time.Second, w.HasSynced, "crd watcher did not sync")
}

// TestCRDWatcherRace verifies callbacks added during a handler run are not skipped.
func TestCRDWatcherRace(t *testing.T) {
	w, fmc, stop := newTestWatcher(t, kclient.CrdWatcherOptions{})
	calls := atomic.NewInt32(0)

	// Race callback and CRD creation
	go func() {
		if w.KnownOrCallback(virtualServiceGVR, func(s <-chan struct{}) {
			calls.Inc()
		}) {
			// Happened sync
			calls.Inc()
		}
	}()
	makeCRD(t, fmc, virtualServiceGVR, nil)
	runWatcher(t, w, stop)
	testutil.WaitFor(t, 5*time.Second, func() bool { return calls.Load() == 1 },
		fmt.Sprintf("expected 1 callback, got %d", calls.Load()))
}

func TestCRDWatcher(t *testing.T) {
	w, fmc, stop := newTestWatcher(t, kclient.CrdWatcherOptions{})

	makeCRD(t, fmc, virtualServiceGVR, nil)
	vsCalls := atomic.NewInt32(0)

	makeCRD(t, fmc, gatewayClassGVR, nil)

	// Created before informer runs
	if got := w.KnownOrCallback(virtualServiceGVR, func(s <-chan struct{}) {
		vsCalls.Inc()
	}); got != false {
		t.Fatalf("KnownOrCallback(virtualservices) = %v, want false before sync", got)
	}

	runWatcher(t, w, stop)
	testutil.WaitFor(t, 5*time.Second, func() bool { return vsCalls.Load() == 1 },
		fmt.Sprintf("expected 1 virtualservices callback, got %d", vsCalls.Load()))

	// created once running
	if got := w.KnownOrCallback(gatewayClassGVR, func(s <-chan struct{}) {
		t.Fatal("callback should not be called")
	}); got != true {
		t.Fatalf("KnownOrCallback(gatewayclasses) = %v, want true once running", got)
	}

	// Create CRD later
	saCalls := atomic.NewInt32(0)
	// When should return false
	if got := w.KnownOrCallback(serviceAccountGVR, func(s <-chan struct{}) {
		saCalls.Inc()
	}); got != false {
		t.Fatalf("KnownOrCallback(serviceaccounts) = %v, want false before creation", got)
	}
	makeCRD(t, fmc, serviceAccountGVR, nil)
	// And call the callback when the CRD is created
	testutil.WaitFor(t, 5*time.Second, func() bool { return saCalls.Load() == 1 },
		fmt.Sprintf("expected 1 serviceaccounts callback, got %d", saCalls.Load()))
}

// TestCRDWatcherWaitForCRD exercises the blocking API the gateway deployer uses:
// WaitForCRD returns true once the CRD appears, and false if stop closes first.
func TestCRDWatcherWaitForCRD(t *testing.T) {
	w, fmc, stop := newTestWatcher(t, kclient.CrdWatcherOptions{})
	go w.Run(stop)

	// CRD appears after the wait starts.
	go func() {
		time.Sleep(20 * time.Millisecond)
		makeCRD(t, fmc, gatewayClassGVR, nil)
	}()
	if !w.WaitForCRD(gatewayClassGVR, stop) {
		t.Fatal("WaitForCRD(gatewayclasses) = false, want true once the CRD appears")
	}
	// Now present: returns immediately.
	if !w.WaitForCRD(gatewayClassGVR, stop) {
		t.Fatal("WaitForCRD(gatewayclasses) = false on second call, want true")
	}

	// A CRD that never appears: WaitForCRD returns false when stop closes.
	neverStop := make(chan struct{})
	go func() {
		time.Sleep(20 * time.Millisecond)
		close(neverStop)
	}()
	if w.WaitForCRD(serviceAccountGVR, neverStop) {
		t.Fatal("WaitForCRD(serviceaccounts) = true, want false when stop closes before the CRD appears")
	}
}

func TestCRDWatcherMinimumVersion(t *testing.T) {
	w, fmc, stop := newTestWatcher(t, kclient.CrdWatcherOptions{})

	makeCRD(t, fmc, grpcRouteGVR, map[string]string{bundleVersionAnnotation: "v1.0.0"})
	calls := atomic.NewInt32(0)

	// Created before informer runs: not ready yet
	if got := w.KnownOrCallback(grpcRouteGVR, func(s <-chan struct{}) {
		calls.Inc()
	}); got != false {
		t.Fatalf("KnownOrCallback(grpcroutes) = %v, want false before sync", got)
	}

	runWatcher(t, w, stop)

	// Still not ready (v1.0.0 is below the 1.1.0 minimum)
	if calls.Load() != 0 {
		t.Fatalf("expected 0 grpcroutes callbacks at v1.0.0, got %d", calls.Load())
	}

	// Upgrade it to v1.1, which is allowed
	makeCRD(t, fmc, grpcRouteGVR, map[string]string{bundleVersionAnnotation: "v1.1.0"})
	testutil.WaitFor(t, 5*time.Second, func() bool { return calls.Load() == 1 },
		fmt.Sprintf("expected 1 grpcroutes callback after upgrade to v1.1.0, got %d", calls.Load()))
}

func TestCRDWatcherMaximumVersion(t *testing.T) {
	// Temporarily add tlsroutes to MaximumCRDVersions at max 1.4.0 (inclusive).
	const tlsRouteCRDName = "tlsroutes.gateway.networking.k8s.io"

	oldMax := kclient.MaximumCRDVersions[tlsRouteCRDName]
	kclient.MaximumCRDVersions[tlsRouteCRDName] = semver.New(1, 4, 0, "", "")
	t.Cleanup(func() {
		if oldMax == nil {
			delete(kclient.MaximumCRDVersions, tlsRouteCRDName)
		} else {
			kclient.MaximumCRDVersions[tlsRouteCRDName] = oldMax
		}
	})

	// Case 1: bundle v1.5.0 is above the inclusive maximum (1.4.0) — should be rejected.
	t.Run("above maximum is rejected", func(t *testing.T) {
		w, fmc, stop := newTestWatcher(t, kclient.CrdWatcherOptions{})
		makeCRD(t, fmc, tlsRouteGVR, map[string]string{bundleVersionAnnotation: "v1.5.0"})
		calls := atomic.NewInt32(0)
		if got := w.KnownOrCallback(tlsRouteGVR, func(s <-chan struct{}) {
			calls.Inc()
		}); got != false {
			t.Fatalf("KnownOrCallback(tlsroutes) = %v, want false before sync", got)
		}
		runWatcher(t, w, stop)
		if calls.Load() != 0 {
			t.Fatalf("expected 0 tlsroutes callbacks above maximum, got %d", calls.Load())
		}
		if got := w.KnownOrCallback(tlsRouteGVR, func(_ <-chan struct{}) {}); got != false {
			t.Fatalf("KnownOrCallback(tlsroutes) = %v, want false above maximum", got)
		}
	})

	// Case 2: bundle v1.4.0 equals the inclusive maximum — should be accepted.
	t.Run("equal to maximum is accepted", func(t *testing.T) {
		w, fmc, stop := newTestWatcher(t, kclient.CrdWatcherOptions{})
		makeCRD(t, fmc, tlsRouteGVR, map[string]string{bundleVersionAnnotation: "v1.4.0"})
		calls := atomic.NewInt32(0)
		if got := w.KnownOrCallback(tlsRouteGVR, func(s <-chan struct{}) {
			calls.Inc()
		}); got != false {
			t.Fatalf("KnownOrCallback(tlsroutes) = %v, want false before sync", got)
		}
		runWatcher(t, w, stop)
		testutil.WaitFor(t, 5*time.Second, func() bool { return calls.Load() == 1 },
			fmt.Sprintf("expected 1 tlsroutes callback at maximum, got %d", calls.Load()))
	})
}

// This test will verify:
// - If the filter is working, removing all of the ignored resources
// - It will exclude any istio.io resource or ingresses.networking.k8s.io resource
// - It will include any resource from group telemetry.istio.io, or any other non-explicitly
// excluded resource, or the exact match of wasmplugins.extensions.istio.io
// - It will exclude backendtlspolicy because it is too old
// - It will include GatewayClass as it is not being explicitly excluded and also has the right Gateway API version
func TestCRDWatcherWithUnionFilter(t *testing.T) {
	opts := kclient.CrdWatcherOptions{
		// Ignore the whole istio group, and ingresses.
		IgnoreResources: "*.istio.io, ingresses.networking.k8s.io",
		// But add all the telemetry group and Istio wasmplugins.
		IncludeResources: "*.telemetry.istio.io, wasmplugins.extensions.istio.io",
	}
	w, fmc, stop := newTestWatcher(t, opts)

	// VirtualService should not be known because it is on *.istio.io
	makeCRD(t, fmc, virtualServiceGVR, nil)
	// Ingress should not be known because it is explicitly excluded
	makeCRD(t, fmc, ingressGVR, nil)
	// WasmPlugin should be known because it is being explicitly included
	makeCRD(t, fmc, wasmPluginGVR, nil)
	// Telemetries should be known because the whole group is being included
	makeCRD(t, fmc, telemetryGVR, nil)

	// BackendTLSPolicy should be filtered out due to its version
	makeCRD(t, fmc, backendTLSPolicyGVR, map[string]string{bundleVersionAnnotation: "v1.3.0"})

	// GatewayClass should be known because it is not being excluded and has a supported version
	makeCRD(t, fmc, gatewayClassGVR, nil)

	runWatcher(t, w, stop)

	// True assertions - The CRDs below should be known
	for _, gvr := range []schema.GroupVersionResource{gatewayClassGVR, wasmPluginGVR, telemetryGVR} {
		if got := w.KnownOrCallback(gvr, func(s <-chan struct{}) {}); got != true {
			t.Errorf("KnownOrCallback(%s) = %v, want true", gvr.Resource, got)
		}
	}

	// False assertions - The CRDs below should not be known
	for _, gvr := range []schema.GroupVersionResource{backendTLSPolicyGVR, virtualServiceGVR, ingressGVR} {
		if got := w.KnownOrCallback(gvr, func(s <-chan struct{}) {}); got != false {
			t.Errorf("KnownOrCallback(%s) = %v, want false", gvr.Resource, got)
		}
	}
}
