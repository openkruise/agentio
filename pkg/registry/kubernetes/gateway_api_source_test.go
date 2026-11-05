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

package kubernetes

import (
	"context"
	"sync"
	"testing"

	"istio.io/istio/pkg/util/sets"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/openkruise/agentio/internal/testutil"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/model"
)

type fakeGatewayCRDWatcher struct {
	mu        sync.Mutex
	known     sets.Set[schema.GroupVersionResource]
	callbacks map[schema.GroupVersionResource][]func(<-chan struct{})
}

type fakeKubeClient struct {
	kube.Client
	watcher *fakeGatewayCRDWatcher
}

func (c *fakeKubeClient) CrdWatcher() kube.CrdWatcher { return c.watcher }

func (c *fakeKubeClient) Run(stop <-chan struct{}) {
	c.Client.Run(stop)
	c.watcher.Run(stop)
}

func newFakeGatewayCRDWatcher(resources ...schema.GroupVersionResource) *fakeGatewayCRDWatcher {
	known := sets.NewWithLength[schema.GroupVersionResource](len(resources))
	for _, resource := range resources {
		known.Insert(resource)
	}
	return &fakeGatewayCRDWatcher{
		known:     known,
		callbacks: make(map[schema.GroupVersionResource][]func(<-chan struct{})),
	}
}

func (w *fakeGatewayCRDWatcher) HasSynced() bool { return true }

func (w *fakeGatewayCRDWatcher) KnownOrCallback(
	resource schema.GroupVersionResource,
	callback func(<-chan struct{}),
) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.known.Contains(resource) {
		return true
	}
	w.callbacks[resource] = append(w.callbacks[resource], callback)
	return false
}

func (w *fakeGatewayCRDWatcher) WaitForCRD(schema.GroupVersionResource, <-chan struct{}) bool {
	return false
}

func (w *fakeGatewayCRDWatcher) Run(<-chan struct{}) {}

func (w *fakeGatewayCRDWatcher) install(resource schema.GroupVersionResource, stop <-chan struct{}) {
	w.mu.Lock()
	w.known.Insert(resource)
	callbacks := append([]func(<-chan struct{}){}, w.callbacks[resource]...)
	delete(w.callbacks, resource)
	w.mu.Unlock()
	for _, callback := range callbacks {
		callback(stop)
	}
}

func TestRegistryWithoutGatewayAPICRDsHasAnEmptySyncedSource(t *testing.T) {
	ctx := t.Context()
	registry := newGatewayTestRegistry(
		t,
		ctx,
		newFakeGatewayCRDWatcher(),
	)
	if gateways := registry.Gateways.List(); len(gateways) != 0 {
		t.Fatalf("absent Gateway API source = %+v", gateways)
	}
}

func TestRegistryStartsGatewayAPIInformersForExistingCRDs(t *testing.T) {
	ctx := t.Context()
	registry := newGatewayTestRegistry(
		t,
		ctx,
		newFakeGatewayCRDWatcher(gatewayResource, gatewayClassResource),
		ownedGatewayClass(),
		ownedGateway(),
	)
	testutil.Eventually(t, func() bool {
		return registry.Gateways.GetKey("demo/egress") != nil
	}, "existing Gateway API object")
}

func TestRegistryStartsGatewayAPIInformersAfterCRDsAreInstalled(t *testing.T) {
	ctx := t.Context()
	watcher := newFakeGatewayCRDWatcher()
	registry := newGatewayTestRegistry(
		t,
		ctx,
		watcher,
		ownedGatewayClass(),
		ownedGateway(),
	)

	watcher.install(gatewayResource, ctx.Done())
	watcher.install(gatewayClassResource, ctx.Done())
	testutil.Eventually(t, func() bool {
		return registry.Gateways.GetKey("demo/egress") != nil
	}, "Gateway API object after CRD installation")
}

func newGatewayTestRegistry(
	t *testing.T,
	ctx context.Context,
	watcher *fakeGatewayCRDWatcher,
	objects ...runtime.Object,
) *Registry {
	t.Helper()
	client := &fakeKubeClient{
		Client:  kube.NewFakeClient(objects...),
		watcher: watcher,
	}
	registry, err := New(client, Options{
		ClusterID:     "test",
		TrustDomain:   "cluster.local",
		RootNamespace: "agentio-system",
	}, ctx.Done())
	if err != nil {
		t.Fatalf("new registry: %v", err)
	}
	client.Run(ctx.Done())
	testutil.Eventually(t, registry.HasSynced, "registry synchronization")
	return registry
}

func TestGatewaySourceMergeFailsOverlapClosedAndRecovers(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	agentioConfig := krt.NewStaticCollection[model.Gateway](nil, []model.Gateway{{
		Namespace: "demo",
		Name:      "egress",
		Source:    model.GatewaySourceAgentioConfig,
	}}, options...)
	gatewayAPI := krt.NewMutableCollection[model.Gateway](nil, []model.Gateway{{
		Namespace: "demo",
		Name:      "egress",
		Source:    model.GatewaySourceGatewayAPI,
	}}, options...)
	merged := krt.JoinWithMergeCollection(
		[]krt.Collection[model.Gateway]{agentioConfig, gatewayAPI.AsCollection()},
		model.MergeGatewaySources,
		options...,
	)
	if !merged.WaitUntilSynced(stop) {
		t.Fatal("merged Gateway source did not synchronize")
	}
	testutil.Eventually(t, func() bool {
		gateway := merged.GetKey("demo/egress")
		return gateway != nil && gateway.Source == model.GatewaySourceConflict
	}, "overlapping Gateway source conflict")

	gatewayAPI.DeleteObject("demo/egress")
	testutil.Eventually(t, func() bool {
		gateway := merged.GetKey("demo/egress")
		return gateway != nil && gateway.Source == model.GatewaySourceAgentioConfig
	}, "Gateway source conflict recovery")
}

func ownedGatewayClass() *gatewayv1.GatewayClass {
	return &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "agentio-egress"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: agentioGatewayController,
		},
	}
}

func ownedGateway() *gatewayv1.Gateway {
	return &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo",
			Name:      "egress",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "agentio-egress",
		},
	}
}
