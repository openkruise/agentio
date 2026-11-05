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
	"sync/atomic"
	"testing"
	"time"

	apiMeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientfeatures "k8s.io/client-go/features"
	clientfeaturestesting "k8s.io/client-go/features/testing"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayfake "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned/fake"
	gatewayclientv1 "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned/typed/apis/v1"
	gatewayinformers "sigs.k8s.io/gateway-api/pkg/client/informers/externalversions/apis/v1"

	"github.com/openkruise/agentio/internal/testutil"
	"github.com/openkruise/agentio/pkg/kube/kclient"
)

func TestClassControllerReportsAcceptedForOwnedClass(t *testing.T) {
	clientfeaturestesting.SetFeatureDuringTest(t, clientfeatures.WatchListClient, false)

	client := gatewayfake.NewSimpleClientset(&gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "agentio-egress", Generation: 3},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayv1.GatewayController("agentio.kruise.io/egress-gateway-controller"),
		},
	})
	informer := gatewayinformers.NewGatewayClassInformer(client, 0, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	classes := kclient.NewWritable[*gatewayv1.GatewayClass, gatewayclientv1.GatewayClassInterface](informer, func(string) gatewayclientv1.GatewayClassInterface {
		return client.GatewayV1().GatewayClasses()
	})
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go informer.Run(stop)
	if !cache.WaitForCacheSync(stop, informer.HasSynced) {
		t.Fatal("GatewayClass informer failed to sync")
	}
	controller := NewClassController(classes)
	go controller.Run(stop)

	testutil.Eventually(t, func() bool {
		current, err := client.GatewayV1().GatewayClasses().Get(context.Background(), "agentio-egress", metav1.GetOptions{})
		if err != nil {
			return false
		}
		condition := apiMeta.FindStatusCondition(current.Status.Conditions, string(gatewayv1.GatewayClassConditionStatusAccepted))
		return condition != nil && condition.Status == metav1.ConditionTrue &&
			condition.Reason == string(gatewayv1.GatewayClassReasonAccepted) &&
			condition.ObservedGeneration == current.Generation
	}, "owned GatewayClass to report Accepted=True")
}

func TestClassControllerCreatesMissingBuiltinClasses(t *testing.T) {
	// The fake clientset does not support the watch-list protocol, so disable
	// WatchListClient and fall back to plain List+Watch.
	clientfeaturestesting.SetFeatureDuringTest(t, clientfeatures.WatchListClient, false)

	client := gatewayfake.NewSimpleClientset(&gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "agentio-egress"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayv1.GatewayController("example.com/custom"),
		},
	})
	// The fake tracker cannot distinguish recreate from original, so count Create calls instead.
	var createCount int32
	client.PrependReactor("create", "gatewayclasses", func(action clienttesting.Action) (bool, runtime.Object, error) {
		if action.(clienttesting.CreateAction).GetObject().(*gatewayv1.GatewayClass).Name == "agentio-egress" {
			atomic.AddInt32(&createCount, 1)
		}
		return false, nil, nil
	})
	resource := client.GatewayV1().GatewayClasses()
	informer := gatewayinformers.NewGatewayClassInformer(client, 0, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	classes := kclient.NewWritable[*gatewayv1.GatewayClass, gatewayclientv1.GatewayClassInterface](informer, func(string) gatewayclientv1.GatewayClassInterface {
		return resource
	})

	stop := make(chan struct{})
	defer close(stop)
	go informer.Run(stop)
	if !cache.WaitForCacheSync(stop, informer.HasSynced) {
		t.Fatal("GatewayClass informer failed to sync")
	}
	controller := NewClassController(classes)
	go controller.Run(stop)

	// The pre-existing "agentio-egress" class above already exists with a
	// non-builtin controllerName, so the controller's initial reconcile must
	// observe it via Get and skip Create entirely.
	testutil.Eventually(t, func() bool {
		return classes.Get("agentio-egress", "") != nil
	}, "agentio-egress informer cache to observe pre-existing class")

	agentioEgress, err := client.GatewayV1().GatewayClasses().Get(context.Background(), "agentio-egress", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(agentioEgress.Spec.ControllerName); got != "example.com/custom" {
		t.Fatalf("pre-existing agentio-egress class was overwritten: controllerName=%q", got)
	}

	// Let the initial reconcile settle so the baseline only reflects
	// already-completed Create attempts, not ones still racing with delete.
	baseline := waitForCreateCountToStabilize(t, &createCount)
	if baseline != 0 {
		t.Fatalf("controller issued %d Create calls against a pre-existing class, want 0", baseline)
	}

	if err := client.GatewayV1().GatewayClasses().Delete(context.Background(), "agentio-egress", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	testutil.Eventually(t, func() bool {
		_, err := client.GatewayV1().GatewayClasses().Get(context.Background(), "agentio-egress", metav1.GetOptions{})
		return err == nil
	}, "agentio-egress to be recreated")
	recreated, err := client.GatewayV1().GatewayClasses().Get(context.Background(), "agentio-egress", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(recreated.Spec.ControllerName); got != "agentio.kruise.io/egress-gateway-controller" {
		t.Fatalf("recreated agentio-egress controllerName=%q, want agentio.kruise.io/egress-gateway-controller", got)
	}
	testutil.Eventually(t, func() bool {
		return atomic.LoadInt32(&createCount) > baseline
	}, "controller to issue a fresh Create after the delete event")
}

// waitForCreateCountToStabilize waits until count stops changing across
// consecutive polls, then returns its settled value.
func waitForCreateCountToStabilize(t *testing.T, count *int32) int32 {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	last := atomic.LoadInt32(count)
	stableSince := time.Now()
	for time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
		current := atomic.LoadInt32(count)
		if current != last {
			last = current
			stableSince = time.Now()
			continue
		}
		if time.Since(stableSince) >= 100*time.Millisecond {
			return last
		}
	}
	t.Fatalf("create count never stabilized, last value %d", last)
	return last
}
