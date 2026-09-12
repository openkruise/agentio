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

package ca

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	kubefake "k8s.io/client-go/kubernetes/fake"
	kubetesting "k8s.io/client-go/testing"

	"github.com/openkruise/agentio/pkg/clienttrust"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/kube/kclient"
	"github.com/openkruise/agentio/pkg/security/mitm"
	"github.com/openkruise/agentio/pkg/security/pki"
)

type clientTrustTest struct {
	ctx           context.Context
	client        kube.Client
	distributor   *ClientTrustDistributor
	configuration krt.StaticSingleton[clienttrust.Settings]
	signer        krt.StaticSingleton[mitm.TrustBundle]
	initial       string
}

func newClientTrustTest(t *testing.T, objects ...runtime.Object) *clientTrustTest {
	t.Helper()
	return newClientTrustTestWithClient(t, kube.NewFakeClient(objects...), "")
}

func newClientTrustTestWithClient(t *testing.T, client kube.Client, secretNamespace string) *clientTrustTest {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	root := clientTrustTestCA(t)
	settings, err := clienttrust.Parse(map[string]any{
		"clientTrust":       map[string]any{"enabled": true},
		"clientTrustBundle": map[string]any{"sources": []any{map[string]any{"agentioMITM": true}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	rig := &clientTrustTest{ctx: ctx, client: client, initial: root,
		configuration: krt.NewStatic(&settings, true),
		signer:        krt.NewStatic(&mitm.TrustBundle{PEM: root}, true),
	}
	informer := kclient.NewFiltered[*corev1.Secret](client, kclient.Filter{Namespace: secretNamespace})
	collection := krt.WrapClient(informer, krt.WithStop(ctx.Done()))
	rig.distributor, err = NewClientTrustDistributor(rig.client, ClientTrustOptions{
		Namespace: "agentio-system", Configuration: rig.configuration, MITMTrustBundle: rig.signer,
		Secrets: collection,
	})
	if err != nil {
		t.Fatal(err)
	}
	rig.distributor.start(ctx)
	rig.client.Run(ctx.Done())
	return rig
}

func (r *clientTrustTest) run(t *testing.T) context.CancelFunc {
	t.Helper()
	leader, cancel := context.WithCancel(r.ctx)
	done := make(chan struct{})
	go func() { defer close(done); r.distributor.runController(leader) }()
	stop := func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("client trust worker did not stop")
		}
	}
	t.Cleanup(stop)
	return stop
}

func clientTrustTestCA(t *testing.T) string {
	t.Helper()
	root, err := pki.NewSelfSignedCA("client trust", 365*24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return string(root.BundlePEM())
}

func (r *clientTrustTest) waitBundle(t *testing.T, namespace string, expected string) *corev1.ConfigMap {
	t.Helper()
	var result *corev1.ConfigMap
	waitForCondition(t, func() bool {
		cm, err := r.client.Kube().CoreV1().ConfigMaps(namespace).Get(r.ctx, "agentio-client-ca", metav1.GetOptions{})
		if err != nil || cm.Data["ca-bundle.pem"] != expected {
			return false
		}
		cached := r.distributor.configMaps.Get(cm.Name, namespace)
		if cached == nil || cached.Data["ca-bundle.pem"] != expected {
			return false
		}
		result = cm
		return true
	}, "client trust bundle in "+namespace)
	return result
}

func TestClientTrustNamespaceEvents(t *testing.T) {
	rig := newClientTrustTest(t,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "plain"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-public"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "terminating"}, Status: corev1.NamespaceStatus{Phase: corev1.NamespaceTerminating}},
	)
	rig.run(t)
	rig.waitBundle(t, "plain", rig.initial)
	rig.waitBundle(t, "kube-system", rig.initial)
	for _, name := range []string{"kube-public", "terminating"} {
		if _, err := rig.client.Kube().CoreV1().ConfigMaps(name).Get(rig.ctx, "agentio-client-ca", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
			t.Fatalf("distributed into excluded namespace %s: %v", name, err)
		}
	}
	if _, err := rig.client.Kube().CoreV1().Namespaces().Create(rig.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "new"}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	rig.waitBundle(t, "new", rig.initial)
	for _, action := range rig.client.Kube().(*kubefake.Clientset).Actions() {
		if action.GetResource().Resource == "pods" {
			t.Fatalf("unexpected Pod access: %v", action)
		}
	}
	// Deletion and drift are repaired even when the desired bundle has not changed.
	if err := rig.client.Kube().CoreV1().ConfigMaps("plain").Delete(rig.ctx, "agentio-client-ca", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	cm := rig.waitBundle(t, "plain", rig.initial)
	cm.Data["ca-bundle.pem"] = "drift"
	if _, err := rig.client.Kube().CoreV1().ConfigMaps("plain").Update(rig.ctx, cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	rig.waitBundle(t, "plain", rig.initial)
}

func TestClientTrustDisableAndReenable(t *testing.T) {
	rig := newClientTrustTest(t, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "app"}})
	rig.run(t)
	original := rig.waitBundle(t, "app", rig.initial)
	configuration := *rig.configuration.Get()
	configuration.Client.Enabled = false
	rig.configuration.Set(&configuration)
	waitForCondition(t, func() bool { return len(rig.distributor.targets.List()) == 0 }, "disabled distribution targets")
	next := clientTrustTestCA(t)
	rig.signer.Set(&mitm.TrustBundle{PEM: next})
	if _, err := rig.client.Kube().CoreV1().Namespaces().Create(rig.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "new"}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	waitForCondition(t, func() bool { return rig.distributor.namespaces.Get("new", "") != nil }, "new namespace cache")
	for _, ns := range []string{"app", "new"} {
		if err := rig.distributor.reconcile(rig.ctx, types.NamespacedName{Namespace: ns, Name: "agentio-client-ca"}); err != nil {
			t.Fatal(err)
		}
	}
	cm, err := rig.client.Kube().CoreV1().ConfigMaps("app").Get(rig.ctx, original.Name, metav1.GetOptions{})
	if err != nil || cm.Data["ca-bundle.pem"] != original.Data["ca-bundle.pem"] {
		t.Fatalf("disabled distribution changed the retained bundle: %v", err)
	}
	if _, err := rig.client.Kube().CoreV1().ConfigMaps("new").Get(rig.ctx, original.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("disabled distribution created a target: %v", err)
	}
	enabled := configuration
	enabled.Client.Enabled = true
	rig.configuration.Set(&enabled)
	rig.waitBundle(t, "app", next)
	rig.waitBundle(t, "new", next)
}

func TestClientTrustBundleEvents(t *testing.T) {
	rig := newClientTrustTest(t, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "app"}})
	stop := rig.run(t)
	rig.waitBundle(t, "app", rig.initial)
	next := clientTrustTestCA(t)
	merged, _, err := clienttrust.Merge([][]byte{[]byte(rig.initial), []byte(next)}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rig.signer.Set(&mitm.TrustBundle{PEM: rig.initial + next})
	rig.waitBundle(t, "app", string(merged))
	// Equivalent inputs do not republish targets.
	var updates atomic.Int32
	registration := rig.distributor.targets.Register(func(event krt.Event[clientTrustTarget]) {
		if event.Old != nil && event.New != nil {
			updates.Add(1)
		}
	})
	defer registration.UnregisterHandler()
	rig.signer.Set(&mitm.TrustBundle{PEM: next + rig.initial + next, Revision: "equivalent"})
	rig.signer.Set(&mitm.TrustBundle{PEM: "-----BEGIN CERTIFICATE-----\ninvalid!\n-----END CERTIFICATE-----\n" + next})
	waitForCondition(t, func() bool { c := rig.distributor.candidates.Get(); return c != nil && c.Error != "" }, "invalid source event")
	if _, err := rig.client.Kube().CoreV1().Namespaces().Create(rig.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "during-error"}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	rig.waitBundle(t, "during-error", string(merged))
	rig.waitBundle(t, "app", string(merged))
	if updates.Load() != 0 {
		t.Fatal("equivalent or invalid source changed existing desired target")
	}
	// Re-entering leadership replays desired state; the valid bundle survives the lease change.
	stop()
	rig.run(t)
	rig.signer.Set(&mitm.TrustBundle{PEM: next})
	rig.waitBundle(t, "app", next)
	rig.waitBundle(t, "during-error", next)
}

func TestClientTrustTargetRetriesAndOwnership(t *testing.T) {
	rig := newClientTrustTest(t,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "app"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "foreign"}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "agentio-client-ca", Namespace: "foreign"}, Data: map[string]string{"ca-bundle.pem": "foreign"}},
	)
	var attempts atomic.Int32
	rig.client.Kube().(*kubefake.Clientset).PrependReactor("create", "configmaps", func(action kubetesting.Action) (bool, runtime.Object, error) {
		if action.GetNamespace() == "app" && attempts.Add(1) == 1 {
			return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "configmaps"}, "agentio-client-ca", nil)
		}
		return false, nil, nil
	})
	rig.run(t)
	rig.waitBundle(t, "app", rig.initial)
	if attempts.Load() < 2 {
		t.Fatal("failed target was not retried")
	}
	cm, err := rig.client.Kube().CoreV1().ConfigMaps("foreign").Get(rig.ctx, "agentio-client-ca", metav1.GetOptions{})
	if err != nil || cm.Data["ca-bundle.pem"] != "foreign" {
		t.Fatalf("foreign target overwritten: %v", err)
	}
}

func TestClientTrustReconcileCancellation(t *testing.T) {
	rig := newClientTrustTest(t,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "first"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "second"}},
	)
	waitForCondition(t, rig.distributor.targets.HasSynced, "desired targets")
	cycle, cancel := context.WithCancel(rig.ctx)
	defer cancel()
	writes := 0
	rig.client.Kube().(*kubefake.Clientset).PrependReactor("create", "configmaps", func(kubetesting.Action) (bool, runtime.Object, error) { writes++; cancel(); return false, nil, nil })
	if err := rig.distributor.reconcile(cycle, types.NamespacedName{Namespace: "first", Name: "agentio-client-ca"}); err != nil {
		t.Fatal(err)
	}
	if err := rig.distributor.reconcile(cycle, types.NamespacedName{Namespace: "second", Name: "agentio-client-ca"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled reconciliation: %v", err)
	}
	if writes != 1 {
		t.Fatalf("canceled worker performed %d writes", writes)
	}
}

func (r *clientTrustTest) setSources(sources ...clienttrust.Source) {
	next := *r.configuration.Get()
	next.Bundle.Sources = sources
	r.configuration.Set(&next)
}

func TestClientTrustWaitsForSecretCache(t *testing.T) {
	client := kube.NewFakeClient(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "app"}})
	var denied atomic.Bool
	var attempts atomic.Int32
	denied.Store(true)
	fake := client.Kube().(*kubefake.Clientset)
	fake.PrependReactor("list", "secrets", func(kubetesting.Action) (bool, runtime.Object, error) {
		attempts.Add(1)
		if denied.Load() {
			return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, "", errors.New("access denied"))
		}
		return false, nil, nil
	})
	rig := newClientTrustTestWithClient(t, client, "agentio-system")
	stop := rig.run(t)
	// Even with a valid MITM bundle, the worker requires its shared Secret cache.
	waitForCondition(t, func() bool {
		return attempts.Load() >= 2 && rig.distributor.targets.HasSynced()
	}, "Secret list retries while distribution waits for cache sync")
	if rig.distributor.options.Secrets.HasSynced() {
		t.Fatal("denied Secret cache reported synced")
	}
	// Losing leadership during startup must stop the waiting worker cleanly.
	stop()
	if _, err := fake.CoreV1().ConfigMaps("app").Get(rig.ctx, "agentio-client-ca", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("unsynced distributor published a bundle: %v", err)
	}

	// A later leader starts distributing once permissions allow the cache to sync.
	rig.run(t)
	denied.Store(false)
	rig.waitBundle(t, "app", rig.initial)
}

func TestClientTrustSourceEvents(t *testing.T) {
	first, second := clientTrustTestCA(t), clientTrustTestCA(t)
	rig := newClientTrustTest(t,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "app"}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "public", Namespace: "source"}, Data: map[string]string{"ca": first}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "private", Namespace: "source"}, Data: map[string][]byte{"ca": []byte(second)}},
	)
	fake := rig.client.Kube().(*kubefake.Clientset)
	rig.run(t)
	rig.waitBundle(t, "app", rig.initial)
	cmSource := clienttrust.Source{ConfigMap: &clienttrust.Reference{Namespace: "source", Name: "public", Key: "ca"}}
	secretSource := clienttrust.Source{Secret: &clienttrust.Reference{Namespace: "source", Name: "private", Key: "ca"}}
	rig.setSources(cmSource, secretSource)
	merged, _, err := clienttrust.Merge([][]byte{[]byte(first), []byte(second)}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rig.waitBundle(t, "app", string(merged))
	// Source changes alone rebuild and distribute the bundle.
	next := clientTrustTestCA(t)
	cm, err := fake.CoreV1().ConfigMaps("source").Get(rig.ctx, "public", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cm.Data["ca"] = next
	if _, err = fake.CoreV1().ConfigMaps("source").Update(rig.ctx, cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	merged, _, err = clienttrust.Merge([][]byte{[]byte(next), []byte(second)}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rig.waitBundle(t, "app", string(merged))
	secret, err := fake.CoreV1().Secrets("source").Get(rig.ctx, "private", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	secret.Data["ca"] = []byte("-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----")
	if _, err = fake.CoreV1().Secrets("source").Update(rig.ctx, secret, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	waitForCondition(t, func() bool {
		result := rig.distributor.candidates.Get()
		return result != nil && strings.Contains(result.Error, "non-certificate")
	}, "invalid Secret source")
	rig.waitBundle(t, "app", string(merged))
	if err = fake.CoreV1().Secrets("source").Delete(rig.ctx, "private", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	waitForCondition(t, func() bool {
		result := rig.distributor.candidates.Get()
		return result != nil && strings.Contains(result.Error, "unavailable")
	}, "deleted Secret source")
	secret.Data["ca"] = []byte(first)
	if _, err = fake.CoreV1().Secrets("source").Create(rig.ctx, secret, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	merged, _, err = clienttrust.Merge([][]byte{[]byte(next), []byte(first)}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rig.waitBundle(t, "app", string(merged))
	rig.setSources(cmSource)
	rig.waitBundle(t, "app", next)
	rig.setSources(cmSource, secretSource)
	rig.waitBundle(t, "app", string(merged))
	assertClientTrustSharedWatch(t, fake)

	for _, action := range fake.Actions() {
		if action.GetResource().Resource == "secrets" && action.GetVerb() == "list" {
			fields := action.(kubetesting.ListAction).GetListRestrictions().Fields.String()
			if action.GetNamespace() != "" || fields != "" {
				t.Fatalf("unscoped Secret list: %v", action)
			}
		}
	}
}

func TestClientTrustSharedSecretCache(t *testing.T) {
	first, second := clientTrustTestCA(t), clientTrustTestCA(t)
	rig := newClientTrustTest(t,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "app"}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "first", Namespace: "source"}, Data: map[string][]byte{"ca": []byte(first)}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "second", Namespace: "other"}, Data: map[string][]byte{"ca": []byte(second)}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "unrelated", Namespace: "source"}, Data: map[string][]byte{"ca": []byte("not a CA")}},
	)
	fake := rig.client.Kube().(*kubefake.Clientset)
	rig.run(t)
	firstSource := clienttrust.Source{Secret: &clienttrust.Reference{Namespace: "source", Name: "first", Key: "ca"}}
	secondSource := clienttrust.Source{Secret: &clienttrust.Reference{Namespace: "other", Name: "second", Key: "ca"}}
	rig.setSources(firstSource, secondSource)
	merged, _, err := clienttrust.Merge([][]byte{[]byte(first), []byte(second)}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rig.waitBundle(t, "app", string(merged))
	rig.setSources(secondSource)
	rig.waitBundle(t, "app", second)

	disabled := *rig.configuration.Get()
	disabled.Client.Enabled = false
	rig.configuration.Set(&disabled)
	waitForCondition(t, func() bool { return len(rig.distributor.targets.List()) == 0 }, "disabled distribution")
	secret, err := fake.CoreV1().Secrets("other").Get(rig.ctx, "second", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	secret.Data["ca"] = []byte(first)
	if _, err = fake.CoreV1().Secrets("other").Update(rig.ctx, secret, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	// The shared cache continues observing changes while this consumer is disabled.
	waitForCondition(t, func() bool {
		value := rig.distributor.options.Secrets.GetKey("other/second")
		return value != nil && string((*value).Data["ca"]) == first
	}, "shared cache updated while distribution was disabled")
	enabled := disabled
	enabled.Client.Enabled = true
	rig.configuration.Set(&enabled)
	rig.waitBundle(t, "app", first)
	assertClientTrustSharedWatch(t, fake)
}

func assertClientTrustSharedWatch(t *testing.T, client *kubefake.Clientset) {
	t.Helper()
	watches := 0
	for _, action := range client.Actions() {
		if action.GetResource().Resource == "secrets" && action.GetVerb() == "watch" {
			watches++
			if action.GetNamespace() != "" || action.(kubetesting.WatchAction).GetWatchRestrictions().Fields.String() != "" {
				t.Fatalf("unexpected shared Secret watch scope: %v", action)
			}
		}
	}
	if watches != 1 {
		t.Fatalf("Secret watch count = %d, want one shared watch", watches)
	}
}

func TestClientTrustOutOfScopeSourceRemoval(t *testing.T) {
	root := clientTrustTestCA(t)
	client := kube.NewFakeClient(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "app"}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "roots", Namespace: "agentio-system"}, Data: map[string][]byte{"ca": []byte(root)}},
	)
	fake := client.Kube().(*kubefake.Clientset)
	rig := newClientTrustTestWithClient(t, client, "agentio-system")
	rig.run(t)
	rig.waitBundle(t, "app", rig.initial)
	healthy := clienttrust.Source{Secret: &clienttrust.Reference{Namespace: "agentio-system", Name: "roots", Key: "ca"}}
	rig.setSources(clienttrust.Source{Secret: &clienttrust.Reference{Namespace: "unreadable", Name: "roots", Key: "ca"}}, healthy)
	waitForCondition(t, func() bool {
		result := rig.distributor.candidates.Get()
		return result != nil && strings.Contains(result.Error, "Secret unreadable/roots is unavailable")
	}, "source outside the shared cache")
	rig.waitBundle(t, "app", rig.initial)
	rig.setSources(healthy)
	rig.waitBundle(t, "app", root)
	for _, action := range fake.Actions() {
		if action.GetResource().Resource == "secrets" && (action.GetVerb() == "list" || action.GetVerb() == "watch") && action.GetNamespace() != "agentio-system" {
			t.Fatalf("out-of-scope reference started another Secret informer: %v", action)
		}
	}
}

func TestClientTrustInvalidTargetChange(t *testing.T) {
	rig := newClientTrustTest(t, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "app"}})
	rig.run(t)
	rig.waitBundle(t, "app", rig.initial)
	next := *rig.configuration.Get()
	next.Bundle.Target.ConfigMapName = "new-client-ca"
	next.Bundle.Sources = []clienttrust.Source{{ConfigMap: &clienttrust.Reference{Namespace: "missing", Name: "missing", Key: "ca"}}}
	rig.configuration.Set(&next)
	waitForCondition(t, func() bool {
		result := rig.distributor.candidates.Get()
		return result != nil && result.Bundle.Target.ConfigMapName == "new-client-ca" && result.Error != ""
	}, "invalid target revision")
	if _, err := rig.client.Kube().CoreV1().ConfigMaps("app").Get(rig.ctx, "new-client-ca", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("new target inherited an unrelated old bundle: %v", err)
	}
	valid := next
	valid.Bundle.Sources = []clienttrust.Source{{AgentioMITM: true}}
	rig.configuration.Set(&valid)
	waitForCondition(t, func() bool {
		cm, err := rig.client.Kube().CoreV1().ConfigMaps("app").Get(rig.ctx, "new-client-ca", metav1.GetOptions{})
		return err == nil && cm.Data["ca-bundle.pem"] == rig.initial
	}, "new valid target")
}
