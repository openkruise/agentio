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

package extensionprovider

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kwatch "k8s.io/apimachinery/pkg/watch"
	kubefake "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/certs/certstest"
	"github.com/openkruise/agentio/extensions/epe/pkg/testing/testsupport"
	"github.com/openkruise/agentio/pkg/kube"
)

func TestWatchWithoutSecretReferences(t *testing.T) {
	client := kube.NewFakeClient()
	fake := client.Kube().(*kubefake.Clientset)
	var requests atomic.Int32
	fake.PrependReactor("*", "secrets", func(ktesting.Action) (bool, runtime.Object, error) {
		requests.Add(1)
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, "", fmt.Errorf("denied"))
	})
	fake.PrependWatchReactor("secrets", func(ktesting.Action) (bool, kwatch.Interface, error) {
		requests.Add(1)
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, "", fmt.Errorf("denied"))
	})
	registry := &Registry{}
	t.Cleanup(registry.Close)
	reg := watch(t, client, "system", []string{"epe"}, registry, t.Context().Done(),
		defaultConfig("https://credentials.example"))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if !reg.WaitUntilSynced(ctx.Done()) {
		t.Fatal("configuration without Secret references did not sync")
	}
	waitForAvailableProvider(t, registry, "default")
	if got := requests.Load(); got != 0 {
		t.Fatalf("made %d Secret requests without references", got)
	}
}

func TestWatchForbiddenSecretDoesNotBlockStartup(t *testing.T) {
	for _, optional := range []bool{false, true} {
		t.Run(fmt.Sprintf("optional=%t", optional), func(t *testing.T) {
			cert, key := certstest.SelfSigned(t, 7101)
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "material", Namespace: "ack-agent-identity"},
				Data: map[string][]byte{
					"ca.crt":  certstest.New(t).CAPEM(),
					"tls.crt": cert,
					"tls.key": key,
				},
			}
			client := kube.NewFakeClient(secret)
			var allowed atomic.Bool
			var denied atomic.Int32
			client.Kube().(*kubefake.Clientset).PrependReactor("list", "secrets",
				func(ktesting.Action) (bool, runtime.Object, error) {
					if allowed.Load() {
						return false, nil, nil
					}
					denied.Add(1)
					return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"},
						"material", fmt.Errorf("denied"))
				})
			defaults := defaultConfig("https://credentials.example")
			defaults.ExtensionProviders[0].GetCredentialProvider().Tls = &configv1.ClientTLS{
				Optional: optional,
				CaSource: &configv1.ClientTLS_CaSecretRef{
					CaSecretRef: &configv1.TargetReference{Name: "material", Namespace: "ack-agent-identity"},
				},
				ClientCertificateSource: &configv1.ClientTLS_ClientCertificateSecretRef{
					ClientCertificateSecretRef: &configv1.TargetReference{
						Name:      "material",
						Namespace: "ack-agent-identity",
					},
				},
			}
			registry := &Registry{}
			t.Cleanup(registry.Close)
			reg := watch(t, client, "system", []string{"epe"}, registry, t.Context().Done(), defaults)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			if !reg.WaitUntilSynced(ctx.Done()) {
				t.Fatal("forbidden Secret blocked initial configuration application")
			}
			testsupport.Eventually(t, 5*time.Second, func() error {
				if denied.Load() == 0 {
					return fmt.Errorf("Secret has not been requested")
				}
				return nil
			})
			initial := liveProvider(registry, "default")
			if initial == nil || (initial.err == nil) != optional {
				t.Fatalf("wrong initial provider state for optional=%t: %+v", optional, initial)
			}
			// The reflector retries after RBAC is granted, without restarting EPE
			// or changing AgentioConfig. Optional providers must reload too.
			allowed.Store(true)
			testsupport.Eventually(t, 10*time.Second, func() error {
				provider := liveProvider(registry, "default")
				if provider == nil || provider == initial || provider.err != nil {
					return fmt.Errorf("provider has not recovered after Secret permission was granted")
				}
				return nil
			})
		})
	}
}

func TestWatchSecretsUsesScopedPermissionsAndStopsUnusedWatches(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ca := certstest.New(t).CAPEM()
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "epe", Namespace: "system"},
		Data: map[string]string{"config": `extensionProviders:
- name: a
  httpCallout:
    url: https://a.example
    tls:
      caSecretRef: {name: material}
- name: b
  credentialProvider:
    url: https://b.example
    tls:
      caSecretRef: {name: material}
- name: c
  httpCallout:
    url: https://c.example
    tls:
      caSecretRef: {namespace: ack-agent-identity, name: material}
`},
	}
	initialConfig := cm.Data["config"]
	client := kube.NewFakeClient(cm)
	fake := client.Kube().(*kubefake.Clientset)
	// Model Roles restricted by both namespace and resourceNames. An
	// unfiltered or cluster-wide request must not obtain any material.
	expected := map[string]bool{"system/material": true, "ack-agent-identity/material": true}
	fake.PrependReactor("list", "secrets", func(action ktesting.Action) (bool, runtime.Object, error) {
		selector := action.(ktesting.ListAction).GetListRestrictions().Fields
		name, exact := selector.RequiresExactMatch("metadata.name")
		if !exact || !expected[action.GetNamespace()+"/"+name] {
			t.Errorf("unscoped Secret list: namespace=%q selector=%q", action.GetNamespace(), selector)
			return true, nil, apierrors.NewForbidden(
				schema.GroupResource{Resource: "secrets"},
				name,
				fmt.Errorf("denied"),
			)
		}
		return true, &corev1.SecretList{Items: []corev1.Secret{{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: action.GetNamespace()},
			Data:       map[string][]byte{"ca.crt": ca},
		}}}, nil
	})
	type startedWatch struct {
		key   string
		watch *kwatch.RaceFreeFakeWatcher
	}
	started := make(chan startedWatch, 8)
	fake.PrependWatchReactor("secrets", func(action ktesting.Action) (bool, kwatch.Interface, error) {
		selector := action.(ktesting.WatchAction).GetWatchRestrictions().Fields
		name, exact := selector.RequiresExactMatch("metadata.name")
		if !exact || !expected[action.GetNamespace()+"/"+name] {
			t.Errorf("unscoped Secret watch: namespace=%q selector=%q", action.GetNamespace(), selector)
			return true, nil, apierrors.NewForbidden(
				schema.GroupResource{Resource: "secrets"},
				name,
				fmt.Errorf("denied"),
			)
		}
		w := kwatch.NewRaceFreeFake()
		started <- startedWatch{key: action.GetNamespace() + "/" + name, watch: w}
		return true, w, nil
	})
	registry := &Registry{}
	t.Cleanup(registry.Close)
	reg := watch(t, client, "system", []string{"epe"}, registry, ctx.Done())
	waitCtx, waitCancel := context.WithTimeout(ctx, 5*time.Second)
	defer waitCancel()
	if !reg.WaitUntilSynced(waitCtx.Done()) {
		t.Fatal("initial configuration did not sync")
	}
	for _, name := range []string{"a", "b", "c"} {
		waitForAvailableProvider(t, registry, name)
	}
	watches := map[string]*kwatch.RaceFreeFakeWatcher{}
	for range 2 {
		select {
		case w := <-started:
			if watches[w.key] != nil {
				t.Fatalf("duplicate watch for shared reference %q", w.key)
			}
			watches[w.key] = w.watch
		case <-waitCtx.Done():
			t.Fatal("scoped watches did not start")
		}
	}
	// Remove one of the two references to system/material and the sole
	// reference to ack-agent-identity/material. Only that namespace's watch should stop.
	cm.Data["config"] = `extensionProviders:
- name: a
  httpCallout:
    url: https://a.example
    tls:
      caSecretRef: {name: material}
`
	if _, err := client.Kube().CoreV1().ConfigMaps("system").Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	testsupport.Eventually(t, 5*time.Second, func() error {
		if !watches["ack-agent-identity/material"].IsStopped() {
			return fmt.Errorf("unused Secret watch has not stopped")
		}
		return nil
	})
	if watches["system/material"].IsStopped() {
		t.Fatal("watch stopped while still referenced by a provider")
	}
	// Re-adding a removed reference must create a working informer again.
	cm.Data["config"] = initialConfig
	if _, err := client.Kube().CoreV1().ConfigMaps("system").Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	waitForAvailableProvider(t, registry, "c")
	select {
	case w := <-started:
		if w.key != "ack-agent-identity/material" {
			t.Fatalf("unexpected restarted watch for %q", w.key)
		}
		watches[w.key] = w.watch
	case <-waitCtx.Done():
		t.Fatal("removed Secret watch did not restart")
	}
	cancel()
	testsupport.Eventually(t, 5*time.Second, func() error {
		for key, w := range watches {
			if !w.IsStopped() {
				return fmt.Errorf("Secret watch %q has not stopped on shutdown", key)
			}
		}
		return nil
	})
	select {
	case w := <-started:
		t.Fatalf("unexpected additional watch for %q", w.key)
	default:
	}
}
