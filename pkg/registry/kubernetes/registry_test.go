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
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kubefake "k8s.io/client-go/kubernetes/fake"
	kubetesting "k8s.io/client-go/testing"

	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/security/attestation"
	"github.com/openkruise/agentio/pkg/security/mitm"
)

var _ interface {
	ResolveScope(model.PeerIdentity, string) (model.ClientScope, error)
} = (*PodScopeResolver)(nil)

var _ attestation.DelegatedIdentityAuthorizer = (*DelegatedIdentityAuthorizer)(nil)
var _ mitm.GatewayCertificateAuthorizer = (*GatewayCertificateAuthorizer)(nil)

func TestRegistrySecretScope(t *testing.T) {
	for _, tt := range []struct {
		name           string
		scopedSecrets  bool
		watchNamespace string
		secretCount    int
	}{
		{name: "root namespace", scopedSecrets: true, watchNamespace: "agentio-system", secretCount: 1},
		{name: "all namespaces", secretCount: 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			client := &fakeKubeClient{
				Client: kube.NewFakeClient(
					&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "roots", Namespace: "agentio-system"}},
					&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "roots", Namespace: "other"}},
				),
				watcher: newFakeGatewayCRDWatcher(),
			}
			registry, err := New(client, Options{
				ClusterID:     "test",
				TrustDomain:   "cluster.local",
				RootNamespace: "agentio-system",
				ScopedSecrets: tt.scopedSecrets,
			}, ctx.Done())
			if err != nil {
				t.Fatal(err)
			}
			fake := client.Kube().(*kubefake.Clientset)
			for _, action := range fake.Actions() {
				if action.GetResource().Resource == "secrets" {
					t.Fatalf("Secret informer started before client.Run: %v", action)
				}
			}
			client.Run(ctx.Done())
			eventually(t, registry.Secrets.HasSynced, "Secret cache synchronization")
			eventually(t, func() bool {
				for _, action := range fake.Actions() {
					if action.GetResource().Resource == "secrets" && action.GetVerb() == "watch" {
						return true
					}
				}
				return false
			}, "shared Secret watch")
			if got := len(registry.Secrets.List()); got != tt.secretCount {
				t.Fatalf("cached Secrets = %d, want %d", got, tt.secretCount)
			}
			if registry.Secrets.GetKey("agentio-system/roots") == nil {
				t.Fatal("root namespace Secret is missing")
			}
			if got := registry.Secrets.GetKey("other/roots") != nil; got == tt.scopedSecrets {
				t.Fatalf("other namespace Secret visible = %v", got)
			}
			watches := 0
			for _, action := range fake.Actions() {
				if action.GetResource().Resource != "secrets" {
					continue
				}
				if action.GetNamespace() != tt.watchNamespace {
					t.Fatalf("Secret request namespace = %q, want %q", action.GetNamespace(), tt.watchNamespace)
				}
				if action.GetVerb() == "watch" {
					watches++
					if fields := action.(kubetesting.WatchAction).GetWatchRestrictions().Fields.String(); fields != "" {
						t.Fatalf("shared Secret watch has a field selector: %s", fields)
					}
				}
			}
			if watches != 1 {
				t.Fatalf("Secret watches = %d, want 1", watches)
			}
			if err := fake.CoreV1().Secrets("agentio-system").Delete(ctx, "roots", metav1.DeleteOptions{}); err != nil {
				t.Fatal(err)
			}
			eventually(t, func() bool {
				return registry.Secrets.GetKey("agentio-system/roots") == nil
			}, "Secret deletion in shared cache")
		})
	}
}

func TestRegistrySyncDoesNotRequireSecrets(t *testing.T) {
	ctx := t.Context()
	client := &fakeKubeClient{
		Client:  kube.NewFakeClient(),
		watcher: newFakeGatewayCRDWatcher(),
	}
	fake := client.Kube().(*kubefake.Clientset)
	fake.PrependReactor("list", "secrets", func(kubetesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, "", fmt.Errorf("access denied"))
	})
	registry, err := New(client, Options{
		ClusterID:     "test",
		TrustDomain:   "cluster.local",
		RootNamespace: "agentio-system",
		ScopedSecrets: true,
	}, ctx.Done())
	if err != nil {
		t.Fatal(err)
	}
	client.Run(ctx.Done())
	eventually(t, func() bool {
		for _, action := range fake.Actions() {
			if action.GetResource().Resource == "secrets" && action.GetVerb() == "list" {
				return true
			}
		}
		return false
	}, "Secret list attempt")
	eventually(t, registry.HasSynced, "registry synchronization without Secret access")
	if registry.Secrets.HasSynced() {
		t.Fatal("Secret cache unexpectedly synced without list permission")
	}
}

func TestDelegatedAuthorizationUsesNodePrincipalIndex(t *testing.T) {
	ctx := t.Context()

	ztunnel := delegationPod("agentio-system", "ztunnel-abc", "ztunnel", "node-a")
	target := delegationPod("demo", "target", "app", "node-a")
	// Keep the old container name here to pin runtime compatibility.
	target.Spec.Containers = []corev1.Container{{
		Name: "istio-proxy",
		Args: []string{"proxy", "ztunnel"},
		Env: []corev1.EnvVar{
			{Name: "ENABLE_SIDECAR_MODE", Value: "true"},
			{Name: "PROXY_MODE", Value: "dedicated"},
		},
	}}
	objects := []runtime.Object{ztunnel, target}
	for i := range 256 {
		pod := delegationPod("noise", fmt.Sprintf("pod-%03d", i), fmt.Sprintf("account-%03d", i), "node-a")
		pod.Annotations = map[string]string{"ambient.istio.io/redirection": "enabled"}
		objects = append(objects, pod)
	}
	registry := newTestRegistry(t, ctx, objects, nil)

	if got := len(registry.podsByNode.Lookup("node-a")); got != 258 {
		t.Fatalf("node candidates = %d, want 258", got)
	}
	const key = "node-a|spiffe://cluster.local/ns/demo/sa/app"
	candidates := registry.delegationPodsByNodePrincipal.Lookup(key)
	if len(candidates) != 1 || candidates[0].Name != target.Name {
		t.Fatalf("delegation candidates = %#v, want only %s", candidates, target.Name)
	}

	// Authorization must not fall back to the broader node index, whose bucket
	// also contains every unrelated Pod above.
	registry.podsByNode = nil
	caller := model.PeerIdentity{
		Principal: model.Principal{
			Kind:        model.PrincipalServiceAccount,
			TrustDomain: "cluster.local",
			ServiceAccount: model.ServiceAccountRef{
				Namespace:      "agentio-system",
				ServiceAccount: "ztunnel",
			},
		},
		AttestedBy: model.AttestationKubernetes,
		Kubernetes: model.KubernetesPeer{
			WorkloadName: ztunnel.Name,
			WorkloadUID:  string(ztunnel.UID),
		},
	}
	requested := model.Principal{
		Kind:        model.PrincipalServiceAccount,
		TrustDomain: "cluster.local",
		ServiceAccount: model.ServiceAccountRef{
			Namespace:      "demo",
			ServiceAccount: "app",
		},
	}
	if err := registry.DelegatedIdentityAuthorizer().Authorize(ctx, caller, requested); err != nil {
		t.Fatalf("Authorize denied valid delegation: %v", err)
	}
}
