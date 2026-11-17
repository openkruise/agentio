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

package validation

import (
	"errors"
	"sync/atomic"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubefake "k8s.io/client-go/kubernetes/fake"
	kubetesting "k8s.io/client-go/testing"

	"github.com/openkruise/agentio/internal/testutil"
	"github.com/openkruise/agentio/pkg/kube"
)

func TestCABundlePatcher(t *testing.T) {
	const name = "validator"
	client := kube.NewFakeClient(&admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Webhooks:   []admissionregistrationv1.ValidatingWebhook{{Name: "validation.agentio.kruise.io"}},
	})
	var bundle atomic.Value
	bundle.Store([]byte("initial-root"))
	p, err := NewCABundlePatcher(client, name, func() []byte { return bundle.Load().([]byte) })
	if err != nil {
		t.Fatal(err)
	}
	go p.Run(t.Context().Done())
	for _, want := range []string{"initial-root", "rotated-root"} {
		bundle.Store([]byte(want))
		p.Sync()
		testutil.Eventually(t, func() bool {
			current, err := client.Kube().
				AdmissionregistrationV1().
				ValidatingWebhookConfigurations().
				Get(t.Context(), name, metav1.GetOptions{})
			return err == nil && string(current.Webhooks[0].ClientConfig.CABundle) == want
		}, "validation webhook CA bundle to converge")
	}
}

func TestCABundlePatcherRetriesConflicts(t *testing.T) {
	const name = "validator"
	client := kube.NewFakeClient(&admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Webhooks:   []admissionregistrationv1.ValidatingWebhook{{Name: "validation.agentio.kruise.io"}},
	})
	var attempts atomic.Int32
	client.Kube().(*kubefake.Clientset).PrependReactor(
		"update",
		"validatingwebhookconfigurations",
		func(action kubetesting.Action) (bool, runtime.Object, error) {
			if attempts.Add(1) <= 5 {
				return true, nil, apierrors.NewConflict(
					action.GetResource().GroupResource(),
					name,
					errors.New("concurrent update"),
				)
			}
			return false, nil, nil
		},
	)
	p, err := NewCABundlePatcher(client, name, func() []byte { return []byte("root") })
	if err != nil {
		t.Fatal(err)
	}
	go p.Run(t.Context().Done())
	testutil.Eventually(t, func() bool {
		current, err := client.Kube().
			AdmissionregistrationV1().
			ValidatingWebhookConfigurations().
			Get(t.Context(), name, metav1.GetOptions{})
		return err == nil && string(current.Webhooks[0].ClientConfig.CABundle) == "root"
	}, "validation webhook CA bundle to converge after five conflicts without another event")
	if got := attempts.Load(); got != 6 {
		t.Fatalf("update attempts = %d, want 6", got)
	}
}
