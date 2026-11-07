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

// CABundlePatcher keeps the validation ValidatingWebhookConfiguration's
// clientConfig.caBundle in sync with the control plane's workload root.
// The composition root triggers
// Sync on CA rotation by subscribing to Authority.TrustBundles.

package validation

import (
	"fmt"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	admissionclientv1 "k8s.io/client-go/kubernetes/typed/admissionregistration/v1"

	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/kube/controllers"
	"github.com/openkruise/agentio/pkg/kube/kclient"
)

// CABundlePatcher reconciles one ValidatingWebhookConfiguration's caBundle
// fields against the current trust bundle. All replicas may run it: writes
// compare against the desired state first, so steady state is read-only.
type CABundlePatcher struct {
	webhookName string
	bundle      func() []byte

	webhooks kclient.StartableClient[*admissionregistrationv1.ValidatingWebhookConfiguration]
	queue    controllers.Queue
}

// NewCABundlePatcher creates a patcher for the named webhook configuration.
// bundle returns the current PEM trust bundle (Authority.RootPEM).
func NewCABundlePatcher(client kube.Client, webhookName string, bundle func() []byte) (*CABundlePatcher, error) {
	if client == nil || bundle == nil {
		return nil, fmt.Errorf("kubernetes client and bundle source are required")
	}
	if webhookName == "" {
		return nil, fmt.Errorf("webhook configuration name is required")
	}
	p := &CABundlePatcher{
		webhookName: webhookName,
		bundle:      bundle,
	}
	informer := kclient.NewFiltered[*admissionregistrationv1.ValidatingWebhookConfiguration](client, kclient.Filter{
		FieldSelector: fields.OneTermEqualSelector(metav1.ObjectNameField, webhookName).String(),
	})
	p.webhooks = kclient.NewWritableStatuslessFromInformer(
		informer,
		func(string) admissionclientv1.ValidatingWebhookConfigurationInterface {
			return client.Kube().AdmissionregistrationV1().ValidatingWebhookConfigurations()
		})
	p.queue = controllers.NewQueue("validation caBundle patcher",
		controllers.WithReconciler(p.reconcile),
		controllers.WithMaxAttempts(5))
	return p, nil
}

// Sync requests a reconcile, for example after a CA rotation commit. It is
// safe to call before Run; the item is processed once the queue starts.
func (p *CABundlePatcher) Sync() {
	p.queue.Add(types.NamespacedName{Name: p.webhookName})
}

// Run watches the webhook configuration until stop closes.
func (p *CABundlePatcher) Run(stop <-chan struct{}) {
	p.webhooks.AddEventHandler(
		controllers.FilteredObjectSpecHandler(p.queue.AddObject, func(o controllers.Object) bool {
			return o.GetName() == p.webhookName
		}),
	)
	defer controllers.ShutdownAll(p.webhooks)

	p.webhooks.Start(stop)
	if !kube.WaitForCacheSync("validation caBundle patcher", stop, p.webhooks.HasSynced) {
		p.queue.ShutDownEarly()
		return
	}
	p.queue.Run(stop)
}

func (p *CABundlePatcher) reconcile(o types.NamespacedName) error {
	current := p.webhooks.Get(o.Name, "")
	if current == nil {
		// Not installed (chart may not enable validation); nothing to patch.
		return nil
	}
	bundle := p.bundle()
	if len(bundle) == 0 {
		return fmt.Errorf("trust bundle is empty")
	}
	needsUpdate := false
	for i := range current.Webhooks {
		if string(current.Webhooks[i].ClientConfig.CABundle) != string(bundle) {
			needsUpdate = true
			break
		}
	}
	if !needsUpdate {
		return nil
	}
	updated := current.DeepCopy()
	for i := range updated.Webhooks {
		updated.Webhooks[i].ClientConfig.CABundle = append([]byte(nil), bundle...)
	}
	if _, err := p.webhooks.Update(updated); err != nil {
		return fmt.Errorf("patch caBundle on ValidatingWebhookConfiguration %s: %w", o.Name, err)
	}
	return nil
}
