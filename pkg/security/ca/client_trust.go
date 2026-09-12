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
	"fmt"
	"math"
	"os"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	coreclientv1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/util/workqueue"

	"github.com/openkruise/agentio/pkg/clienttrust"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/kube/controllers"
	"github.com/openkruise/agentio/pkg/kube/kclient"
	"github.com/openkruise/agentio/pkg/security/mitm"
)

// ClientTrustOptions connects distribution to validated configuration and public CA sources.
type ClientTrustOptions struct {
	Namespace       string
	PackagePath     string
	Configuration   krt.Singleton[clienttrust.Settings]
	MITMTrustBundle krt.Singleton[mitm.TrustBundle]
	// Secrets is the Secret collection shared by the registry.
	Secrets krt.Collection[*corev1.Secret]
}

// ClientTrustDistributor publishes client trust in the same namespaces as the workload CA.
// KRT derives desired state; only the leader's queue performs Kubernetes writes.
type ClientTrustDistributor struct {
	client       kube.Client
	options      ClientTrustOptions
	configMaps   kclient.StartableClient[*corev1.ConfigMap]
	namespaces   kclient.StartableInformer[*corev1.Namespace]
	packageData  clienttrust.Package
	packageError error
	candidates   krt.Singleton[clientTrustBundleResult]
	bundles      krt.Singleton[clientTrustBundle]
	targets      krt.Collection[clientTrustTarget]
}

// NewClientTrustDistributor registers cached inputs and loads the immutable public CA package.
func NewClientTrustDistributor(client kube.Client, options ClientTrustOptions) (*ClientTrustDistributor, error) {
	if client == nil || options.Namespace == "" || options.Configuration == nil || options.Secrets == nil {
		return nil, fmt.Errorf("client trust distributor requires client, namespace, configuration and Secret source")
	}
	configMaps := kclient.NewWritableStatuslessFromInformer(
		kclient.NewFiltered[*corev1.ConfigMap](client, kclient.Filter{}),
		func(namespace string) coreclientv1.ConfigMapInterface {
			return client.Kube().CoreV1().ConfigMaps(namespace)
		},
	)
	d := &ClientTrustDistributor{
		client:     client,
		options:    options,
		configMaps: configMaps,
		namespaces: kclient.NewFiltered[*corev1.Namespace](client, kclient.Filter{}),
	}
	if options.PackagePath == "" {
		d.packageError = fmt.Errorf("default CA package path is not configured")
	} else {
		data, err := os.ReadFile(options.PackagePath)
		if err == nil {
			d.packageData, err = clienttrust.ParsePackage(data)
		}
		d.packageError = err
	}
	return d, nil
}

// Run maintains process-scoped KRT state and re-enters election after leadership loss.
func (d *ClientTrustDistributor) Run(ctx context.Context) {
	d.start(ctx)
	runLeaseElection(ctx, d.client.Kube(), d.options.Namespace,
		"agentiod-client-trust-leader", "client trust distributor", d.runController)
}

func (d *ClientTrustDistributor) start(ctx context.Context) {
	options := krt.NewOptionsBuilder(ctx.Done(), "Client_Trust", nil)
	configMaps := krt.WrapClient(d.configMaps, options.WithName("ConfigMaps")...)
	namespaces := krt.WrapClient(d.namespaces, options.WithName("Namespaces")...)
	d.candidates = krt.NewSingleton(func(handler krt.HandlerContext) *clientTrustBundleResult {
		configuration := krt.FetchOne(handler, d.options.Configuration.AsCollection())
		if configuration == nil || !configuration.Client.Enabled {
			return nil
		}
		return d.build(handler, configuration.Bundle, configMaps)
	}, options.WithName("Bundle_Result")...)
	d.bundles = krt.NewSingleton(func(handler krt.HandlerContext) *clientTrustBundle {
		result := krt.FetchOne(handler, d.candidates.AsCollection())
		if result == nil || result.Error != "" {
			// Keep the last complete bundle and still subscribe to missing sources.
			handler.DiscardResult()
			return nil
		}
		return &result.Bundle
	}, options.WithName("Bundle")...)
	d.targets = krt.NewCollection(namespaces, func(handler krt.HandlerContext, ns *corev1.Namespace) *clientTrustTarget {
		if ns.Status.Phase == corev1.NamespaceTerminating || ns.DeletionTimestamp != nil || distributorIgnoredNamespaces.Contains(ns.Name) {
			return nil
		}
		configuration := krt.FetchOne(handler, d.options.Configuration.AsCollection())
		bundle := krt.FetchOne(handler, d.bundles.AsCollection())
		if configuration == nil || !configuration.Client.Enabled {
			return nil
		}
		if bundle == nil || bundle.Target != configuration.Bundle.Target {
			return nil
		}
		return &clientTrustTarget{Namespace: ns.Name, Bundle: *bundle}
	}, options.WithName("Targets")...)
	d.configMaps.Start(ctx.Done())
	d.namespaces.Start(ctx.Done())
}

func (d *ClientTrustDistributor) runController(ctx context.Context) {
	failures := map[types.NamespacedName]string{}
	queue := controllers.NewQueue("client trust distributor",
		// Retry failed targets until recovery, with bounded backoff rather than a global resync.
		controllers.WithMaxAttempts(math.MaxInt),
		controllers.WithRateLimiter(workqueue.NewTypedItemExponentialFailureRateLimiter[any](time.Second, time.Minute)),
		controllers.WithReconciler(func(key types.NamespacedName) error {
			cycle, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			var err error
			if key.Name == "" {
				err = d.sourceError()
			} else {
				err = d.reconcile(cycle, key)
			}
			if ctx.Err() != nil {
				return nil
			}
			if err != nil {
				if failures[key] != err.Error() {
					log.Error("client trust reconciliation failed", "target", key.String(), "error", err)
					d.recordError(cycle, err)
					failures[key] = err.Error()
				}
			} else {
				delete(failures, key)
			}
			if key.Name == "" {
				// Invalid inputs recover through source events, not repeated parsing.
				return nil
			}
			return err
		}))
	targetWatch := d.targets.Register(func(event krt.Event[clientTrustTarget]) {
		target := event.Latest()
		queue.Add(types.NamespacedName{Namespace: target.Namespace, Name: target.Bundle.Target.ConfigMapName})
	})
	defer targetWatch.UnregisterHandler()
	sourceWatch := d.candidates.Register(func(krt.Event[clientTrustBundleResult]) { queue.Add(types.NamespacedName{}) })
	defer sourceWatch.UnregisterHandler()
	configMapWatch := d.configMaps.AddEventHandler(controllers.ObjectHandler(func(object controllers.Object) {
		key := types.NamespacedName{Namespace: object.GetNamespace(), Name: object.GetName()}
		if d.targets.GetKey(key.String()) != nil {
			queue.Add(key)
		}
	}))
	defer d.configMaps.ShutdownHandler(configMapWatch)
	if !kube.WaitForCacheSync(
		"client trust distributor",
		ctx.Done(),
		d.namespaces.HasSynced,
		d.configMaps.HasSynced,
		d.options.Secrets.HasSynced,
		d.targets.HasSynced,
	) {
		queue.ShutDownEarly()
		return
	}
	queue.Run(ctx.Done())
	// Finish in-flight reconciliation before a later lease acquisition starts a new worker.
	<-queue.Closed()
}

func (d *ClientTrustDistributor) sourceError() error {
	result := d.candidates.Get()
	if result == nil {
		return nil
	}
	if result.Error != "" {
		return fmt.Errorf("client trust bundle: %s", result.Error)
	}
	for _, warning := range result.Warnings {
		log.Warn("client trust certificate expiry", "detail", warning)
	}
	return nil
}

func (d *ClientTrustDistributor) reconcile(ctx context.Context, key types.NamespacedName) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	desired := d.targets.GetKey(key.String())
	if desired == nil {
		return nil
	}
	ns := d.namespaces.Get(key.Namespace, "")
	if ns == nil || ns.Status.Phase == corev1.NamespaceTerminating || ns.DeletionTimestamp != nil {
		return nil
	}
	configuration := d.options.Configuration.Get()
	if configuration == nil || !configuration.Client.Enabled || configuration.Bundle.Target != desired.Bundle.Target {
		return nil
	}
	return d.write(ctx, key.Namespace, desired.Bundle.Target, []byte(desired.Bundle.PEM), desired.Bundle.Version)
}

func (d *ClientTrustDistributor) write(
	ctx context.Context,
	namespace string,
	target clienttrust.Target,
	bundle []byte,
	version string,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	cm := d.configMaps.Get(target.ConfigMapName, namespace)
	create := cm == nil

	owner := d.options.Namespace + "/client-trust"
	if create {
		cm = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:        target.ConfigMapName,
				Namespace:   namespace,
				Annotations: map[string]string{clienttrust.OwnerAnnotation: owner},
			},
			Data: map[string]string{},
		}
	} else {
		if cm.Annotations[clienttrust.OwnerAnnotation] != owner {
			return fmt.Errorf("client trust target %s/%s belongs to another owner", namespace, target.ConfigMapName)
		}
		if cm.Data[target.Key] == string(bundle) &&
			cm.Annotations[clienttrust.PackageAnnotation] == version &&
			cm.Annotations[clienttrust.DigestAnnotation] == clienttrust.Digest(bundle) {
			return nil
		}
		cm = cm.DeepCopy()
	}
	if cm.Data == nil {
		cm.Data = map[string]string{}
	}
	cm.Data[target.Key] = string(bundle)
	cm.Annotations[clienttrust.DigestAnnotation] = clienttrust.Digest(bundle)
	cm.Annotations[clienttrust.PackageAnnotation] = version
	var err error
	if create {
		_, err = d.configMaps.Create(cm)
	} else {
		_, err = d.configMaps.Update(cm)
	}
	return err
}

// recordError emits one bounded event per changed failure alongside logs.
func (d *ClientTrustDistributor) recordError(ctx context.Context, cause error) {
	message := cause.Error()
	if len(message) > 1024 {
		message = message[:1024]
	}
	now := metav1.Now()
	eventCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err := d.client.Kube().CoreV1().Events(d.options.Namespace).Create(eventCtx, &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "client-trust-",
			Namespace:    d.options.Namespace,
		},
		InvolvedObject: corev1.ObjectReference{
			APIVersion: "coordination.k8s.io/v1",
			Kind:       "Lease",
			Namespace:  d.options.Namespace,
			Name:       "agentiod-client-trust-leader",
		},
		Reason:         "ClientTrustReconcileFailed",
		Message:        message,
		Type:           corev1.EventTypeWarning,
		Source:         corev1.EventSource{Component: "agentiod-client-trust"},
		FirstTimestamp: now,
		LastTimestamp:  now,
		Count:          1,
	}, metav1.CreateOptions{})
	if err != nil {
		log.Warn("could not record client trust event", "error", err)
	}
}
