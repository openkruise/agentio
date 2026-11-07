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

package kclient

import (
	"context"
	"fmt"

	"istio.io/istio/pkg/ptr"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/kube/controllers"
)

// NewFiltered creates a shared, typed informer from the process kube.Client.
// Informers with the same GVR, namespace, and selectors share one cache.
func NewFiltered[T controllers.ComparableObject](
	client kube.Client,
	filter Filter,
) StartableInformer[T] {
	return NewFilteredFor[T](client, registrationFor[T](client), filter)
}

// NewFilteredFor is the external-API variant of NewFiltered. The registration
// supplies typed List/Watch functions without adding that API to kube.Client.
func NewFilteredFor[T controllers.ComparableObject](
	client kube.Client,
	registration kube.InformerRegistration,
	filter Filter,
) StartableInformer[T] {
	return newFilteredFor[T](client, registration, filter)
}

func newFilteredFor[T controllers.ComparableObject](
	client kube.Client,
	registration kube.InformerRegistration,
	filter Filter,
) *activeInformer[T] {
	source := client.InformerFor(registration, kube.InformerOptions{
		LabelSelector:   filter.LabelSelector,
		FieldSelector:   filter.FieldSelector,
		Namespace:       filter.Namespace,
		ObjectTransform: filter.ObjectTransform,
	})
	return &activeInformer[T]{
		Informer: newInformerClient[T](source.Informer, filter),
		start:    source.Start,
	}
}

func registrationFor[T controllers.ComparableObject](client kube.Client) kube.InformerRegistration {
	switch any(ptr.Empty[T]()).(type) {
	case *corev1.Pod:
		return namespacedRegistration[*corev1.PodList](
			schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"},
			&corev1.Pod{}, client.Kube().CoreV1().Pods,
		)
	case *corev1.Service:
		return namespacedRegistration[*corev1.ServiceList](
			schema.GroupVersionResource{Group: "", Version: "v1", Resource: "services"},
			&corev1.Service{}, client.Kube().CoreV1().Services,
		)
	case *corev1.ServiceAccount:
		return namespacedRegistration[*corev1.ServiceAccountList](
			schema.GroupVersionResource{Group: "", Version: "v1", Resource: "serviceaccounts"},
			&corev1.ServiceAccount{}, client.Kube().CoreV1().ServiceAccounts,
		)
	case *autoscalingv2.HorizontalPodAutoscaler:
		return namespacedRegistration[*autoscalingv2.HorizontalPodAutoscalerList](
			schema.GroupVersionResource{Group: "autoscaling", Version: "v2", Resource: "horizontalpodautoscalers"},
			&autoscalingv2.HorizontalPodAutoscaler{}, client.Kube().AutoscalingV2().HorizontalPodAutoscalers,
		)
	case *policyv1.PodDisruptionBudget:
		return namespacedRegistration[*policyv1.PodDisruptionBudgetList](
			schema.GroupVersionResource{Group: "policy", Version: "v1", Resource: "poddisruptionbudgets"},
			&policyv1.PodDisruptionBudget{}, client.Kube().PolicyV1().PodDisruptionBudgets,
		)
	case *corev1.Namespace:
		return clusterRegistration[*corev1.NamespaceList](
			schema.GroupVersionResource{Group: "", Version: "v1", Resource: "namespaces"},
			&corev1.Namespace{}, client.Kube().CoreV1().Namespaces(),
		)
	case *corev1.Node:
		return clusterRegistration[*corev1.NodeList](
			schema.GroupVersionResource{Group: "", Version: "v1", Resource: "nodes"},
			&corev1.Node{}, client.Kube().CoreV1().Nodes(),
		)
	case *appsv1.Deployment:
		return namespacedRegistration[*appsv1.DeploymentList](
			schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"},
			&appsv1.Deployment{}, client.Kube().AppsV1().Deployments,
		)
	case *discoveryv1.EndpointSlice:
		return namespacedRegistration[*discoveryv1.EndpointSliceList](
			schema.GroupVersionResource{Group: discoveryv1.GroupName, Version: "v1", Resource: "endpointslices"},
			&discoveryv1.EndpointSlice{}, client.Kube().DiscoveryV1().EndpointSlices,
		)
	case *corev1.Secret:
		return namespacedRegistration[*corev1.SecretList](
			schema.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"},
			&corev1.Secret{}, client.Kube().CoreV1().Secrets,
		)
	case *corev1.ConfigMap:
		return namespacedRegistration[*corev1.ConfigMapList](
			schema.GroupVersionResource{Group: "", Version: "v1", Resource: "configmaps"},
			&corev1.ConfigMap{}, client.Kube().CoreV1().ConfigMaps,
		)
	case *gatewayv1.Gateway:
		return namespacedRegistration[*gatewayv1.GatewayList](
			schema.GroupVersionResource{Group: gatewayv1.GroupName, Version: "v1", Resource: "gateways"},
			&gatewayv1.Gateway{}, client.GatewayAPI().GatewayV1().Gateways,
		)
	case *gatewayv1.GatewayClass:
		return clusterRegistration[*gatewayv1.GatewayClassList](
			schema.GroupVersionResource{Group: gatewayv1.GroupName, Version: "v1", Resource: "gatewayclasses"},
			&gatewayv1.GatewayClass{}, client.GatewayAPI().GatewayV1().GatewayClasses(),
		)
	case *admissionregistrationv1.MutatingWebhookConfiguration:
		return clusterRegistration[*admissionregistrationv1.MutatingWebhookConfigurationList](
			schema.GroupVersionResource{Group: admissionregistrationv1.GroupName, Version: "v1", Resource: "mutatingwebhookconfigurations"},
			&admissionregistrationv1.MutatingWebhookConfiguration{}, client.Kube().AdmissionregistrationV1().MutatingWebhookConfigurations(),
		)
	case *admissionregistrationv1.ValidatingWebhookConfiguration:
		return clusterRegistration[*admissionregistrationv1.ValidatingWebhookConfigurationList](
			schema.GroupVersionResource{
				Group:    admissionregistrationv1.GroupName,
				Version:  "v1",
				Resource: "validatingwebhookconfigurations",
			},
			&admissionregistrationv1.ValidatingWebhookConfiguration{},
			client.Kube().AdmissionregistrationV1().ValidatingWebhookConfigurations(),
		)
	default:
		panic(fmt.Sprintf("no informer registration for %T", ptr.Empty[T]()))
	}
}

// listWatcher retains the generated client's concrete List result type.
type listWatcher[L runtime.Object] interface {
	List(context.Context, metav1.ListOptions) (L, error)
	Watch(context.Context, metav1.ListOptions) (watch.Interface, error)
}

func namespacedRegistration[L runtime.Object, C listWatcher[L]](resource schema.GroupVersionResource, object runtime.Object, clientForNamespace func(string) C) kube.InformerRegistration {
	return kube.InformerRegistration{
		Resource: resource,
		Object:   object,
		List: func(ctx context.Context, namespace string, options metav1.ListOptions) (runtime.Object, error) {
			return clientForNamespace(namespace).List(ctx, options)
		},
		Watch: func(ctx context.Context, namespace string, options metav1.ListOptions) (watch.Interface, error) {
			return clientForNamespace(namespace).Watch(ctx, options)
		},
	}
}

func clusterRegistration[L runtime.Object, C listWatcher[L]](resource schema.GroupVersionResource, object runtime.Object, client C) kube.InformerRegistration {
	return namespacedRegistration[L](resource, object, func(string) C { return client })
}
