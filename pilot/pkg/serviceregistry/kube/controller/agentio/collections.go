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

package agentio

import (
	"context"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	agentsclient "github.com/openkruise/agents-api/client/clientset/versioned"
	corev1 "k8s.io/api/core/v1"

	kubesecrets "istio.io/istio/pilot/pkg/credentials/kube"
	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pkg/config/schema/kubeclient"
	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/kube/kclient"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/kube/kubetypes"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
)

// registerTypes registers the agents-api TrafficPolicy and
// GlobalTrafficPolicy types with the kubeclient informer mechanism so that
// NewDelayedInformer can use typed List/Watch instead of unstructured.
func registerTypes(agentsCS agentsclient.Interface) {
	tpGVR := schema.GroupVersionResource{Group: "agents.kruise.io", Version: "v1alpha1", Resource: "trafficpolicies"}
	tpGVK := schema.GroupVersionKind{Group: "agents.kruise.io", Version: "v1alpha1", Kind: "TrafficPolicy"}
	kubeclient.Register[*agentsv1alpha1.TrafficPolicy](tpGVR, tpGVK,
		func(c kubeclient.ClientGetter, ns string, opts metav1.ListOptions) (runtime.Object, error) {
			return agentsCS.AgentsV1alpha1().TrafficPolicies(ns).List(context.Background(), opts)
		},
		func(c kubeclient.ClientGetter, ns string, opts metav1.ListOptions) (watch.Interface, error) {
			return agentsCS.AgentsV1alpha1().TrafficPolicies(ns).Watch(context.Background(), opts)
		},
		nil,
	)

	gtpGVR := schema.GroupVersionResource{Group: "agents.kruise.io", Version: "v1alpha1", Resource: "globaltrafficpolicies"}
	gtpGVK := schema.GroupVersionKind{Group: "agents.kruise.io", Version: "v1alpha1", Kind: "GlobalTrafficPolicy"}
	kubeclient.Register[*agentsv1alpha1.GlobalTrafficPolicy](gtpGVR, gtpGVK,
		func(c kubeclient.ClientGetter, ns string, opts metav1.ListOptions) (runtime.Object, error) {
			return agentsCS.AgentsV1alpha1().GlobalTrafficPolicies().List(context.Background(), opts)
		},
		func(c kubeclient.ClientGetter, ns string, opts metav1.ListOptions) (watch.Interface, error) {
			return agentsCS.AgentsV1alpha1().GlobalTrafficPolicies().Watch(context.Background(), opts)
		},
		nil,
	)

	registerSecurityProfileType(agentsCS)
}

var securityProfileGVR = schema.GroupVersionResource{
	Group: "agents.kruise.io", Version: "v1alpha1", Resource: "securityprofiles",
}

var securityProfileGVK = schema.GroupVersionKind{
	Group: "agents.kruise.io", Version: "v1alpha1", Kind: "SecurityProfile",
}

// registerSecurityProfileType registers SecurityProfile with the kubeclient
// informer mechanism. Unlike the TrafficPolicy registrations above it also
// supplies a write function: kclient derives its Patcher from that function,
// and the status controller needs the Patcher to server-side-apply status.
func registerSecurityProfileType(agentsCS agentsclient.Interface) {
	kubeclient.Register[*agentsv1alpha1.SecurityProfile](securityProfileGVR, securityProfileGVK,
		func(c kubeclient.ClientGetter, ns string, opts metav1.ListOptions) (runtime.Object, error) {
			return agentsCS.AgentsV1alpha1().SecurityProfiles(ns).List(context.Background(), opts)
		},
		func(c kubeclient.ClientGetter, ns string, opts metav1.ListOptions) (watch.Interface, error) {
			return agentsCS.AgentsV1alpha1().SecurityProfiles(ns).Watch(context.Background(), opts)
		},
		func(c kubeclient.ClientGetter, ns string) kubetypes.WriteAPI[*agentsv1alpha1.SecurityProfile] {
			return agentsCS.AgentsV1alpha1().SecurityProfiles(ns)
		},
	)
}

func newSecurityProfilesCollection(
	client kube.Client,
	stop <-chan struct{},
	opts krt.OptionsBuilder,
) krt.Collection[*agentsv1alpha1.SecurityProfile] {
	inf := kclient.NewDelayedInformer[*agentsv1alpha1.SecurityProfile](client,
		securityProfileGVR,
		kubetypes.StandardInformer, kclient.Filter{ObjectFilter: client.ObjectFilter()})
	inf.Start(stop)
	return krt.WrapClient(inf, opts.WithName("SecurityProfiles")...)
}

// newSecretsCollection mirrors the Gateway API controller's secret informer
// (pilot/pkg/config/kube/gateway/controller.go:189-195): the field selector
// excludes the two largest secret types in a typical cluster, and an empty
// RestrictedSecretsScope means watch every namespace.
func newSecretsCollection(client kube.Client, opts krt.OptionsBuilder) krt.Collection[*corev1.Secret] {
	return krt.WrapClient(
		kclient.NewFiltered[*corev1.Secret](client, kubetypes.Filter{
			FieldSelector: kubesecrets.SecretsFieldSelector,
			ObjectFilter:  client.ObjectFilter(),
			Namespace:     features.RestrictedSecretsScope,
		}),
		opts.WithName("SecurityProfileSecrets")...,
	)
}

func newTrafficPoliciesCollection(client kube.Client, stop <-chan struct{}, opts krt.OptionsBuilder) krt.Collection[*agentsv1alpha1.TrafficPolicy] {
	inf := kclient.NewDelayedInformer[*agentsv1alpha1.TrafficPolicy](client,
		schema.GroupVersionResource{Group: "agents.kruise.io", Version: "v1alpha1", Resource: "trafficpolicies"},
		kubetypes.StandardInformer, kclient.Filter{ObjectFilter: client.ObjectFilter()})
	inf.Start(stop)
	return krt.WrapClient(inf, opts.WithName("TrafficPolicies")...)
}

func newGlobalTrafficPoliciesCollection(client kube.Client, stop <-chan struct{}, opts krt.OptionsBuilder) krt.Collection[*agentsv1alpha1.GlobalTrafficPolicy] {
	inf := kclient.NewDelayedInformer[*agentsv1alpha1.GlobalTrafficPolicy](client,
		schema.GroupVersionResource{Group: "agents.kruise.io", Version: "v1alpha1", Resource: "globaltrafficpolicies"},
		kubetypes.StandardInformer, kclient.Filter{ObjectFilter: client.ObjectFilter()})
	inf.Start(stop)
	return krt.WrapClient(inf, opts.WithName("GlobalTrafficPolicies")...)
}
