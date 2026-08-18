// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// collection.go builds the krt collections that feed the store.
// SecurityProfile / GlobalSecurityProfile CRDs are compiled into
// securityprofile.Profile at the collection boundary. A source object that
// fails to compile becomes an identity-bearing item carrying CompileError
// rather than a nil, so the store can tell "this version is invalid" from
// "this profile was deleted" and keep serving the last known good one.

package profilestore

import (
	"context"
	"fmt"
	"maps"

	"istio.io/istio/extensions/epe/pkg/policy/securityprofile"

	"github.com/go-logr/logr"
	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	agentsclient "github.com/openkruise/agents-api/client/clientset/versioned"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pkg/config/schema/kubeclient"
	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/kube/kclient"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/kube/kubetypes"
)

var (
	securityProfileGVR = schema.GroupVersionResource{
		Group: "agents.kruise.io", Version: "v1alpha1", Resource: "securityprofiles",
	}
	securityProfileGVK = schema.GroupVersionKind{
		Group: "agents.kruise.io", Version: "v1alpha1", Kind: "SecurityProfile",
	}
	globalSecurityProfileGVR = schema.GroupVersionResource{
		Group: "agents.kruise.io", Version: "v1alpha1", Resource: "globalsecurityprofiles",
	}
	globalSecurityProfileGVK = schema.GroupVersionKind{
		Group: "agents.kruise.io", Version: "v1alpha1", Kind: "GlobalSecurityProfile",
	}
	sandboxGVR = schema.GroupVersionResource{
		Group: "agents.kruise.io", Version: "v1alpha1", Resource: "sandboxes",
	}
)

// RegisterTypes registers the agents-api SecurityProfile and
// GlobalSecurityProfile types with the kubeclient informer mechanism so that
// NewDelayedInformer can use typed List/Watch instead of unstructured. It
// must be called once before NewCollection, with the clientset the informers
// should use. Sandboxes need no registration: they are watched through the
// metadata client only.
func RegisterTypes(agentsCS agentsclient.Interface) {
	kubeclient.Register[*agentsv1alpha1.SecurityProfile](securityProfileGVR, securityProfileGVK,
		func(c kubeclient.ClientGetter, ns string, opts metav1.ListOptions) (runtime.Object, error) {
			return agentsCS.AgentsV1alpha1().SecurityProfiles(ns).List(context.Background(), opts)
		},
		func(c kubeclient.ClientGetter, ns string, opts metav1.ListOptions) (watch.Interface, error) {
			return agentsCS.AgentsV1alpha1().SecurityProfiles(ns).Watch(context.Background(), opts)
		},
		nil,
	)
	kubeclient.Register[*agentsv1alpha1.GlobalSecurityProfile](globalSecurityProfileGVR, globalSecurityProfileGVK,
		func(c kubeclient.ClientGetter, ns string, opts metav1.ListOptions) (runtime.Object, error) {
			return agentsCS.AgentsV1alpha1().GlobalSecurityProfiles().List(context.Background(), opts)
		},
		func(c kubeclient.ClientGetter, ns string, opts metav1.ListOptions) (watch.Interface, error) {
			return agentsCS.AgentsV1alpha1().GlobalSecurityProfiles().Watch(context.Background(), opts)
		},
		nil,
	)
}

// NewCollection watches SecurityProfile and GlobalSecurityProfile
// through krt collections built on the given client and returns the joined
// collection of compiled profiles. RegisterTypes must have been called first.
// debugger may be nil.
func NewCollection(client kube.Client, debugger *krt.DebugHandler, stop <-chan struct{}) krt.Collection[securityprofile.Profile] {
	opts := krt.NewOptionsBuilder(stop, "epe", debugger)
	log := ctrllog.Log.WithName("profile")

	configMapClient := kclient.NewFiltered[*corev1.ConfigMap](client,
		kclient.Filter{ObjectFilter: client.ObjectFilter()})
	configMaps := krt.WrapClient(configMapClient, opts.WithName("ConfigMaps")...)

	spInf := kclient.NewDelayedInformer[*agentsv1alpha1.SecurityProfile](client,
		securityProfileGVR, kubetypes.StandardInformer,
		kclient.Filter{ObjectFilter: client.ObjectFilter()})
	spInf.Start(stop)
	sps := krt.WrapClient(spInf, opts.WithName("SecurityProfiles")...)

	gspInf := kclient.NewDelayedInformer[*agentsv1alpha1.GlobalSecurityProfile](client,
		globalSecurityProfileGVR, kubetypes.StandardInformer,
		kclient.Filter{ObjectFilter: client.ObjectFilter()})
	gspInf.Start(stop)
	gsps := krt.WrapClient(gspInf, opts.WithName("GlobalSecurityProfiles")...)

	compiledSPs := krt.NewCollection(sps, func(ctx krt.HandlerContext, o *agentsv1alpha1.SecurityProfile) *securityprofile.Profile {
		sp, err := compileProfile(o, &o.Spec, ctx, configMaps)
		if err != nil {
			// Whether anything is still being served for this identity is the
			// store's knowledge, not this layer's; applyBatch logs that.
			log.Error(err, "profile failed to compile", "profile", o.Namespace+"/"+o.Name)
			return securityprofile.InvalidProfile(o, &o.Spec, err)
		}
		return sp
	}, opts.WithName("CompiledSecurityProfiles")...)

	compiledGSPs := krt.NewCollection(gsps, func(ctx krt.HandlerContext, o *agentsv1alpha1.GlobalSecurityProfile) *securityprofile.Profile {
		sp, err := compileProfile(o, &o.Spec, ctx, configMaps)
		if err != nil {
			log.Error(err, "global profile failed to compile", "profile", o.Name)
			return securityprofile.InvalidProfile(o, &o.Spec, err)
		}
		return sp
	}, opts.WithName("CompiledGlobalSecurityProfiles")...)

	// Debounce on the checked-mode join coalesces event bursts into one
	// batch per window (KRT_EVENT_DISTRIBUTE_DEBOUNCE[_MAX], default off),
	// so RegisterCollection's applyBatch rebuilds the snapshot once per
	// batch instead of once per profile change.
	return krt.JoinCollection([]krt.Collection[securityprofile.Profile]{compiledSPs, compiledGSPs, newInlineCollection(client, opts, log)},
		append(opts.WithName("CompiledProfiles"),
			krt.WithDebounce(features.KrtEventDistributeDebounce, features.KrtEventDistributeDebounceMax))...)
}

// newInlineCollection watches Sandbox metadata and compiles the objects
// carrying the agents.kruise.io/security-rules annotation into per-Sandbox
// inline rule profiles. The informer is metadata-only (PartialObjectMetadata):
// the compiler never reads spec or status, and a Sandbox carries a full pod
// template that would otherwise be transferred and cached for every Sandbox
// in the cluster. It is also delayed, like the profile informers: the Sandbox
// CRD may not exist in the cluster, and a non-delayed informer would retry
// the 404 list forever, never sync, and wedge startup behind
// WaitUntilSynced. Objects without the annotation emit nil and contribute no
// rules.
func newInlineCollection(client kube.Client, opts krt.OptionsBuilder, log logr.Logger) krt.Collection[securityprofile.Profile] {
	sandboxInf := kclient.NewDelayedInformer[*metav1.PartialObjectMetadata](client,
		sandboxGVR, kubetypes.MetadataInformer,
		kclient.Filter{ObjectFilter: client.ObjectFilter()})
	sandboxInf.Start(opts.Stop())
	sandboxes := krt.WrapClient(sandboxInf, opts.WithName("Sandboxes")...)

	return krt.NewCollection(sandboxes, func(_ krt.HandlerContext, o *metav1.PartialObjectMetadata) *securityprofile.Profile {
		if o.GetAnnotations()[securityprofile.AnnotationSecurityRules] == "" {
			return nil
		}
		p, err := securityprofile.NewInlineProfile(o)
		if err != nil {
			// The annotation is written by the Sandbox Manager, so a compile
			// failure indicates a schema disagreement; drop the rules rather
			// than guessing. Unlike CRD profiles there is no last-known-good:
			// the pod's own rules cannot be served from a prior version
			// once the pod moved on.
			log.Error(err, "inline security rules failed to compile", "sandbox", o.Namespace+"/"+o.Name)
			return nil
		}
		return p
	}, opts.WithName("CompiledInlineProfiles")...)
}

func compileProfile(
	obj metav1.Object,
	spec *agentsv1alpha1.SecurityProfileSpec,
	ctx krt.HandlerContext,
	configMaps krt.Collection[*corev1.ConfigMap],
) (*securityprofile.Profile, error) {
	sp, err := securityprofile.NewProfile(obj, spec)
	if err != nil {
		return nil, err
	}
	inputs, inputError := resolveInputs(ctx, configMaps, sp.Meta, spec.Inputs)
	if inputError != "" {
		return nil, fmt.Errorf("resolve inputs: %s", inputError)
	}
	sp.Inputs = inputs
	return sp, nil
}

func resolveInputs(
	ctx krt.HandlerContext,
	configMaps krt.Collection[*corev1.ConfigMap],
	meta securityprofile.Meta,
	declared []agentsv1alpha1.SecurityProfileInput,
) (map[string]any, string) {
	if len(declared) == 0 {
		return nil, ""
	}

	resolved := make(map[string]any, len(declared))
	for _, input := range declared {
		hasInline := input.Inline != nil
		hasConfigMap := input.ConfigMap != nil
		if hasInline == hasConfigMap {
			return nil, fmt.Sprintf("input %q must set exactly one source", input.Name)
		}
		if hasInline {
			resolved[input.Name] = maps.Clone(input.Inline)
			continue
		}

		namespace := input.ConfigMap.Namespace
		if namespace == "" {
			namespace = meta.Namespace
		}
		if namespace == "" {
			return nil, fmt.Sprintf("ConfigMap input %q requires an explicit namespace for a global profile", input.Name)
		}
		key := namespace + "/" + input.ConfigMap.Name
		if configMaps == nil || ctx == nil {
			return nil, fmt.Sprintf("load input %q from ConfigMap %s: ConfigMap collection is not configured", input.Name, key)
		}
		configMap := krt.FetchOne(ctx, configMaps, krt.FilterKey(key))
		if configMap == nil {
			return nil, fmt.Sprintf("load input %q from ConfigMap %s: not found", input.Name, key)
		}
		resolved[input.Name] = maps.Clone((*configMap).Data)
	}
	return resolved, ""
}
