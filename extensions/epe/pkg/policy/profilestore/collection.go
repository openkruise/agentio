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
//
// An absent ConfigMap-backed input is not a compile failure: the profile
// installs with InputsError set, its rules enforce, and only evaluations that
// read inputs fail through the consuming action's failure policy.

package profilestore

import (
	"context"
	"fmt"
	"maps"
	"strings"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"
	"github.com/openkruise/agentio/pkg/features"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/kube/kclient"

	"github.com/go-logr/logr"
	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	securityProfileGVR = schema.GroupVersionResource{
		Group:    "agents.kruise.io",
		Version:  "v1alpha1",
		Resource: "securityprofiles",
	}
	globalSecurityProfileGVR = schema.GroupVersionResource{
		Group:    "agents.kruise.io",
		Version:  "v1alpha1",
		Resource: "globalsecurityprofiles",
	}
	sandboxGVR = schema.GroupVersionResource{
		Group:    "agents.kruise.io",
		Version:  "v1alpha1",
		Resource: "sandboxes",
	}
)

// NewCollection watches SecurityProfile and GlobalSecurityProfile
// through krt collections built on the given client and returns the joined
// collection of compiled profiles. debugger may be nil.
//
// regs is the filter registration set requests are evaluated against. Every
// candidate version's rule payloads are projected against it at this
// boundary, so a static authoring error — an uncompilable credential
// parameter CEL expression, a malformed action document — rejects the version
// here and the store keeps serving the last known good one, instead of
// surfacing on the first matching request where the ext_proc provider's
// global failureModeAllow would decide the outcome. The request path reads
// that projection; it never builds one. Per-Sandbox profiles are projected
// here too, under the same failure semantics — see newSandboxCollection.
func NewCollection(client kube.Client, regs []filter.Registration, debugger *krt.DebugHandler, stop <-chan struct{}) krt.Collection[securityprofile.Profile] {
	opts := krt.NewOptionsBuilder(stop, "epe", debugger)
	log := ctrllog.Log.WithName("profile")

	configMapClient := kclient.NewFiltered[*corev1.ConfigMap](client, kclient.Filter{})
	configMapClient.Start(stop)
	configMaps := krt.WrapClient(configMapClient, opts.WithName("ConfigMaps")...)

	spInf := kclient.NewDelayedInformerFor[*agentsv1alpha1.SecurityProfile](client,
		securityProfileRegistration(client), kclient.Filter{})
	spInf.Start(stop)
	sps := krt.WrapClient(spInf, opts.WithName("SecurityProfiles")...)

	gspInf := kclient.NewDelayedInformerFor[*agentsv1alpha1.GlobalSecurityProfile](client,
		globalSecurityProfileRegistration(client), kclient.Filter{})
	gspInf.Start(stop)
	gsps := krt.WrapClient(gspInf, opts.WithName("GlobalSecurityProfiles")...)

	compiledSPs := krt.NewCollection(sps, func(ctx krt.HandlerContext, o *agentsv1alpha1.SecurityProfile) *securityprofile.Profile {
		sp, err := compileProfile(o, &o.Spec, regs, ctx, configMaps)
		if err != nil {
			// Whether anything is still being served for this identity is the
			// store's knowledge, not this layer's; applyBatch logs that.
			log.Error(err, "profile failed to compile", "profile", o.Namespace+"/"+o.Name)
			return securityprofile.InvalidProfile(o, &o.Spec, err)
		}
		return sp
	}, opts.WithName("CompiledSecurityProfiles")...)

	compiledGSPs := krt.NewCollection(gsps, func(ctx krt.HandlerContext, o *agentsv1alpha1.GlobalSecurityProfile) *securityprofile.Profile {
		sp, err := compileProfile(o, &o.Spec, regs, ctx, configMaps)
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
	return krt.JoinCollection([]krt.Collection[securityprofile.Profile]{compiledSPs, compiledGSPs, newSandboxCollection(client, regs, opts, log)},
		append(opts.WithName("CompiledProfiles"),
			krt.WithDebounce(features.KRTDebounceAfter, features.KRTDebounceMax))...)
}

func securityProfileRegistration(client kube.Client) kube.InformerRegistration {
	return kube.InformerRegistration{
		Resource: securityProfileGVR,
		Object:   &agentsv1alpha1.SecurityProfile{},
		List: func(ctx context.Context, namespace string, options metav1.ListOptions) (runtime.Object, error) {
			return client.AgentsAPI().AgentsV1alpha1().SecurityProfiles(namespace).List(ctx, options)
		},
		Watch: func(ctx context.Context, namespace string, options metav1.ListOptions) (watch.Interface, error) {
			return client.AgentsAPI().AgentsV1alpha1().SecurityProfiles(namespace).Watch(ctx, options)
		},
	}
}

func globalSecurityProfileRegistration(client kube.Client) kube.InformerRegistration {
	return kube.InformerRegistration{
		Resource: globalSecurityProfileGVR,
		Object:   &agentsv1alpha1.GlobalSecurityProfile{},
		List: func(ctx context.Context, _ string, options metav1.ListOptions) (runtime.Object, error) {
			return client.AgentsAPI().AgentsV1alpha1().GlobalSecurityProfiles().List(ctx, options)
		},
		Watch: func(ctx context.Context, _ string, options metav1.ListOptions) (watch.Interface, error) {
			return client.AgentsAPI().AgentsV1alpha1().GlobalSecurityProfiles().Watch(ctx, options)
		},
	}
}

// newSandboxCollection watches Sandbox metadata and publishes one state-bearing
// item per Sandbox. The informer is metadata-only (PartialObjectMetadata): the
// compiler never reads spec or status, and a Sandbox carries a full pod template
// that would otherwise be transferred and cached for every Sandbox in the
// cluster. It is also delayed, like the profile informers: the Sandbox CRD may
// not exist in the cluster, and a non-delayed informer would retry the 404 list
// forever, never sync, and wedge startup behind WaitUntilSynced.
//
// Claimed Sandboxes publish Ready, ReadyEmpty, or Invalid after compiling and
// projecting rule payloads. Unclaimed Sandboxes publish Unknown. This keeps
// readiness and the effective rule chain in one immutable store snapshot, while
// ensuring the request path compiles nothing.
func newSandboxCollection(client kube.Client, regs []filter.Registration, opts krt.OptionsBuilder, log logr.Logger) krt.Collection[securityprofile.Profile] {
	sandboxResource := client.Metadata().Resource(sandboxGVR)
	sandboxInf := kclient.NewDelayedInformerFor[*metav1.PartialObjectMetadata](client,
		kube.InformerRegistration{
			Resource: sandboxGVR,
			Object:   &metav1.PartialObjectMetadata{},
			List: func(ctx context.Context, namespace string, options metav1.ListOptions) (runtime.Object, error) {
				return sandboxResource.Namespace(namespace).List(ctx, options)
			},
			Watch: func(ctx context.Context, namespace string, options metav1.ListOptions) (watch.Interface, error) {
				return sandboxResource.Namespace(namespace).Watch(ctx, options)
			},
		}, kclient.Filter{})
	sandboxInf.Start(opts.Stop())
	sandboxes := krt.WrapClient(sandboxInf, opts.WithName("Sandboxes")...)

	return krt.NewCollection(sandboxes, func(_ krt.HandlerContext, o *metav1.PartialObjectMetadata) *securityprofile.Profile {
		p := compileSandboxProfile(o, regs)
		if p.CompileError != "" {
			log.Error(nil, "sandbox security rules failed to compile", "sandbox", o.Namespace+"/"+o.Name, "error", p.CompileError)
		}
		return p
	}, opts.WithName("CompiledSandboxProfiles")...)
}

func compileSandboxProfile(o *metav1.PartialObjectMetadata, regs []filter.Registration) *securityprofile.Profile {
	if o.GetLabels()[agentsv1alpha1.LabelSandboxIsClaimed] != agentsv1alpha1.True {
		return securityprofile.NewSandboxStateProfile(o, securityprofile.SandboxPolicyUnknown)
	}
	if o.GetAnnotations()[securityprofile.AnnotationSecurityRules] == "" {
		return securityprofile.NewSandboxStateProfile(o, securityprofile.SandboxPolicyReadyEmpty)
	}
	p, err := securityprofile.NewSandboxProfile(o)
	if err == nil {
		err = p.Project(regs)
	}
	if err != nil {
		return securityprofile.InvalidSandboxProfile(o, err)
	}
	return p
}

func compileProfile(
	obj metav1.Object,
	spec *agentsv1alpha1.SecurityProfileSpec,
	regs []filter.Registration,
	ctx krt.HandlerContext,
	configMaps krt.Collection[*corev1.ConfigMap],
) (*securityprofile.Profile, error) {
	sp, err := securityprofile.NewProfile(obj, spec)
	if err != nil {
		return nil, err
	}
	if err := sp.Project(regs); err != nil {
		return nil, err
	}
	// Static input authoring errors reject the version like any other compile
	// error. A ConfigMap that is merely absent must not: the profile's rules
	// install and enforce, only inputs-dependent evaluations fail — otherwise
	// a missing ConfigMap on first create would leave the pods this profile
	// selects with none of its Block rules in effect.
	inputs, unavailable, err := resolveInputs(ctx, configMaps, sp.Meta, spec.Inputs)
	if err != nil {
		return nil, fmt.Errorf("resolve inputs: %w", err)
	}
	sp.Inputs = inputs
	sp.InputsError = unavailable
	return sp, nil
}

// resolveInputs resolves every declared input. It returns the resolved
// values, a non-empty unavailable message when one or more ConfigMap-backed
// inputs do not (or no longer) exist, and an error for static authoring
// mistakes that no cluster state can heal.
//
// Every ConfigMap is fetched even after a miss, so the krt dependency on each
// referenced ConfigMap registers and a later create/update/delete of any of
// them recompiles the profile.
func resolveInputs(
	ctx krt.HandlerContext,
	configMaps krt.Collection[*corev1.ConfigMap],
	meta securityprofile.Meta,
	declared []agentsv1alpha1.SecurityProfileInput,
) (map[string]any, string, error) {
	if len(declared) == 0 {
		return nil, "", nil
	}

	resolved := make(map[string]any, len(declared))
	var missing []string
	for _, input := range declared {
		hasInline := input.Inline != nil
		hasConfigMap := input.ConfigMap != nil
		if hasInline == hasConfigMap {
			return nil, "", fmt.Errorf("input %q must set exactly one source", input.Name)
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
			return nil, "", fmt.Errorf("ConfigMap input %q requires an explicit namespace for a global profile", input.Name)
		}
		key := namespace + "/" + input.ConfigMap.Name
		if configMaps == nil || ctx == nil {
			return nil, "", fmt.Errorf("load input %q from ConfigMap %s: ConfigMap collection is not configured", input.Name, key)
		}
		configMap := krt.FetchOne(ctx, configMaps, krt.FilterKey(key))
		if configMap == nil {
			missing = append(missing, fmt.Sprintf("input %q from ConfigMap %s: not found", input.Name, key))
			continue
		}
		resolved[input.Name] = maps.Clone((*configMap).Data)
	}
	if len(missing) > 0 {
		// The partial values are discarded on purpose: serving a mixed bag
		// where some inputs are live and some silently absent is exactly the
		// ambiguity the unavailable marker exists to prevent.
		return nil, strings.Join(missing, "; "), nil
	}
	return resolved, "", nil
}
