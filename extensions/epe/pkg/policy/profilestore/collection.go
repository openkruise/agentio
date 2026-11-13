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
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
	"github.com/openkruise/agentio/pkg/features"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/kube/kclient"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/registry"
	"github.com/openkruise/agentio/pkg/registry/kubernetes/kruise"

	"github.com/go-logr/logr"
	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
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
// surfacing during rule evaluation on the first matching request. The request path reads
// that projection; it never builds one. Per-Sandbox profiles are projected
// here too, under the same failure semantics — see newSandboxCollection.
func NewCollection(
	client kube.Client,
	regs []filter.Registration,
	debugger *krt.DebugHandler,
	stop <-chan struct{},
) *Collection {
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

	compiledSPs := krt.NewCollection(
		sps,
		func(_ krt.HandlerContext, o *agentsv1alpha1.SecurityProfile) *securityprofile.Profile {
			sp, err := compileProfile(o, &o.Spec, regs)
			if err != nil {
				// Whether anything is still being served for this identity is the
				// store's knowledge, not this layer's; applyBatch logs that.
				log.Error(err, "profile failed to compile", "profile", o.Namespace+"/"+o.Name)
				return securityprofile.InvalidProfile(o, &o.Spec, err)
			}
			return sp
		},
		opts.WithName("CompiledSecurityProfiles")...)

	compiledGSPs := krt.NewCollection(
		gsps,
		func(_ krt.HandlerContext, o *agentsv1alpha1.GlobalSecurityProfile) *securityprofile.Profile {
			sp, err := compileProfile(o, &o.Spec, regs)
			if err != nil {
				log.Error(err, "global profile failed to compile", "profile", o.Name)
				return securityprofile.InvalidProfile(o, &o.Spec, err)
			}
			return sp
		},
		opts.WithName("CompiledGlobalSecurityProfiles")...)

	profiles := &Collection{
		Source: registry.Source[securityprofile.Profile]{Registry: registry.NewSourceRegistry()},
	}
	collections := []krt.Collection[securityprofile.Profile]{compiledSPs, compiledGSPs}
	if features.SandboxMode {
		profiles = newSandboxCollection(client, regs, opts, log)
		collections = append(collections, profiles.Collection)
	}

	// Debounce derived informer events so the store copies its snapshot once per batch.
	prepared := krt.JoinCollection(collections, opts.WithName("PreparedProfiles")...)
	profiles.Collection = inputCollection(prepared, configMaps,
		append(opts.WithName("CompiledProfiles"),
			krt.WithDebounce(features.KRTDebounceAfter, features.KRTDebounceMax))...)
	return profiles
}

// Collection keeps source discovery beside its asynchronous policy projection.
type Collection struct {
	registry.Source[securityprofile.Profile]
	sandbox func(context.Context, subject.Subject) (sandboxSource, bool, error)
}

// register couples derived publications and source invalidations for the store's lifetime.
func (c *Collection) register(
	publish func([]krt.Event[securityprofile.Profile]),
	notify func([]model.ResourceKey),
) krt.HandlerRegistration {
	unregisterDeletes := c.Registry.RegisterDeletes(notify)
	return profileRegistration{
		HandlerRegistration: c.RegisterBatch(publish, true),
		unregisterDeletes:   unregisterDeletes,
	}
}

type profileRegistration struct {
	krt.HandlerRegistration
	unregisterDeletes func()
}

func (r profileRegistration) UnregisterHandler() {
	r.unregisterDeletes()
	r.HandlerRegistration.UnregisterHandler()
}

// sandboxSource keeps the policy's native key separate from its host Workload.
type sandboxSource struct {
	name     types.NamespacedName
	identity model.SourceIdentity
}

func sandboxProfileKey(namespace, name string) model.ResourceKey {
	return model.ResourceKey{
		TypeURL: model.SecurityProfileType,
		Name:    securityprofile.MatchSandbox.String() + "/" + namespace + "/" + name,
	}
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

func sandboxRegistration(client kube.Client) kube.InformerRegistration {
	resource := client.Metadata().Resource(sandboxGVR)
	return kube.InformerRegistration{
		Resource: sandboxGVR,
		Object:   &metav1.PartialObjectMetadata{},
		List: func(ctx context.Context, namespace string, options metav1.ListOptions) (runtime.Object, error) {
			return resource.Namespace(namespace).List(ctx, options)
		},
		Watch: func(ctx context.Context, namespace string, options metav1.ListOptions) (watch.Interface, error) {
			return resource.Namespace(namespace).Watch(ctx, options)
		},
	}
}

// newSandboxCollection watches Sandbox metadata and compiles the objects
// carrying the agents.kruise.io/security-rules annotation into per-Sandbox
// rule profiles. The informer is metadata-only (PartialObjectMetadata):
// the compiler never reads spec or status, and a Sandbox carries a full pod
// template that would otherwise be transferred and cached for every Sandbox
// in the cluster. It is also delayed, like the profile informers: the Sandbox
// CRD may not exist in the cluster, and a non-delayed informer would retry
// the 404 list forever, never sync, and wedge startup behind
// WaitUntilSynced. Objects without the annotation emit nil and contribute no
// rules.
//
// Rule payloads are projected against regs here as they are for CRD profiles,
// so the request path compiles nothing. Failure semantics are also the CRD
// profile's: a version that fails to compile or project becomes an
// identity-bearing invalid item, so the store keeps serving the last known
// good version of that Sandbox UID's rules when one exists and installs nothing
// otherwise. Requests wait for a usable first version, failing closed when
// their request budget expires. An empty annotation remains a legitimate removal.
// After initial sync, lookups use only the watched snapshot; an unknown explicit
// Sandbox identity fails closed without reading the Kubernetes API.
func newSandboxCollection(
	client kube.Client,
	regs []filter.Registration,
	opts krt.OptionsBuilder,
	log logr.Logger,
) *Collection {
	sandboxInf := kclient.NewDelayedInformerFor[*metav1.PartialObjectMetadata](client,
		sandboxRegistration(client), kclient.Filter{})
	sandboxInf.Start(opts.Stop())
	sandboxes := krt.WrapClient(sandboxInf, opts.WithName("Sandboxes")...)
	byUID := krt.NewIndex(sandboxes, "sandbox-profile-uids", func(o *metav1.PartialObjectMetadata) []string {
		uid, found := kruise.SandboxUID(o)
		if !found {
			return nil
		}
		return []string{uid}
	})
	sources := registry.TrackSources(sandboxes, "sandbox-profile-sources",
		func(o *metav1.PartialObjectMetadata) []model.ResourceKey {
			if !kruise.HasSecurityRules(o) {
				return nil
			}
			return []model.ResourceKey{sandboxProfileKey(o.Namespace, o.Name)}
		},
		func(o *metav1.PartialObjectMetadata) model.SourceIdentity {
			return model.SourceIdentity{UID: string(o.UID)}
		})

	compiled := krt.NewCollection(
		sandboxes,
		func(_ krt.HandlerContext, o *metav1.PartialObjectMetadata) *securityprofile.Profile {
			if !kruise.HasSecurityRules(o) {
				return nil
			}
			p, err := securityprofile.NewSandboxProfile(o)
			if err == nil {
				err = p.Project(regs)
			}
			if err != nil {
				// Whether an older version is still being served is the store's
				// knowledge; applyBatch logs and meters that.
				log.Error(err, "sandbox security rules failed to compile", "sandbox", o.Namespace+"/"+o.Name)
				return securityprofile.InvalidSandboxProfile(o, err)
			}
			return p
		},
		opts.WithName("CompiledSandboxProfiles")...)
	return &Collection{
		Source: registry.Source[securityprofile.Profile]{Collection: compiled, Registry: sources},
		sandbox: func(_ context.Context, subject subject.Subject) (sandboxSource, bool, error) {
			var obj *metav1.PartialObjectMetadata
			if subject.Sandbox != nil {
				matches := byUID.Lookup(subject.Sandbox.UID)
				if len(matches) != 1 {
					return sandboxSource{}, false, fmt.Errorf(
						"sandbox %q has %d matching sources",
						subject.Sandbox.UID,
						len(matches),
					)
				}
				obj = matches[0]
				if obj.Namespace != subject.Workload.Namespace {
					return sandboxSource{}, false, fmt.Errorf(
						"sandbox %q is outside workload namespace %q",
						subject.Sandbox.UID,
						subject.Workload.Namespace,
					)
				}
			} else {
				cached := sandboxes.GetKey(subject.Workload.Namespace + "/" + subject.Workload.Name)
				if cached == nil {
					return sandboxSource{}, false, nil
				}
				obj = *cached
			}
			return sandboxSource{
				name:     types.NamespacedName{Namespace: obj.Namespace, Name: obj.Name},
				identity: model.SourceIdentity{UID: string(obj.UID)},
			}, kruise.HasSecurityRules(obj), nil
		},
	}
}

func compileProfile(
	obj metav1.Object,
	spec *agentsv1alpha1.SecurityProfileSpec,
	regs []filter.Registration,
) (*securityprofile.Profile, error) {
	sp, err := securityprofile.NewProfile(obj, spec)
	if err != nil {
		return nil, err
	}
	if err := sp.Project(regs); err != nil {
		return nil, err
	}

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
	if err := securityprofile.ValidateInputs(meta.Namespace, declared); err != nil {
		return nil, "", err
	}
	if len(declared) == 0 {
		return nil, "", nil
	}

	resolved := make(map[string]any, len(declared))
	var missing []string
	for _, input := range declared {
		if input.Inline != nil {
			resolved[input.Name] = maps.Clone(input.Inline)
			continue
		}

		namespace := input.ConfigMap.Namespace
		if namespace == "" {
			namespace = meta.Namespace
		}
		key := namespace + "/" + input.ConfigMap.Name
		if configMaps == nil {
			return nil, "", fmt.Errorf(
				"load input %q from ConfigMap %s: ConfigMap collection is not configured",
				input.Name,
				key,
			)
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
