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
	"cmp"
	"fmt"

	agents "github.com/openkruise/agents-api/agents/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/policy"
)

// ReferenceIssue describes a confirmed reference problem after static validation.
type ReferenceIssue struct {
	Field   string
	Reason  string
	Message string
}

// ReferenceSources holds the existing control-plane caches used by reference checks.
type ReferenceSources struct {
	AgentioConfig krt.Collection[model.AgentioConfiguration]
	ConfigMaps    krt.Collection[*corev1.ConfigMap]
	Secrets       krt.Collection[*corev1.Secret]
	Services      krt.Collection[*corev1.Service]
	RootNamespace string
	ScopedSecrets bool
}

// ReferenceChecker uses a cache snapshot when ctx is nil (admission). A KRT
// context also subscribes to changes, including a missing object's creation.
type ReferenceChecker struct {
	sources          ReferenceSources
	configMapsSynced krt.Collection[bool]
	secretsSynced    krt.Collection[bool]
	servicesSynced   krt.Collection[bool]
}

func NewReferenceChecker(sources ReferenceSources, stop <-chan struct{}) *ReferenceChecker {
	return &ReferenceChecker{
		sources:          sources,
		configMapsSynced: cacheSynced(sources.ConfigMaps, stop),
		secretsSynced:    cacheSynced(sources.Secrets, stop),
		servicesSynced:   cacheSynced(sources.Services, stop),
	}
}

// Publish the initial sync transition even when the watched cache is empty.
func cacheSynced(cache krt.Syncer, stop <-chan struct{}) krt.Collection[bool] {
	ready := cache.HasSynced()
	state := krt.NewStatic(&ready, true, krt.WithStop(stop))
	if !ready {
		go func() {
			if cache.WaitUntilSynced(stop) {
				synced := true
				state.Set(&synced)
			}
		}()
	}
	return state.AsCollection()
}

func checkCachedReference[T any](
	ctx krt.HandlerContext, cache krt.Collection[T], synced krt.Collection[bool],
	key string, missing ReferenceIssue,
) []ReferenceIssue {
	if !krt.FetchOrList(ctx, synced)[0] {
		return nil
	}
	if len(krt.FetchOrList(ctx, cache, krt.FilterKey(key))) == 0 {
		return []ReferenceIssue{missing}
	}
	return nil
}

// SecurityProfile checks provider, input and credential references.
func (v *ReferenceChecker) SecurityProfile(ctx krt.HandlerContext, p model.SecurityProfile) []ReferenceIssue {
	var issues []ReferenceIssue
	spec := field.NewPath("spec")
	for i, input := range p.Spec.Inputs {
		if input.ConfigMap == nil {
			continue
		}
		key := cmp.Or(input.ConfigMap.Namespace, p.Namespace) + "/" + input.ConfigMap.Name
		issues = append(issues, checkCachedReference(ctx, v.sources.ConfigMaps, v.configMapsSynced, key, ReferenceIssue{
			Field:   spec.Child("inputs").Index(i).Child("configMap").String(),
			Reason:  "ConfigMapNotFound",
			Message: fmt.Sprintf("Input %q: ConfigMap %s not found", input.Name, key),
		})...)
	}
	for i, rule := range p.Spec.Rules {
		actions := spec.Child("rules").Index(i).Child("actions")
		if callout := rule.Actions.HTTPCallout; callout != nil {
			path := actions.Child("httpCallout", "provider", "name").String()
			issues = append(issues, v.providerRef(ctx, path, rule.Name, callout.Provider.Name, false)...)
		}
		tt := rule.Actions.TokenTransformation
		if tt == nil || tt.Disabled {
			continue
		}
		refPath := actions.Child("tokenTransformation", "credentialRef")
		ref, err := policy.NormalizeCredentialRef(tt.CredentialRef)
		if err != nil {
			issues = append(issues, ReferenceIssue{Field: refPath.String(), Reason: "InvalidReference", Message: err.Error()})
			continue
		}
		if ref.CredentialProvider != nil {
			// The rule names a remote credential. The local connection comes
			// from the configured default, including for OAuth2.
			issues = append(issues, v.providerRef(ctx, refPath.String(), rule.Name, "", true)...)
			continue
		}
		namespace := cmp.Or(ref.Secret.Namespace, p.Namespace)
		if namespace == "" {
			// Global profiles may resolve this from the selected Pod.
			continue
		}
		key := namespace + "/" + ref.Secret.Name
		// Policy validation assumes EPE uses the same Secret access scope.
		if v.sources.ScopedSecrets && namespace != v.sources.RootNamespace {
			issues = append(issues, ReferenceIssue{
				Field:   refPath.String(),
				Reason:  "RefNotPermitted",
				Message: fmt.Sprintf("Rule %q: Secret %s is outside the permitted namespace %s", rule.Name, key, v.sources.RootNamespace),
			})
			continue
		}
		issues = append(issues, checkCachedReference(ctx, v.sources.Secrets, v.secretsSynced, key, ReferenceIssue{
			Field:   refPath.String(),
			Reason:  "SecretNotFound",
			Message: fmt.Sprintf("Rule %q: Secret %s not found", rule.Name, key),
		})...)
	}
	return issues
}

func (v *ReferenceChecker) providerRef(
	ctx krt.HandlerContext, path, rule, name string, credentials bool,
) []ReferenceIssue {
	configs := krt.FetchOrList(ctx, v.sources.AgentioConfig, krt.FilterKey("effective"))
	if len(configs) == 0 {
		return nil
	}
	cfg := configs[0].Value
	description, expectedType := "HTTP callout provider", "an HTTP callout provider"
	if credentials {
		description, expectedType = "default credential provider", "a credential provider"
		defaults := cfg.GetDefaultProviders()
		if defaults == nil {
			// EPE can supply the default credential provider from its environment.
			return nil
		}
		name = defaults.GetCredentialProvider()
		if name == "" {
			return []ReferenceIssue{{
				Field:   path,
				Reason:  "DefaultProviderDisabled",
				Message: fmt.Sprintf("Rule %q: the default credential provider is disabled", rule),
			}}
		}
	}
	for _, provider := range cfg.GetExtensionProviders() {
		if provider.GetName() != name {
			continue
		}
		if (credentials && provider.GetCredentialProvider() == nil) ||
			(!credentials && provider.GetHttpCallout() == nil) {
			return []ReferenceIssue{{
				Field:   path,
				Reason:  "ProviderTypeMismatch",
				Message: fmt.Sprintf("Rule %q: provider %q must be %s", rule, name, expectedType),
			}}
		}
		return nil
	}
	if credentials && name == configv1.EnvironmentCredentialProviderName {
		return nil
	}
	return []ReferenceIssue{{
		Field:   path,
		Reason:  "ProviderNotFound",
		Message: fmt.Sprintf("Rule %q: %s %q is missing", rule, description, name),
	}}
}

// TrafficPolicy checks references to named Services.
func (v *ReferenceChecker) TrafficPolicy(ctx krt.HandlerContext, p model.TrafficPolicy) []ReferenceIssue {
	var issues []ReferenceIssue
	namespace := p.Namespace
	if p.Global {
		namespace = v.sources.RootNamespace
	}
	for _, direction := range []struct {
		name  string
		rules *agents.TrafficPolicyDirection
	}{{"ingress", p.Spec.Ingress}, {"egress", p.Spec.Egress}} {
		if direction.rules == nil {
			continue
		}
		for i, rule := range direction.rules.Rules {
			peers, member := rule.To, "to"
			if direction.name == "ingress" {
				peers, member = rule.From, "from"
			}
			for j, peer := range peers {
				// CIDR wins over the other peer fields, matching the compiler.
				if peer.CIDR != "" || peer.Service == nil || peer.Service.Name == "" || peer.Service.Name == "*" {
					continue
				}
				path := field.NewPath("spec", direction.name, "rules").Index(i).Child(member).Index(j).String()
				key := cmp.Or(peer.Service.Namespace, namespace) + "/" + peer.Service.Name
				issues = append(issues, checkCachedReference(ctx, v.sources.Services, v.servicesSynced, key, ReferenceIssue{
					Field:   path + ".service.name",
					Reason:  "ServiceNotFound",
					Message: fmt.Sprintf("%s: Service %s not found", path, key),
				})...)
			}
		}
	}
	return issues
}
