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

package policystatus

import (
	"cmp"
	"fmt"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"
	"github.com/openkruise/agentio/pkg/krt"
)

// Keep the first definite failure ahead of an unknown; still inspect every
// reference so KRT tracks recovery of all dependencies.
func referenceProblem(c *metav1.Condition, status metav1.ConditionStatus, reason, message string) {
	if c.Status == metav1.ConditionTrue || (c.Status == metav1.ConditionUnknown && status == metav1.ConditionFalse) {
		c.Status, c.Reason, c.Message = status, reason, message
	}
}

func (c *Controller) profileRefs(ctx krt.HandlerContext, s source) metav1.Condition {
	resolved := condition("ResolvedRefs", metav1.ConditionTrue, "ResolvedRefs",
		"All configuration references were found in the control-plane cache", s.Metadata.Generation)
	for _, input := range s.Profile.Inputs {
		if input.ConfigMap == nil {
			continue
		}
		if !*krt.FetchOne(ctx, c.configMapsSynced.AsCollection()) {
			referenceProblem(
				&resolved,
				metav1.ConditionUnknown,
				"CacheNotSynced",
				"ConfigMap cache has not synchronized",
			)
			continue
		}
		key := cmp.Or(input.ConfigMap.Namespace, s.Metadata.Namespace) + "/" + input.ConfigMap.Name
		if krt.FetchOne(ctx, c.registry.ConfigMaps, krt.FilterKey(key)) == nil {
			referenceProblem(&resolved, metav1.ConditionFalse, "ConfigMapNotFound",
				fmt.Sprintf("input %q: ConfigMap %s not found", input.Name, key))
		}
	}
	for _, rule := range s.Profile.Rules {
		if rule.Actions.HTTPCallout != nil {
			referenceProblem(&resolved, metav1.ConditionUnknown, "RuntimeResolutionRequired",
				fmt.Sprintf("rule %q: HTTP callout provider is resolved by EPE", rule.Name))
		}
		tt := rule.Actions.TokenTransformation
		if tt == nil || tt.Disabled {
			continue
		}
		ref, err := securityprofile.NormalizeCredentialRef(tt.CredentialRef)
		if err != nil {
			referenceProblem(&resolved, metav1.ConditionFalse, "InvalidReference", err.Error())
			continue
		}
		if ref.CredentialProvider != nil {
			referenceProblem(&resolved, metav1.ConditionUnknown, "RuntimeResolutionRequired",
				fmt.Sprintf("rule %q: credential provider is resolved by EPE", rule.Name))
			continue
		}
		c.secretRef(ctx, s, rule.Name, *ref.Secret, &resolved)
	}
	return resolved
}

func (c *Controller) secretRef(ctx krt.HandlerContext, s source, rule string,
	ref agentsv1alpha1.SecretCredentialRef, resolved *metav1.Condition,
) {
	namespace := cmp.Or(ref.Namespace, s.Metadata.Namespace)
	if namespace == "" {
		referenceProblem(resolved, metav1.ConditionUnknown, "RuntimeResolutionRequired",
			fmt.Sprintf("rule %q: Secret namespace depends on the requesting Pod", rule))
		return
	}
	if c.scopedSecrets && namespace != c.namespace {
		referenceProblem(resolved, metav1.ConditionUnknown, "OutsideWatchScope",
			fmt.Sprintf("rule %q: Secret %s/%s is outside the control-plane Secret watch scope",
				rule, namespace, ref.Name))
		return
	}
	if !*krt.FetchOne(ctx, c.secretsSynced.AsCollection()) {
		referenceProblem(resolved, metav1.ConditionUnknown, "CacheNotSynced", "Secret cache has not synchronized")
		return
	}
	key := namespace + "/" + ref.Name
	if krt.FetchOne(ctx, c.registry.Secrets, krt.FilterKey(key)) == nil {
		referenceProblem(resolved, metav1.ConditionFalse, "SecretNotFound",
			fmt.Sprintf("rule %q: Secret %s not found", rule, key))
	}
}

func (c *Controller) trafficRefs(ctx krt.HandlerContext, s source) metav1.Condition {
	resolved := condition("ResolvedRefs", metav1.ConditionTrue, "ResolvedRefs",
		"All named peer references resolved; empty selector matches are valid", s.Metadata.Generation)
	namespace := s.Metadata.Namespace
	if s.Kind == "GlobalTrafficPolicy" {
		namespace = c.namespace
	}
	for _, direction := range []struct {
		name  string
		rules *agentsv1alpha1.TrafficPolicyDirection
	}{{"ingress", s.Traffic.Ingress}, {"egress", s.Traffic.Egress}} {
		if direction.rules == nil {
			continue
		}
		for i, rule := range direction.rules.Rules {
			peers, field := rule.To, "to"
			if direction.name == "ingress" {
				peers, field = rule.From, "from"
			}
			for j, peer := range peers {
				path := fmt.Sprintf("spec.%s.rules[%d].%s[%d]", direction.name, i, field, j)
				c.trafficPeer(ctx, peer, namespace, path, &resolved)
			}
		}
	}
	return resolved
}

func (c *Controller) trafficPeer(ctx krt.HandlerContext, peer agentsv1alpha1.TrafficPolicyPeer,
	namespace, path string, resolved *metav1.Condition,
) {
	switch {
	case peer.CIDR != "":
		// CIDR wins over the other peer fields, matching the compiler.
	case peer.Service != nil:
		ref := peer.Service
		if ref.Name == "" || ref.Name == "*" {
			return
		}
		key := cmp.Or(ref.Namespace, namespace) + "/" + ref.Name
		if krt.FetchOne(ctx, c.registry.KubernetesServices, krt.FilterKey(key)) == nil {
			referenceProblem(resolved, metav1.ConditionFalse, "ServiceNotFound", path+": Service "+key+" not found")
		}
	case peer.FQDN != "":
		// The resolver exposes addresses, not error causes. An empty result
		// cannot distinguish an in-flight lookup from an unsuccessful one.
		if len(c.traffic.Resolve(ctx, peer.FQDN)) == 0 {
			referenceProblem(resolved, metav1.ConditionUnknown, "DNSResolutionPending",
				path+": no resolved addresses available for "+peer.FQDN)
		}
	}
}
