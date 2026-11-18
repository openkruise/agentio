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

package policy

import (
	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	metavalidation "k8s.io/apimachinery/pkg/apis/meta/v1/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// ValidateTrafficPolicy checks configuration without resolving live peers.
// Missing Services, Pods and DNS records are reported by policy status instead.
func ValidateTrafficPolicy(spec agentsv1alpha1.TrafficPolicySpec) field.ErrorList {
	root := field.NewPath("spec")
	errs := metavalidation.ValidateLabelSelector(
		&spec.Selector,
		metavalidation.LabelSelectorValidationOptions{},
		root.Child("selector"),
	)
	if spec.Priority < 0 {
		errs = append(errs, field.Invalid(root.Child("priority"), spec.Priority, "must be nonnegative"))
	}
	for _, direction := range []struct {
		name  string
		value *agentsv1alpha1.TrafficPolicyDirection
	}{{"ingress", spec.Ingress}, {"egress", spec.Egress}} {
		if direction.value == nil {
			continue
		}
		for i, rule := range direction.value.Rules {
			path := root.Child(direction.name, "rules").Index(i)
			if rule.Action != agentsv1alpha1.RuleActionAllow && rule.Action != agentsv1alpha1.RuleActionReject {
				errs = append(errs, field.Invalid(path.Child("action"), rule.Action, "unsupported traffic rule action"))
			}
			if _, err := compileNativePorts(rule.Ports); err != nil {
				errs = append(errs, field.Invalid(path.Child("ports"), field.OmitValueType{}, err.Error()))
			}
			for _, entry := range []struct {
				name  string
				peers []agentsv1alpha1.TrafficPolicyPeer
			}{{"from", rule.From}, {"to", rule.To}} {
				for j, peer := range entry.peers {
					peerPath := path.Child(entry.name).Index(j)
					if peer.CIDR != "" {
						if _, err := parsePrefix(peer.CIDR); err != nil {
							errs = append(
								errs,
								field.Invalid(peerPath.Child("cidr"), peer.CIDR, "invalid CIDR: "+err.Error()),
							)
						}
					}
					if peer.Workload != nil {
						selector := metav1.LabelSelector{MatchLabels: peer.Workload.Selector}
						errs = append(errs, metavalidation.ValidateLabelSelector(
							&selector,
							metavalidation.LabelSelectorValidationOptions{},
							peerPath.Child("workload", "selector"),
						)...)
					}
				}
			}
		}
	}
	return errs
}
