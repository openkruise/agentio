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
	"fmt"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	metavalidation "k8s.io/apimachinery/pkg/apis/meta/v1/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// ValidateTrafficPolicy checks configuration without resolving live peers.
// Missing Services, Pods and DNS records are reported by policy status instead.
func ValidateTrafficPolicy(spec agentsv1alpha1.TrafficPolicySpec) error {
	if errs := metavalidation.ValidateLabelSelector(
		&spec.Selector,
		metavalidation.LabelSelectorValidationOptions{},
		field.NewPath("spec", "selector"),
	); len(
		errs,
	) > 0 {
		return errs.ToAggregate()
	}
	if spec.Priority < 0 {
		return fmt.Errorf("spec.priority must be nonnegative")
	}
	for _, direction := range []struct {
		name  string
		value *agentsv1alpha1.TrafficPolicyDirection
	}{{"ingress", spec.Ingress}, {"egress", spec.Egress}} {
		if direction.value == nil {
			continue
		}
		for i, rule := range direction.value.Rules {
			path := fmt.Sprintf("spec.%s.rules[%d]", direction.name, i)
			if rule.Action != agentsv1alpha1.RuleActionAllow && rule.Action != agentsv1alpha1.RuleActionReject {
				return fmt.Errorf("%s: unsupported traffic rule action %q", path, rule.Action)
			}
			if _, err := compileNativePorts(rule.Ports); err != nil {
				return fmt.Errorf("%s.ports: %w", path, err)
			}
			for _, peers := range [][]agentsv1alpha1.TrafficPolicyPeer{rule.From, rule.To} {
				for _, peer := range peers {
					if peer.CIDR != "" {
						if _, err := parsePrefix(peer.CIDR); err != nil {
							return fmt.Errorf("%s: invalid CIDR %q: %w", path, peer.CIDR, err)
						}
					}
					if peer.Workload != nil {
						selector := metav1.LabelSelector{MatchLabels: peer.Workload.Selector}
						if errs := metavalidation.ValidateLabelSelector(
							&selector,
							metavalidation.LabelSelectorValidationOptions{},
							field.NewPath(path, "workload", "selector"),
						); len(
							errs,
						) > 0 {
							return errs.ToAggregate()
						}
					}
				}
			}
		}
	}
	return nil
}
