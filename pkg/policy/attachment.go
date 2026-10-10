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
	"slices"
	"sort"
	"strings"
	"time"

	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
)

const (
	globalPolicyAttachmentIndexKey     = "@global"
	namespacePolicyAttachmentKeyPrefix = "ns/"
)

// PolicyKind identifies a typed consumer of the shared payload-free
// attachment projection.
type PolicyKind = model.PolicyKind

// Supported policy families for attachments.
const (
	PolicyKindTrafficPolicy = model.PolicyKindTrafficPolicy
	PolicyKindEgressPolicy  = model.PolicyKindEgressPolicy
	PolicyKindSNIPolicy     = model.PolicyKindSNIPolicy
)

// AttachmentTarget describes shared selectors or a legacy Sandbox's same-name Pod.
type AttachmentTarget struct {
	Global     bool
	Namespaces []string
	Selector   metav1.LabelSelector
	PodName    string
}

// PolicyAttachment is the payload-free binding projection of a typed policy.
type PolicyAttachment struct {
	Kind            PolicyKind
	Name            string
	Target          AttachmentTarget
	Priority        int32
	CreationTime    time.Time
	SourceName      string
	SourceNamespace string

	// selector is compiled once at the producer boundary. Target.Selector is
	// its canonical source of truth and is the only form used for equality.
	selector labels.Selector
}

func (p PolicyAttachment) ResourceName() string {
	return (model.PolicyRef{
		Kind: p.Kind,
		Name: p.Name,
	}).ResourceName()
}

func (p PolicyAttachment) Equals(other PolicyAttachment) bool {
	return p.Kind == other.Kind &&
		p.Name == other.Name &&
		p.Target.Global == other.Target.Global &&
		p.Target.PodName == other.Target.PodName &&
		equalStrings(p.Target.Namespaces, other.Target.Namespaces) &&
		apiequality.Semantic.DeepEqual(p.Target.Selector, other.Target.Selector) &&
		p.Priority == other.Priority &&
		p.CreationTime.Equal(other.CreationTime) &&
		p.SourceName == other.SourceName &&
		p.SourceNamespace == other.SourceNamespace
}

// NewPolicyAttachment validates and normalizes one immutable attachment.
func NewPolicyAttachment(attachment PolicyAttachment) (PolicyAttachment, error) {
	attachment.Target.Namespaces = append([]string(nil), attachment.Target.Namespaces...)
	attachment.Target.Selector = *attachment.Target.Selector.DeepCopy()
	if err := validateAttachmentValues("namespace", attachment.Target.Namespaces); err != nil {
		return PolicyAttachment{}, err
	}
	sort.Strings(attachment.Target.Namespaces)
	if err := attachment.validate(); err != nil {
		return PolicyAttachment{}, err
	}
	if attachment.selector == nil {
		selector, err := metav1.LabelSelectorAsSelector(&attachment.Target.Selector)
		if err != nil {
			return PolicyAttachment{}, fmt.Errorf("policy attachment %s selector: %w", attachment.Name, err)
		}
		attachment.selector = selector
	}
	return attachment, nil
}

func (p PolicyAttachment) validate() error {
	if err := (model.PolicyRef{
		Kind: p.Kind,
		Name: p.Name,
	}).Validate(); err != nil {
		return fmt.Errorf("policy attachment: %w", err)
	}
	modes := 0
	if p.Target.Global {
		modes++
	}
	if len(p.Target.Namespaces) > 0 {
		modes++
	}
	if modes != 1 {
		return fmt.Errorf("policy attachment %s must use exactly one target mode", p.Name)
	}
	return nil
}

func validateAttachmentValues(kind string, values []string) error {
	seen := sets.NewWithLength[string](len(values))
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("policy attachment %s is empty", kind)
		}
		if seen.Contains(value) {
			return fmt.Errorf("policy attachment %s %q is duplicated", kind, value)
		}
		seen.Insert(value)
	}
	return nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func selectorEmpty(selector metav1.LabelSelector) bool {
	return len(selector.MatchLabels) == 0 && len(selector.MatchExpressions) == 0
}

func containsString(values []string, value string) bool {
	_, found := slices.BinarySearch(values, value)
	return found
}

// Selects reports whether this attachment applies to the Workload.
func (p PolicyAttachment) Selects(workload model.Workload) bool {
	if p.Target.PodName != "" {
		// shortcut: release compatibility assumes same-name Pods; shared hosts need Sandbox-aware consumers.
		return strings.HasPrefix(workload.Source.Registry, "kubernetes/") &&
			workload.Name == p.Target.PodName && containsString(p.Target.Namespaces, workload.Namespace)
	}
	return p.selects(workload.Namespace, workload.Labels)
}

func (p PolicyAttachment) selects(namespace string, targetLabels map[string]string) bool {
	if !p.Target.Global && !containsString(p.Target.Namespaces, namespace) {
		return false
	}
	selector := p.selector
	if selector == nil {
		var err error
		selector, err = metav1.LabelSelectorAsSelector(&p.Target.Selector)
		if err != nil {
			return false
		}
	}
	return selector.Matches(labels.Set(targetLabels))
}

func (p PolicyAttachment) specificity() int {
	if !selectorEmpty(p.Target.Selector) {
		return 2
	}
	if len(p.Target.Namespaces) > 0 {
		return 1
	}
	return 0
}

func policyAttachmentLess(left, right PolicyAttachment) bool {
	if left.Kind != right.Kind {
		return left.Kind < right.Kind
	}
	// Sandbox inline rules follow every shared profile, including MaxInt32 priority.
	if (left.Target.PodName == "") != (right.Target.PodName == "") {
		return left.Target.PodName == ""
	}
	if left.Priority != right.Priority {
		return left.Priority < right.Priority
	}
	if left.Kind == PolicyKindTrafficPolicy {
		// Prefer older policies at equal priority so a newly created policy
		// cannot take precedence merely through its namespace or name.
		if !left.CreationTime.Equal(right.CreationTime) {
			return left.CreationTime.Before(right.CreationTime)
		}
		if left.SourceNamespace != right.SourceNamespace {
			return left.SourceNamespace < right.SourceNamespace
		}
		if left.SourceName != right.SourceName {
			return left.SourceName < right.SourceName
		}
		return left.Name < right.Name
	}
	if left.specificity() != right.specificity() {
		return left.specificity() > right.specificity()
	}
	if !left.CreationTime.Equal(right.CreationTime) {
		return left.CreationTime.Before(right.CreationTime)
	}
	if left.SourceName != right.SourceName {
		return left.SourceName < right.SourceName
	}
	if left.SourceNamespace != right.SourceNamespace {
		return left.SourceNamespace < right.SourceNamespace
	}
	return left.Name < right.Name
}
