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
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"istio.io/istio/pkg/util/sets"
)

const (
	globalPolicyAttachmentIndexKey     = "@global"
	namespacePolicyAttachmentKeyPrefix = "ns/"
	sandboxPolicyAttachmentKeyPrefix   = "uid/"
)

// PolicyKind identifies a typed consumer of the shared payload-free
// attachment projection.
type PolicyKind = model.PolicyKind

const (
	PolicyKindAuthorization = model.PolicyKindAuthorization
	PolicyKindEgressPolicy  = model.PolicyKindEgressPolicy
	PolicyKindSNIPolicy     = model.PolicyKindSNIPolicy
)

// AttachmentTarget describes selector-derived policy attachment (global, namespaces, or label selector).
type AttachmentTarget struct {
	Global     bool
	Namespaces []string
	SandboxUID string
	Selector   metav1.LabelSelector
}

// SandboxSubject is the joined policy-selection view of a Sandbox and its
// Workload binding. Namespace and labels come from an explicit Sandbox;
// implicit Pod-shaped Sandboxes retain Workload metadata for compatibility.
// Addresses and readiness always come from the active Workload.
type SandboxSubject struct {
	SandboxUID string
	Namespace  string
	Labels     map[string]string
	Addresses  []string
	Ready      bool
}

func (s SandboxSubject) ResourceName() string { return s.SandboxUID }

func (s SandboxSubject) Equals(other SandboxSubject) bool {
	return s.SandboxUID == other.SandboxUID && s.Namespace == other.Namespace &&
		reflect.DeepEqual(s.Labels, other.Labels) && reflect.DeepEqual(s.Addresses, other.Addresses) &&
		s.Ready == other.Ready
}

// PolicyAttachment is the payload-free Sandbox-binding projection of a typed policy.
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
		equalStrings(p.Target.Namespaces, other.Target.Namespaces) &&
		apiequality.Semantic.DeepEqual(p.Target.Selector, other.Target.Selector) &&
		p.Target.SandboxUID == other.Target.SandboxUID &&
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
	if p.Target.SandboxUID != "" {
		modes++
		if _, err := policySandboxUID(p.Target.SandboxUID, p.Target.Selector); err != nil {
			return fmt.Errorf("policy attachment %s: %w", p.Name, err)
		}
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

func policySandboxUID(declared string, selector metav1.LabelSelector) (string, error) {
	selected, selectedSet := selector.MatchLabels[agentsv1alpha1.LabelSandboxID]
	if declared != "" && strings.TrimSpace(declared) != declared {
		return "", fmt.Errorf("sandbox UID %q contains surrounding whitespace", declared)
	}
	if selectedSet && (selected == "" || strings.TrimSpace(selected) != selected) {
		return "", fmt.Errorf("sandbox UID selector value %q is invalid", selected)
	}
	if declared != "" && selectedSet && declared != selected {
		return "", fmt.Errorf("sandbox UID %q conflicts with selector value %q", declared, selected)
	}
	if declared != "" {
		return declared, nil
	}
	return selected, nil
}

func containsString(values []string, value string) bool {
	_, found := slices.BinarySearch(values, value)
	return found
}

// Selects reports whether this attachment applies to the sandbox.
func (p PolicyAttachment) Selects(subject SandboxSubject) bool {
	if p.Target.SandboxUID != "" && p.Target.SandboxUID != subject.SandboxUID {
		return false
	}
	if p.Target.SandboxUID == "" && !p.Target.Global && !containsString(p.Target.Namespaces, subject.Namespace) {
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
	return selector.Matches(labels.Set(subject.Labels))
}

func (p PolicyAttachment) specificity() int {
	if p.Target.SandboxUID != "" {
		return 3
	}
	if !selectorEmpty(p.Target.Selector) {
		return 2
	}
	if len(p.Target.Namespaces) > 0 {
		return 1
	}
	return 0
}

func policyAttachmentLess(left, right PolicyAttachment) bool {
	if left.Priority != right.Priority {
		return left.Priority < right.Priority
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

// PolicyBindingGroup contains the ordered resource names for one typed policy
// consumer.
type PolicyBindingGroup struct {
	Kind  PolicyKind
	Names []string
}

// SandboxPolicyBindings is the shared payload-free projection of explicit and
// selector-derived policy references for one sandbox.
type SandboxPolicyBindings struct {
	SandboxUID    string
	Groups        []PolicyBindingGroup
	Unresolved    []model.PolicyRef
	InvalidReason string
}

func (b SandboxPolicyBindings) ResourceName() string { return b.SandboxUID }

func (b SandboxPolicyBindings) Equals(other SandboxPolicyBindings) bool {
	if b.SandboxUID != other.SandboxUID || b.InvalidReason != other.InvalidReason ||
		len(b.Groups) != len(other.Groups) || len(b.Unresolved) != len(other.Unresolved) {
		return false
	}
	for index := range b.Groups {
		if b.Groups[index].Kind != other.Groups[index].Kind ||
			!equalStrings(b.Groups[index].Names, other.Groups[index].Names) {
			return false
		}
	}
	for index := range b.Unresolved {
		if b.Unresolved[index] != other.Unresolved[index] {
			return false
		}
	}
	return true
}

func (b SandboxPolicyBindings) Valid() bool {
	return b.InvalidReason == "" && len(b.Unresolved) == 0
}

func (b SandboxPolicyBindings) PolicyNames(kind PolicyKind) []string {
	for _, group := range b.Groups {
		if group.Kind == kind {
			// Returned slice is shared with the caller; treat it as read-only.
			return group.Names
		}
	}
	return nil
}

func attachmentIndexKeys(attachment PolicyAttachment) []string {
	switch {
	case attachment.Target.SandboxUID != "":
		return []string{sandboxPolicyAttachmentKeyPrefix + attachment.Target.SandboxUID}
	case attachment.Target.Global:
		return []string{globalPolicyAttachmentIndexKey}
	default:
		result := make([]string, 0, len(attachment.Target.Namespaces))
		for _, namespace := range attachment.Target.Namespaces {
			result = append(result, namespacePolicyAttachmentKeyPrefix+namespace)
		}
		return result
	}
}

func NewSandboxPolicyBindingsCollection(
	sandboxes krt.Collection[model.Sandbox],
	subjects krt.Collection[SandboxSubject],
	attachments krt.Collection[PolicyAttachment],
	options krt.OptionsBuilder,
) krt.Collection[SandboxPolicyBindings] {
	byTarget := krt.NewIndex(attachments, "policyAttachmentsByTarget", attachmentIndexKeys)
	return krt.NewManyCollection(subjects,
		func(ctx krt.HandlerContext, subject SandboxSubject) []SandboxPolicyBindings {
			sandbox := krt.FetchOne(ctx, sandboxes, krt.FilterKey(subject.SandboxUID))
			if sandbox != nil {
				if err := sandbox.Validate(); err != nil {
					return []SandboxPolicyBindings{{
						SandboxUID:    subject.ResourceName(),
						Unresolved:    append([]model.PolicyRef(nil), sandbox.PolicyRefs...),
						InvalidReason: err.Error(),
					}}
				}
			}
			matchedByName := make(map[string]PolicyAttachment)
			for _, indexKey := range []string{
				sandboxPolicyAttachmentKeyPrefix + subject.SandboxUID,
				globalPolicyAttachmentIndexKey,
				namespacePolicyAttachmentKeyPrefix + subject.Namespace,
			} {
				for _, attachment := range krt.Fetch(ctx, attachments, krt.FilterIndex(byTarget, indexKey)) {
					if attachment.Selects(subject) {
						matchedByName[attachment.ResourceName()] = attachment
					}
				}
			}
			if len(matchedByName) == 0 && (sandbox == nil || len(sandbox.PolicyRefs) == 0) {
				return nil
			}
			matched := make([]PolicyAttachment, 0, len(matchedByName))
			for _, attachment := range matchedByName {
				matched = append(matched, attachment)
			}
			sort.Slice(matched, func(i, j int) bool { return policyAttachmentLess(matched[i], matched[j]) })
			byKind := make(map[PolicyKind][]string)
			seen := sets.New[string]()
			unresolved := make([]model.PolicyRef, 0)
			if sandbox != nil {
				for _, reference := range sandbox.PolicyRefs {
					key := reference.ResourceName()
					if krt.FetchOne(ctx, attachments, krt.FilterKey(key)) == nil {
						unresolved = append(unresolved, reference)
						continue
					}
					if seen.Contains(key) {
						continue
					}
					seen.Insert(key)
					byKind[reference.Kind] = append(byKind[reference.Kind], reference.Name)
				}
			}
			for _, attachment := range matched {
				key := attachment.ResourceName()
				if seen.Contains(key) {
					continue
				}
				seen.Insert(key)
				byKind[attachment.Kind] = append(byKind[attachment.Kind], attachment.Name)
			}
			kinds := make([]PolicyKind, 0, len(byKind))
			for kind := range byKind {
				kinds = append(kinds, kind)
			}
			slices.Sort(kinds)
			groups := make([]PolicyBindingGroup, 0, len(kinds))
			for _, kind := range kinds {
				groups = append(groups, PolicyBindingGroup{
					Kind:  kind,
					Names: byKind[kind],
				})
			}
			return []SandboxPolicyBindings{{
				SandboxUID: subject.ResourceName(),
				Groups:     groups,
				Unresolved: unresolved,
			}}
		}, options.WithName("sandbox-policy-bindings")...)
}
