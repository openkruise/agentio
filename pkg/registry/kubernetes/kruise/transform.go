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

package kruise

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	corev1 "k8s.io/api/core/v1"

	"github.com/openkruise/agentio/pkg/krt"
	agentlog "github.com/openkruise/agentio/pkg/log"
	"github.com/openkruise/agentio/pkg/model"
	podsource "github.com/openkruise/agentio/pkg/registry/kubernetes/pod"
)

var log = agentlog.New("registry")

// sandboxUID qualifies the delivery ID with the Kruise kind. Non-pooled
// Sandboxes without a delivery label retain the namespace--name fallback.
func sandboxUID(sandbox *agentsv1alpha1.Sandbox) (string, bool) {
	if sandbox == nil {
		return "", false
	}
	if sandboxID := sandbox.Labels[agentsv1alpha1.LabelSandboxID]; sandboxID != "" {
		return model.SandboxUID(model.SandboxKindKruise, sandboxID), true
	}
	if sandbox.Labels[agentsv1alpha1.LabelSandboxPool] != "" {
		return "", false
	}
	if sandbox.Namespace == "" || sandbox.Name == "" {
		return "", false
	}
	return model.SandboxUID(model.SandboxKindKruise, sandbox.Namespace+"--"+sandbox.Name), true
}

func newSandboxesByUID(
	sandboxes krt.Collection[*agentsv1alpha1.Sandbox],
) krt.Index[string, *agentsv1alpha1.Sandbox] {
	return krt.NewIndex(sandboxes, "kruiseSandboxesByUID", func(sandbox *agentsv1alpha1.Sandbox) []string {
		if !isPolicySubject(sandbox) {
			return nil
		}
		uid, found := sandboxUID(sandbox)
		if !found {
			return nil
		}
		return []string{uid}
	})
}

func newPodsByUID(pods krt.Collection[*corev1.Pod]) krt.Index[string, *corev1.Pod] {
	return krt.NewIndex(pods, "kruiseSandboxPodsByUID", func(pod *corev1.Pod) []string {
		if pod == nil || pod.UID == "" {
			return nil
		}
		return []string{string(pod.UID)}
	})
}

func backingPod(
	ctx krt.HandlerContext,
	pods krt.Collection[*corev1.Pod],
	podsByUID krt.Index[string, *corev1.Pod],
	sandbox *agentsv1alpha1.Sandbox,
) *corev1.Pod {
	if sandbox == nil || sandbox.Status.PodInfo.PodUID == "" {
		return nil
	}
	matches := krt.Fetch(ctx, pods, krt.FilterIndex(podsByUID, string(sandbox.Status.PodInfo.PodUID)))
	if len(matches) != 1 || !ownedPod(matches[0], sandbox) {
		return nil
	}
	return matches[0]
}

func newSandboxes(
	sandboxesByUID krt.IndexCollection[string, *agentsv1alpha1.Sandbox],
	pods krt.Collection[*corev1.Pod],
	podsByUID krt.Index[string, *corev1.Pod],
	clusterID string,
	options ...krt.CollectionOption,
) krt.Collection[model.Sandbox] {
	return krt.NewCollection(sandboxesByUID,
		func(ctx krt.HandlerContext, group krt.IndexObject[string, *agentsv1alpha1.Sandbox]) *model.Sandbox {
			if len(group.Objects) != 1 {
				return nil
			}
			sandbox := group.Objects[0]
			if !isPolicySubject(sandbox) {
				return nil
			}
			pod := backingPod(ctx, pods, podsByUID, sandbox)
			var attester *model.Attester
			if pod != nil && pod.DeletionTimestamp == nil && podsource.IsEligible(pod) {
				attester = &model.Attester{WorkloadUID: podsource.WorkloadUID(clusterID, pod)}
			}
			return &model.Sandbox{
				Attester:  attester,
				UID:       group.Key,
				Namespace: sandbox.Namespace,
			}
		}, options...)
}

// newSecurityProfiles projects owned policy inputs independently of runtime metadata.
func newSecurityProfiles(
	sandboxes krt.IndexCollection[string, *agentsv1alpha1.Sandbox],
	options ...krt.CollectionOption,
) krt.Collection[model.SecurityProfile] {
	return krt.NewCollection(
		sandboxes,
		func(ctx krt.HandlerContext, group krt.IndexObject[string, *agentsv1alpha1.Sandbox]) *model.SecurityProfile {
			if len(group.Objects) != 1 || !isPolicySubject(group.Objects[0]) {
				return nil
			}
			sandbox := group.Objects[0]
			rules, err := sandboxSecurityRules(sandbox)
			if err != nil {
				log.Warn("invalid Sandbox security rules; retaining previous inline profile",
					"namespace", sandbox.Namespace, "sandbox", sandbox.Name, "error", err)
				ctx.DiscardResult()
				return nil
			}
			if len(rules) == 0 {
				return nil
			}
			return &model.SecurityProfile{
				Dedicated:  true,
				SandboxUID: group.Key,
				Namespace:  sandbox.Namespace,
				Name:       sandbox.Name,
				Spec:       agentsv1alpha1.SecurityProfileSpec{Rules: rules},
			}
		},
		options...)
}

func sandboxSecurityRules(sandbox *agentsv1alpha1.Sandbox) ([]agentsv1alpha1.SecurityRule, error) {
	raw := sandbox.Annotations[agentsv1alpha1.AnnotationSecurityRules]
	if raw == "" {
		return nil, nil
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	var rules []agentsv1alpha1.SecurityRule
	if err := decoder.Decode(&rules); err != nil {
		return nil, fmt.Errorf("decode %s: %w", agentsv1alpha1.AnnotationSecurityRules, err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s must contain a single JSON array", agentsv1alpha1.AnnotationSecurityRules)
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("%s contains no rules", agentsv1alpha1.AnnotationSecurityRules)
	}
	return rules, nil
}

func isPolicySubject(sandbox *agentsv1alpha1.Sandbox) bool {
	if sandbox == nil || sandbox.UID == "" || sandbox.DeletionTimestamp != nil {
		return false
	}
	if sandbox.Labels[agentsv1alpha1.LabelSandboxPool] == "" {
		return true
	}
	return sandbox.Labels[agentsv1alpha1.LabelSandboxIsClaimed] == agentsv1alpha1.True
}

func ownedPod(pod *corev1.Pod, sandbox *agentsv1alpha1.Sandbox) bool {
	if pod == nil || sandbox == nil || pod.Namespace != sandbox.Namespace {
		return false
	}
	for _, owner := range pod.OwnerReferences {
		if owner.Controller != nil && *owner.Controller &&
			owner.APIVersion == agentsv1alpha1.GroupVersion.String() &&
			owner.Kind == "Sandbox" && owner.Name == sandbox.Name && owner.UID == sandbox.UID {
			return true
		}
	}
	return false
}

// OwnsPod classifies Kruise Sandbox hosts from the Pod itself, independently
// of Sandbox availability, claim status, or lifecycle.
func OwnsPod(pod *corev1.Pod) bool {
	if pod == nil {
		return false
	}
	for _, owner := range pod.OwnerReferences {
		if owner.Controller != nil && *owner.Controller &&
			owner.APIVersion == agentsv1alpha1.GroupVersion.String() && owner.Kind == "Sandbox" {
			return true
		}
	}
	return false
}
