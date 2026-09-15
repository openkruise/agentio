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
	"maps"
	"strings"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	podsource "github.com/openkruise/agentio/pkg/registry/kubernetes/pod"
)

const podLabelCreatedBy = agentsv1alpha1.InternalPrefix + "created-by"

// isPodOwnedInternalLabel reports the Kruise-internal labels that deliberately
// describe the backing Pod and may therefore override Sandbox CR metadata.
// Unknown internal labels remain Sandbox-owned by default.
func isPodOwnedInternalLabel(key string) bool {
	switch key {
	case agentsv1alpha1.LabelSandboxName,
		agentsv1alpha1.LabelAllowInternetAccess,
		agentsv1alpha1.AnnotationOwner,
		podLabelCreatedBy:
		return true
	default:
		return false
	}
}

// sandboxUID returns the sandbox delivery identity: the sandbox-id label, or namespace--name for non-pooled sandboxes.
func sandboxUID(sandbox *agentsv1alpha1.Sandbox) (string, bool) {
	if sandbox == nil {
		return "", false
	}
	if sandboxID := sandbox.Labels[agentsv1alpha1.LabelSandboxID]; sandboxID != "" {
		return sandboxID, true
	}
	if sandbox.Labels[agentsv1alpha1.LabelSandboxPool] != "" {
		return "", false
	}
	if sandbox.Namespace == "" || sandbox.Name == "" {
		return "", false
	}
	return sandbox.Namespace + "--" + sandbox.Name, true
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

func mergeSandboxLabels(sandboxLabels, podLabels map[string]string) map[string]string {
	merged := maps.Clone(sandboxLabels)
	for key, value := range podLabels {
		if strings.HasPrefix(key, agentsv1alpha1.InternalPrefix) && !isPodOwnedInternalLabel(key) {
			continue
		}
		if merged == nil {
			merged = make(map[string]string, len(podLabels))
		}
		merged[key] = value
	}
	return merged
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
			var podLabels map[string]string
			if pod != nil {
				podLabels = pod.Labels
			}
			var attester *model.Attester
			if pod != nil && pod.DeletionTimestamp == nil && podsource.IsEligible(pod) {
				attester = &model.Attester{WorkloadUID: podsource.WorkloadUID(clusterID, pod)}
			}
			return &model.Sandbox{
				State:     runtimeState(sandbox),
				Attester:  attester,
				UID:       group.Key,
				Namespace: sandbox.Namespace,
				Labels:    mergeSandboxLabels(sandbox.Labels, podLabels),
			}
		}, options...)
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

func runtimeState(sandbox *agentsv1alpha1.Sandbox) model.SandboxState {
	switch sandbox.Status.Phase {
	case agentsv1alpha1.SandboxPending:
		return model.SandboxStatePending
	case agentsv1alpha1.SandboxRunning:
		return model.SandboxStateRunning
	case agentsv1alpha1.SandboxPaused:
		for _, condition := range sandbox.Status.Conditions {
			if condition.Type == string(agentsv1alpha1.SandboxConditionPaused) && condition.Status == metav1.ConditionTrue {
				return model.SandboxStatePaused
			}
		}
	case agentsv1alpha1.SandboxSucceeded, agentsv1alpha1.SandboxFailed:
		return model.SandboxStateStopped
	}
	// Transitional phases do not prove a completed lifecycle state.
	return model.SandboxStateUnspecified
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
