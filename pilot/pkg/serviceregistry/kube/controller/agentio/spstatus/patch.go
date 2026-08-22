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

package spstatus

import (
	"encoding/json"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	apiVersion = "agents.kruise.io/v1alpha1"
	kind       = "SecurityProfile"
)

// applyStatus is the wire shape of a server-side-apply status patch.
//
// It is a hand-rolled struct rather than agentsv1alpha1.SecurityProfile
// because that type's Status field carries `omitempty` on
// ObservedGeneration: an apply body that omits a field this fieldManager
// previously owned tells the apiserver to prune it. The status subresource
// here must therefore always spell out observedGeneration, including 0.
type applyStatus struct {
	APIVersion string          `json:"apiVersion"`
	Kind       string          `json:"kind"`
	Metadata   applyMetadata   `json:"metadata"`
	Status     applyStatusBody `json:"status"`
}

// Namespace is deliberately absent: Patcher.ApplyStatus takes it as a separate
// argument (pkg/kube/kclient/interfaces.go:126).
type applyMetadata struct {
	Name string `json:"name"`
}

type applyStatusBody struct {
	// No omitempty: generation 0 must still be declared.
	ObservedGeneration int64              `json:"observedGeneration"`
	Conditions         []metav1.Condition `json:"conditions"`
}

// BuildPatch renders the apply body for a profile's desired status.
//
// The CRD marks status.conditions as x-kubernetes-list-type: map with
// list-map-keys: [type] (securityprofile-crd.yaml:938-940), so the apiserver
// merges per condition rather than replacing the whole list.
func BuildPatch(name string, st agentsv1alpha1.SecurityProfileStatus) ([]byte, error) {
	conds := st.Conditions
	if conds == nil {
		conds = []metav1.Condition{}
	}
	return json.Marshal(applyStatus{
		APIVersion: apiVersion,
		Kind:       kind,
		Metadata:   applyMetadata{Name: name},
		Status: applyStatusBody{
			ObservedGeneration: st.ObservedGeneration,
			Conditions:         conds,
		},
	})
}
