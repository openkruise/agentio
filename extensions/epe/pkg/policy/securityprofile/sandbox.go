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

// sandbox.go compiles the per-Sandbox policy annotations. Only the Sandbox Manager may
// write these annotations (the tenant-facing metadata key is blacklisted for
// direct use), and the rules are evaluated under the verified workload
// namespace/name of the Sandbox source — so the lookup is an exact
// namespace/name match, never a label selector, which a workload could
// influence.
package securityprofile

import (
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/registry/kubernetes/kruise"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// AnnotationSecurityRules is the Sandbox annotation that carries the
// normalized rule chain: a JSON array of v1alpha1.SecurityRule.
const AnnotationSecurityRules = v1alpha1.AnnotationSecurityRules

// NewSandboxProfile compiles the combined rule chain of one Sandbox into a
// Profile. It reads only object metadata, so callers can feed it
// PartialObjectMetadata from a metadata-only informer. The returned profile
// carries an empty selector (these rules are matched by identity, not
// matched by labels) and the Sandbox's resourceVersion, so it is identified
// like any CRD profile version.
//
// The returned profile is not yet projected: the caller must call Project
// before it can be bound, exactly as for a CRD profile.
//
// The legacy array ignores unknown fields; the native inline object has a strict schema.
func NewSandboxProfile(sandbox metav1.Object) (*Profile, error) {
	spec, err := kruise.SandboxSecurityProfile(sandbox)
	if err != nil || spec == nil {
		return nil, err
	}
	profile, err := newProfile(sandboxMeta(sandbox), spec)
	if err != nil {
		return nil, err
	}
	profile.Selector = labels.Nothing()
	return profile, nil
}

// InvalidSandboxProfile returns an identity-bearing collection item for a
// Sandbox whose rules failed to compile or project — the
// counterpart of InvalidProfile. It is never eligible for matching; the
// profile store recognizes CompileError and retains any last-known-good
// previous version under the same identity, so a bad annotation update does
// not silently remove rules that were enforcing.
func InvalidSandboxProfile(sandbox metav1.Object, err error) *Profile {
	message := "invalid sandbox security rules"
	if err != nil {
		message = err.Error()
	}
	return &Profile{
		Meta:         sandboxMeta(sandbox),
		Selector:     labels.Nothing(),
		CompileError: message,
	}
}

func sandboxMeta(sandbox metav1.Object) Meta {
	uid, _ := kruise.SandboxUID(sandbox)
	return Meta{
		Name:              sandbox.GetName(),
		SourceIdentity:    model.SourceIdentity{UID: string(sandbox.GetUID())},
		SandboxUID:        uid,
		Namespace:         sandbox.GetNamespace(),
		CreationTimestamp: sandbox.GetCreationTimestamp(),
		Version:           sandbox.GetResourceVersion(),
		Match:             MatchSandbox,
	}
}
