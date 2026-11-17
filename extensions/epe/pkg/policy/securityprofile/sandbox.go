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
	"strings"

	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/registry/kubernetes/kruise"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// AnnotationSecurityRules is the Sandbox annotation that carries the
// normalized rule chain: a JSON array of v1alpha1.SecurityRule.
//
// The literal mirrors the Sandbox Manager's annotation key. It stays a local
// constant because the agents-api module does not export it yet; switch to
// v1alpha1.AnnotationSecurityRules once it lands upstream.
const AnnotationSecurityRules = "agents.kruise.io/security-rules"

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
	raw := sandbox.GetAnnotations()[AnnotationSecurityRules]
	policies, err := kruise.SandboxPolicies(sandbox)
	if err != nil || policies == nil {
		return nil, err
	}
	spec := policies.Profile()
	for i := range spec.Rules {
		escapeSandboxHeaderValues(spec.Rules[i].Actions.HeaderManipulation)
	}
	uid, _ := kruise.SandboxUID(sandbox)
	meta := Meta{
		Name:              sandbox.GetName(),
		SourceIdentity:    model.SourceIdentity{UID: string(sandbox.GetUID())},
		SandboxUID:        uid,
		Namespace:         sandbox.GetNamespace(),
		CreationTimestamp: sandbox.GetCreationTimestamp(),
		Version:           sandbox.GetResourceVersion(),
		Match:             MatchSandbox,
	}
	if policies.SecurityProfile == nil {
		rules, err := compileRules(spec.Rules)
		if err != nil {
			return nil, err
		}
		return &Profile{Meta: meta, Selector: labels.Nothing(), RawSandboxRules: raw, Rules: rules}, nil
	}
	profile, err := newProfile(meta, spec)
	if err != nil {
		return nil, err
	}
	profile.Selector = labels.Nothing()
	profile.E2BRuleOffset = policies.E2BRuleOffset
	return profile, nil
}

// InvalidSandboxProfile returns an identity-bearing collection item for a
// Sandbox whose rules failed to compile or project — the
// counterpart of InvalidProfile. It is never eligible for matching; the
// profile store recognizes CompileError and retains any last-known-good
// previous version under the same identity, so a bad annotation update does
// not silently remove rules that were enforcing.
func InvalidSandboxProfile(sandbox metav1.Object, err error) *Profile {
	uid, _ := kruise.SandboxUID(sandbox)
	message := "invalid sandbox security rules"
	if err != nil {
		message = err.Error()
	}
	return &Profile{
		Meta: Meta{
			Name:              sandbox.GetName(),
			SourceIdentity:    model.SourceIdentity{UID: string(sandbox.GetUID())},
			SandboxUID:        uid,
			Namespace:         sandbox.GetNamespace(),
			CreationTimestamp: sandbox.GetCreationTimestamp(),
			Version:           sandbox.GetResourceVersion(),
			Match:             MatchSandbox,
		},
		Selector:     labels.Nothing(),
		CompileError: message,
	}
}

// escapeSandboxHeaderValues neutralizes Go template delimiters in annotation
// set values. The E2B contract defines these header values as plaintext, and the
// headermutation filter compiles every value as a template; without escaping,
// a tenant-supplied "{{...}}" would be evaluated against the render scope
// instead of arriving verbatim on the wire.
func escapeSandboxHeaderValues(hm *v1alpha1.HeaderManipulationAction) {
	if hm == nil {
		return
	}
	for i := range hm.Set {
		hm.Set[i].Value = strings.ReplaceAll(hm.Set[i].Value, "{{", `{{"{{"}}`)
	}
}
