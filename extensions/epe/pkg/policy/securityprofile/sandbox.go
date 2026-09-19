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

// sandbox.go compiles the per-Sandbox security rules carried in the
// agents.kruise.io/security-rules annotation. Only the Sandbox Manager may
// write that annotation (the tenant-facing metadata key is blacklisted for
// direct use), and the rules are evaluated under the verified workload
// identity of the Sandbox's own Pod — so the lookup is an exact
// namespace/name match, never a label selector, which a workload could
// influence.
package securityprofile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// AnnotationSecurityRules is the Sandbox annotation that carries the
// normalized rule chain: a JSON array of v1alpha1.SecurityRule.
const AnnotationSecurityRules = v1alpha1.AnnotationSecurityRules

type SandboxPolicyState uint8

const (
	SandboxPolicyUnknown SandboxPolicyState = iota
	SandboxPolicyReady
	SandboxPolicyReadyEmpty
	SandboxPolicyInvalid
)

func (state SandboxPolicyState) String() string {
	switch state {
	case SandboxPolicyReady:
		return "ready"
	case SandboxPolicyReadyEmpty:
		return "ready_empty"
	case SandboxPolicyInvalid:
		return "invalid"
	default:
		return "unknown"
	}
}

var ErrSandboxPolicyWaitOverloaded = errors.New("sandbox policy wait overloaded")

type PolicySnapshot struct {
	Profiles       []*Profile
	SandboxExists  bool
	SandboxState   SandboxPolicyState
	SandboxVersion string
}

func NewSandboxStateProfile(sandbox metav1.Object, state SandboxPolicyState) *Profile {
	return &Profile{
		Meta: Meta{
			Name:              sandbox.GetName(),
			Namespace:         sandbox.GetNamespace(),
			CreationTimestamp: sandbox.GetCreationTimestamp(),
			Version:           sandbox.GetResourceVersion(),
			Match:             MatchPod,
		},
		Selector:     labels.Nothing(),
		SandboxState: state,
	}
}

// NewSandboxProfile compiles the rule chain of one Sandbox into a
// Profile. It reads only object metadata, so callers can feed it
// PartialObjectMetadata from a metadata-only informer. The returned profile
// carries an empty selector (these rules are matched by identity, not
// matched by labels) and the Sandbox's resourceVersion, so it is identified
// like any CRD profile version.
//
// The returned profile is not yet projected: the caller must call Project
// before it can be bound, exactly as for a CRD profile.
//
// Unknown JSON fields fail the compile: the annotation is a server artifact
// and anything unrecognized means the writer and reader disagree about the
// schema, which must not degrade into silently dropped rules.
func NewSandboxProfile(sandbox metav1.Object) (*Profile, error) {
	raw := sandbox.GetAnnotations()[AnnotationSecurityRules]
	if raw == "" {
		return nil, nil
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	dec.DisallowUnknownFields()
	var specRules []v1alpha1.SecurityRule
	if err := dec.Decode(&specRules); err != nil {
		return nil, fmt.Errorf("decode %s annotation: %w", AnnotationSecurityRules, err)
	}
	if len(specRules) == 0 {
		return nil, fmt.Errorf("%s annotation contains no rules", AnnotationSecurityRules)
	}
	for i := range specRules {
		escapeSandboxHeaderValues(specRules[i].Actions.HeaderManipulation)
	}
	rules, err := compileRules(specRules)
	if err != nil {
		return nil, err
	}
	return &Profile{
		Meta: Meta{
			Name:              sandbox.GetName(),
			Namespace:         sandbox.GetNamespace(),
			CreationTimestamp: sandbox.GetCreationTimestamp(),
			Version:           sandbox.GetResourceVersion(),
			Match:             MatchPod,
		},
		Selector:     labels.Nothing(),
		Rules:        rules,
		SandboxState: SandboxPolicyReady,
	}, nil
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
		Meta: Meta{
			Name:              sandbox.GetName(),
			Namespace:         sandbox.GetNamespace(),
			CreationTimestamp: sandbox.GetCreationTimestamp(),
			Version:           sandbox.GetResourceVersion(),
			Match:             MatchPod,
		},
		Selector:     labels.Nothing(),
		CompileError: message,
		SandboxState: SandboxPolicyInvalid,
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
