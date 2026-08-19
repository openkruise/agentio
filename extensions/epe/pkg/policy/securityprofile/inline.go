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

// inline.go compiles the per-Sandbox inline security rules carried in the
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
	"fmt"
	"strings"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// AnnotationSecurityRules is the Sandbox annotation that carries the
// normalized inline rule chain: a JSON array of v1alpha1.SecurityRule.
//
// The literal mirrors the Sandbox Manager's annotation key. It stays a local
// constant because the agents-api module does not export it yet; switch to
// v1alpha1.AnnotationSecurityRules once it lands upstream.
const AnnotationSecurityRules = "agents.kruise.io/security-rules"

// NewInlineProfile compiles the inline rule chain of one Sandbox into a
// Profile. It reads only object metadata, so callers can feed it
// PartialObjectMetadata from a metadata-only informer. The returned profile
// carries an empty selector (inline rules are looked up by identity, not
// matched by labels) and the Sandbox's resourceVersion so projection caches
// can key on it like any CRD profile.
//
// Unknown JSON fields fail the compile: the annotation is a server artifact
// and anything unrecognized means the writer and reader disagree about the
// schema, which must not degrade into silently dropped rules.
func NewInlineProfile(sandbox metav1.Object) (*Profile, error) {
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
		escapeInlineHeaderValues(specRules[i].Actions.HeaderManipulation)
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
			Source:            SourceInline,
		},
		Selector: labels.Nothing(),
		Rules:    rules,
	}, nil
}

// escapeInlineHeaderValues neutralizes Go template delimiters in inline set
// values. The E2B contract defines inline header values as plaintext, and the
// headermutation filter compiles every value as a template; without escaping,
// a tenant-supplied "{{...}}" would be evaluated against the render scope
// instead of arriving verbatim on the wire.
func escapeInlineHeaderValues(hm *v1alpha1.HeaderManipulationAction) {
	if hm == nil {
		return
	}
	for i := range hm.Set {
		hm.Set[i].Value = strings.ReplaceAll(hm.Set[i].Value, "{{", `{{"{{"}}`)
	}
}
