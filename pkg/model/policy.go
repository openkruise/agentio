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

package model

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
)

// PolicyKind identifies an independently stored shared policy family.
type PolicyKind string

// Supported shared policy families.
const (
	PolicyKindTrafficPolicy   PolicyKind = "traffic-policy"
	PolicyKindEgressPolicy    PolicyKind = "egress-policy"
	PolicyKindSecurityProfile PolicyKind = "security-profile"
)

// PolicyRef identifies a shared policy by family and resource name.
type PolicyRef struct {
	Kind PolicyKind
	Name string
}

// ResourceName returns the collection key for this policy reference.
func (r PolicyRef) ResourceName() string { return string(r.Kind) + "|" + r.Name }

// Validate checks that the reference has a supported family and a nonempty name.
func (r PolicyRef) Validate() error {
	switch r.Kind {
	case PolicyKindTrafficPolicy, PolicyKindEgressPolicy, PolicyKindSecurityProfile:
	default:
		return fmt.Errorf("unsupported policy kind %q", r.Kind)
	}
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("%s policy name is required", r.Kind)
	}
	return nil
}

// TrafficPolicyRules carries source rules without selection or priority metadata.
// Empty directions and rules without the direction's peers are ignored, as in Poseidon.
// Declared peers that resolve to no addresses still configure default deny.
type TrafficPolicyRules struct {
	Ingress *agentsv1alpha1.TrafficPolicyDirection
	Egress  *agentsv1alpha1.TrafficPolicyDirection
}

type TrafficPolicy struct {
	UID          string
	Name         string
	Namespace    string
	Global       bool
	CreationTime time.Time
	Spec         agentsv1alpha1.TrafficPolicySpec
}

// GetUID returns the source object's UID.
func (p TrafficPolicy) GetUID() types.UID { return types.UID(p.UID) }

func (p TrafficPolicy) ResourceName() string {
	if p.Global {
		return "global/" + p.Name
	}
	return "namespaced/" + p.Namespace + "/" + p.Name
}

func (p TrafficPolicy) Equals(other TrafficPolicy) bool {
	return p.UID == other.UID && p.Name == other.Name &&
		p.Namespace == other.Namespace &&
		p.Global == other.Global &&
		p.CreationTime.Equal(other.CreationTime) &&
		reflect.DeepEqual(p.Spec, other.Spec)
}

type SecurityProfile struct {
	UID          string
	Name         string
	Namespace    string
	Global       bool
	CreationTime time.Time
	Spec         agentsv1alpha1.SecurityProfileSpec
}

// GetUID returns the source object's UID.
func (p SecurityProfile) GetUID() types.UID { return types.UID(p.UID) }

func (p SecurityProfile) ResourceName() string {
	if p.Global {
		return "global/" + p.Name
	}
	return "namespaced/" + p.Namespace + "/" + p.Name
}

func (p SecurityProfile) Equals(other SecurityProfile) bool {
	return p.UID == other.UID &&
		p.Name == other.Name &&
		p.Namespace == other.Namespace &&
		p.Global == other.Global &&
		p.CreationTime.Equal(other.CreationTime) &&
		reflect.DeepEqual(p.Spec, other.Spec)
}
