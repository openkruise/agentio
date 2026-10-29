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

// Package policystatus reports configuration validation independently of delivery.
package policystatus

import (
	"reflect"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/openkruise/agentio/pkg/krt"
	kubernetesregistry "github.com/openkruise/agentio/pkg/registry/kubernetes"
)

type source struct {
	Metadata metav1.ObjectMeta
	Kind     string
	Resource string
	Profile  *agentsv1alpha1.SecurityProfileSpec
	Traffic  *agentsv1alpha1.TrafficPolicySpec
}

func (s source) ResourceName() string {
	return s.Resource + "/" + s.Metadata.Namespace + "/" + s.Metadata.Name
}
func (s source) Equals(other source) bool { return reflect.DeepEqual(s, other) }
func (s source) gvr() schema.GroupVersionResource {
	return schema.GroupVersionResource{Group: "agents.kruise.io",
		Version:  "v1alpha1",
		Resource: s.Resource}
}

// Project only validation inputs: a status write must not rerun CEL/template compilation.
func policySource(meta metav1.ObjectMeta, kind, resource string,
	profile *agentsv1alpha1.SecurityProfileSpec, traffic *agentsv1alpha1.TrafficPolicySpec,
) *source {
	return &source{
		Metadata: metav1.ObjectMeta{Name: meta.Name,
			Namespace:         meta.Namespace,
			UID:               meta.UID,
			Generation:        meta.Generation,
			CreationTimestamp: meta.CreationTimestamp},
		Kind:     kind,
		Resource: resource,
		Profile:  profile,
		Traffic:  traffic,
	}
}

func newSources(r *kubernetesregistry.Registry, opts krt.OptionsBuilder) krt.Collection[source] {
	sp := krt.NewCollection(r.SecurityProfileObjects,
		func(_ krt.HandlerContext, p *agentsv1alpha1.SecurityProfile) *source {
			return policySource(p.ObjectMeta, "SecurityProfile", "securityprofiles", &p.Spec, nil)
		}, opts.WithName("security-profile-inputs")...)
	gsp := krt.NewCollection(r.GlobalSecurityProfileObjects,
		func(_ krt.HandlerContext, p *agentsv1alpha1.GlobalSecurityProfile) *source {
			return policySource(p.ObjectMeta, "GlobalSecurityProfile", "globalsecurityprofiles", &p.Spec, nil)
		}, opts.WithName("global-security-profile-inputs")...)
	tp := krt.NewCollection(r.TrafficPolicyObjects,
		func(_ krt.HandlerContext, p *agentsv1alpha1.TrafficPolicy) *source {
			return policySource(p.ObjectMeta, "TrafficPolicy", "trafficpolicies", nil, &p.Spec)
		}, opts.WithName("traffic-policy-inputs")...)
	gtp := krt.NewCollection(r.GlobalTrafficPolicyObjects,
		func(_ krt.HandlerContext, p *agentsv1alpha1.GlobalTrafficPolicy) *source {
			return policySource(p.ObjectMeta, "GlobalTrafficPolicy", "globaltrafficpolicies", nil, &p.Spec)
		}, opts.WithName("global-traffic-policy-inputs")...)
	return krt.JoinCollection([]krt.Collection[source]{sp, gsp, tp, gtp}, opts.WithName("inputs")...)
}

type result struct {
	Source     source
	Conditions []metav1.Condition
}

func (r result) ResourceName() string     { return r.Source.ResourceName() }
func (r result) Equals(other result) bool { return reflect.DeepEqual(r, other) }

type compiledProfile struct {
	Source   source
	Accepted metav1.Condition
}

func (p compiledProfile) ResourceName() string              { return p.Source.ResourceName() }
func (p compiledProfile) Equals(other compiledProfile) bool { return reflect.DeepEqual(p, other) }

func condition(typ string, status metav1.ConditionStatus, reason, message string, generation int64) metav1.Condition {
	return metav1.Condition{Type: typ,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: generation}
}
