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

package compiler

import (
	"fmt"

	"google.golang.org/protobuf/proto"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"

	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/policy"
)

type Inputs struct {
	ClusterID     string
	RootNamespace string

	Pods               krt.Collection[*corev1.Pod]
	KubernetesServices krt.Collection[*corev1.Service]
	EndpointSlices     krt.Collection[*discoveryv1.EndpointSlice]

	Sandboxes krt.Collection[model.Sandbox]
	Workloads krt.Collection[model.Workload]
	Services  krt.Collection[model.Service]
	Endpoints krt.Collection[model.Endpoint]
	Gateways  krt.Collection[model.Gateway]

	TrafficPolicies            krt.Collection[model.TrafficPolicy]
	SecurityProfiles           krt.Collection[model.SecurityProfile]
	GatewayPatches             krt.Collection[model.GatewayPatch]
	Telemetry                  krt.Collection[model.Telemetry]
	TelemetryProviderOverrides krt.Singleton[model.TelemetryProviderOverrides]

	AgentioConfig krt.Collection[model.AgentioConfiguration]

	Resolve          policy.HostnameResolver
	DiscoveryAddress string
	TrustDomain      string
}

// Compiler turns registry state into an xDS snapshot. The derived collections
// are built once, in New, and maintained incrementally.
type Compiler struct {
	inputs   Inputs
	graph    *graph
	failures *failureRecorder
}

func New(inputs Inputs, options krt.OptionsBuilder) (*Compiler, error) {
	if options.Stop() == nil {
		return nil, fmt.Errorf("KRT stop channel is required")
	}
	if inputs.Sandboxes == nil || inputs.Workloads == nil || inputs.Pods == nil || inputs.KubernetesServices == nil ||
		inputs.EndpointSlices == nil || inputs.Services == nil || inputs.Endpoints == nil ||
		inputs.Gateways == nil || inputs.TrafficPolicies == nil || inputs.SecurityProfiles == nil {
		return nil, fmt.Errorf("all compiler input collections are required")
	}
	if inputs.GatewayPatches == nil {
		return nil, fmt.Errorf("GatewayPatch collection is required")
	}
	if inputs.Telemetry == nil {
		return nil, fmt.Errorf("Telemetry collection is required")
	}
	if inputs.TelemetryProviderOverrides == nil {
		return nil, fmt.Errorf("Telemetry provider override singleton is required")
	}
	if inputs.AgentioConfig == nil {
		return nil, fmt.Errorf("Agentio configuration collection is required")
	}
	failures := newFailureRecorder()
	built, err := buildGraph(inputs, failures, options)
	if err != nil {
		return nil, err
	}
	return &Compiler{inputs: inputs, graph: built, failures: failures}, nil
}

// HasSynced reports whether the derived collections have processed the state present when they were created; do not publish a snapshot before this is true.
func (c *Compiler) HasSynced() bool {
	return c.graph.resources.HasSynced() && c.graph.policies.sandboxSNIPolicies.HasSynced()
}

// WaitUntilSynced blocks until the derived collections are populated, or until
// stop is closed. It reports whether syncing completed.
func (c *Compiler) WaitUntilSynced(stop <-chan struct{}) bool {
	return c.graph.resources.WaitUntilSynced(stop) && c.graph.policies.sandboxSNIPolicies.WaitUntilSynced(stop)
}

// Resources exposes the compiled resource event stream.
func (c *Compiler) Resources() krt.EventStream[model.Resource] {
	return c.graph.resources
}

// Gateways exposes the conflict-merged declarations accepted by the semantic
// configuration graph. Authorization and generation must consume this same
// last-known-good view.
func (c *Compiler) Gateways() krt.Collection[model.Gateway] {
	return c.graph.gateways
}

// SandboxPolicyBindings exposes the payload-free policy binding projection per Sandbox.
func (c *Compiler) SandboxPolicyBindings() krt.Collection[policy.SandboxPolicyBindings] {
	return c.graph.policies.sandboxBindings
}

// PolicyNames returns the policy names bound to the given Sandbox UID.
func (c *Compiler) PolicyNames(sandboxUID string, kind model.PolicyKind) []string {
	binding := c.graph.policies.sandboxBindings.GetKey(sandboxUID)
	if binding == nil || !binding.Valid() {
		return nil
	}
	return append([]string(nil), binding.PolicyNames(kind)...)
}

// Failures returns the objects that currently fail to compile, keyed by
// "kind/name". A failing object is omitted from the snapshot while the rest of
// the configuration continues to be published.
func (c *Compiler) Failures() map[string]string {
	return c.failures.snapshot()
}

func (c *Compiler) Snapshot() (model.ResourceSet, error) {
	return model.NewResourceSet(c.graph.resources.List())
}

// SandboxSNIPolicies exposes inline payload changes, including rules-only edits.
func (c *Compiler) SandboxSNIPolicies() krt.Collection[SandboxSNIPolicy] {
	return c.graph.policies.sandboxSNIPolicies
}

// SNIPolicy returns a private copy of the complete payload for one Sandbox.
func (c *Compiler) SNIPolicy(uid string) *extensionsv1.SniTrafficPolicy {
	current := c.graph.policies.sandboxSNIPolicies.GetKey(uid)
	if current == nil {
		return nil
	}
	return proto.Clone(current.Policy).(*extensionsv1.SniTrafficPolicy)
}
