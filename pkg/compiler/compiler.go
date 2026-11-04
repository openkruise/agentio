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

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/policy"
)

type Inputs struct {
	// SandboxMode enables Sandbox resources and their Sandbox policies.
	// Shared system policies remain on Workload resources in both modes.
	SandboxMode   bool
	ClusterID     string
	RootNamespace string

	Pods               krt.Collection[*corev1.Pod]
	KubernetesServices krt.Collection[*corev1.Service]
	EndpointSlices     krt.Collection[*discoveryv1.EndpointSlice]
	ConfigMaps         krt.Collection[*corev1.ConfigMap]
	Secrets            krt.Collection[*corev1.Secret]

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

	Resolve            policy.HostnameResolver
	DiscoveryAddress   string
	TrustDomain        string
	GatewayTrustBundle string
}

// Compiler turns registry state into an xDS snapshot. The derived collections
// are built once, in New, and maintained incrementally.
type Compiler struct {
	graph    *graph
	failures *failureRecorder
}

func New(inputs Inputs, options krt.OptionsBuilder) (*Compiler, error) {
	if options.Stop() == nil {
		return nil, fmt.Errorf("KRT stop channel is required")
	}
	if !inputs.SandboxMode {
		inputs.Sandboxes = krt.NewStaticCollection[model.Sandbox](nil, nil, options.WithName("disabled-sandboxes")...)
	}
	if inputs.Sandboxes == nil || inputs.Workloads == nil || inputs.Pods == nil || inputs.KubernetesServices == nil ||
		inputs.EndpointSlices == nil || inputs.ConfigMaps == nil || inputs.Secrets == nil ||
		inputs.Services == nil || inputs.Endpoints == nil ||
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
	built := buildGraph(inputs, failures, options)
	return &Compiler{graph: built, failures: failures}, nil
}

// HasSynced reports whether the derived collections have processed the state present when they were created; do not publish a snapshot before this is true.
func (c *Compiler) HasSynced() bool {
	return c.graph.resources.HasSynced()
}

// WaitUntilSynced blocks until the derived collections are populated, or until
// stop is closed. It reports whether syncing completed.
func (c *Compiler) WaitUntilSynced(stop <-chan struct{}) bool {
	return c.graph.resources.WaitUntilSynced(stop)
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

// Bindings exposes shared policy selections keyed by Workload UID.
func (c *Compiler) Bindings() krt.Collection[policy.Bindings] {
	return c.graph.policies.policyBindings
}

// PolicyNames returns the shared policy names bound to the given Workload.
func (c *Compiler) PolicyNames(workloadUID string, kind model.PolicyKind) []string {
	binding := c.graph.policies.policyBindings.GetKey(workloadUID)
	if binding == nil {
		return nil
	}
	return append([]string(nil), binding.PolicyNames(kind)...)
}

// Failures returns the objects that currently fail to compile, keyed by
// "kind/name". A failed update may retain the previous valid output or withdraw
// the resource, depending on the compilation stage.
func (c *Compiler) Failures() map[string]string {
	return c.failures.snapshot()
}

func (c *Compiler) Snapshot() (model.ResourceSet, error) {
	return model.NewResourceSet(c.graph.resources.List())
}
