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

package api_test

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	sandboxv1 "github.com/openkruise/agentio/api/sandbox/v1"
	securityv1 "github.com/openkruise/agentio/api/security/v1"
	workloadv1 "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/pkg/model"
)

func TestWireMessageNamesAndTypeURLs(t *testing.T) {
	cases := []struct {
		message proto.Message
		want    string
	}{
		{&sandboxv1.Sandbox{}, "agentio.sandbox.Sandbox"},
		{&securityv1.TrafficPolicy{}, "agentio.security.TrafficPolicy"},
		{&workloadv1.Address{}, "istio.workload.Address"},
		{&workloadv1.Workload{}, "istio.workload.Workload"},
		// Control-plane-only configuration decoded from ConfigMap YAML by
		// field name; its package is not a wire contract.
		{&configv1.AgentioConfig{}, "agentio.config.v1.AgentioConfig"},
		{&configv1.EgressServiceEntry{}, "agentio.config.v1.EgressServiceEntry"},
		{&configv1.EgressServiceEntryEndpoint{}, "agentio.config.v1.EgressServiceEntryEndpoint"},
		// EgressPolicies is packed with anypb into Workload.Extensions
		// (pkg/compiler/wds.go), so its full name is a wire contract.
		{&extensionsv1.EgressPolicies{}, "agentio.extensions.EgressPolicies"},
		{&extensionsv1.EgressPolicy{}, "agentio.extensions.EgressPolicy"},
		{&extensionsv1.TrafficPolicyExtension{}, "agentio.extensions.TrafficPolicyExtension"},
		{&extensionsv1.WorkloadMetadata{}, "agentio.extensions.WorkloadMetadata"},
		{&extensionsv1.PolicyReference{}, "agentio.extensions.PolicyReference"},
		{&extensionsv1.PolicyResourceReference{}, "agentio.extensions.PolicyResourceReference"},
		{&extensionsv1.SniTrafficPolicy{}, "agentio.extensions.SniTrafficPolicy"},
	}

	for _, tc := range cases {
		name := string(tc.message.ProtoReflect().Descriptor().FullName())
		if name != tc.want {
			t.Errorf("message full name = %q, want %q", name, tc.want)
		}
		value, err := anypb.New(tc.message)
		if err != nil {
			t.Fatal(err)
		}
		typeURL := value.TypeUrl
		wantTypeURL := "type.googleapis.com/" + tc.want
		if typeURL != wantTypeURL {
			t.Errorf("type URL = %q, want %q", typeURL, wantTypeURL)
		}
	}
}

// The Authorization descriptor extends Istio's istio.security namespace with
// Agentio fields, so it lives in agentio.security to avoid a protobuf
// global-registry conflict with upstream istio.io/istio (see
// api/security/v1/authorization.proto). Its wire type URL stays
// type.googleapis.com/istio.security.Authorization: pkg/model pins the
// constant and the compiler builds the Any explicitly rather than deriving
// the URL from the descriptor.
func TestAuthorizationDescriptorIsRenamedOffTheWireNamespace(t *testing.T) {
	name := string((&securityv1.Authorization{}).ProtoReflect().Descriptor().FullName())
	if name != "agentio.security.Authorization" {
		t.Errorf("Authorization full name = %q, want %q", name, "agentio.security.Authorization")
	}
	if model.WorkloadAuthorizationType != "type.googleapis.com/istio.security.Authorization" {
		t.Errorf("WorkloadAuthorizationType = %q, want %q",
			model.WorkloadAuthorizationType, "type.googleapis.com/istio.security.Authorization")
	}
}

func TestSandboxDescriptorMatchesDiscoveryTypeURL(t *testing.T) {
	value, err := anypb.New(&sandboxv1.Sandbox{})
	if err != nil {
		t.Fatal(err)
	}
	if value.TypeUrl != model.SandboxType {
		t.Fatalf("Sandbox Any type URL = %q, discovery type URL = %q", value.TypeUrl, model.SandboxType)
	}
}
