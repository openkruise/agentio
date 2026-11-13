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

package xds

import (
	"slices"
	"testing"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	sandboxv1 "github.com/openkruise/agentio/api/sandbox/v1"
	workloadv1 "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/pkg/model"
)

func TestSecurityProfileReferencesDeltaDelivery(t *testing.T) {
	for _, typeURL := range []string{model.AddressType, model.WorkloadType, model.SandboxType} {
		t.Run(typeURL, func(t *testing.T) {
			base := addressResource(t, "client", "client")
			if typeURL == model.SandboxType {
				base = sandboxResourceWithAttester(t, "client", "worker")
			}
			resourceWithRefs := func(names ...string) model.Resource {
				t.Helper()
				reference := mustAny(&extensionsv1.PolicyReference{
					TypeUrl:   model.SecurityProfileType,
					Resources: policyResources(names...),
				})
				var value *anypb.Any
				if typeURL == model.SandboxType {
					value = mustAny(
						&sandboxv1.Sandbox{
							Uid:        "client",
							Attester:   &sandboxv1.Sandbox_Attester{WorkloadUid: "worker"},
							Extensions: []*anypb.Any{reference},
						},
					)
				} else {
					value = mustAny(
						&workloadv1.Address{Type: &workloadv1.Address_Workload{Workload: &workloadv1.Workload{
							Uid: "client",
							Extensions: []*workloadv1.Extension{
								{Name: "security-profile-reference", Config: reference},
							},
						}}},
					)
				}
				resource, err := model.NewResource(
					base.Key,
					base.XDSName,
					testResourceContents(value),
					base.Aliases,
					base.Facts,
				)
				if err != nil {
					t.Fatal(err)
				}
				return resource
			}
			name := "namespaced/demo/profile"
			if typeURL == model.SandboxType {
				name = "sandboxes/client/securityProfiles/inline"
			}
			ctx := t.Context()
			server := newTestServer(t, gatewayScope(), []model.Resource{resourceWithRefs(name)}, nil)
			stream := newFakeStream(ctx, 8)
			done := server.start(stream)
			request := nodeRequest(typeURL)
			request.ResourceNamesSubscribe = []string{"client"}
			stream.send(request)
			assertRefs := func(response *discoveryv3.DeltaDiscoveryResponse, want ...string) {
				t.Helper()
				if len(response.Resources) != 1 {
					t.Fatalf("resources: %v", response)
				}
				value := response.Resources[0].Resource
				var config *anypb.Any
				switch typeURL {
				case model.SandboxType:
					sandbox := &sandboxv1.Sandbox{}
					if err := value.UnmarshalTo(sandbox); err != nil {
						t.Fatal(err)
					}
					if len(sandbox.Extensions) != 1 {
						t.Fatalf("Sandbox extensions: %v", sandbox.Extensions)
					}
					config = sandbox.Extensions[0]
				default:
					workload := &workloadv1.Workload{}
					if typeURL == model.AddressType {
						address := &workloadv1.Address{}
						if err := value.UnmarshalTo(address); err != nil {
							t.Fatal(err)
						}
						workload = address.GetWorkload()
					} else if err := value.UnmarshalTo(workload); err != nil {
						t.Fatal(err)
					}
					if len(workload.GetExtensions()) != 1 {
						t.Fatalf("Workload extensions: %v", workload)
					}
					config = workload.Extensions[0].Config
				}
				refs := &extensionsv1.PolicyReference{}
				if err := config.UnmarshalTo(refs); err != nil {
					t.Fatal(err)
				}
				if !proto.Equal(
					refs,
					&extensionsv1.PolicyReference{
						TypeUrl:   model.SecurityProfileType,
						Resources: policyResources(want...),
					},
				) {
					t.Fatalf("references %v, want type %s and names %v", refs, model.SecurityProfileType, want)
				}
			}
			first := stream.awaitResponses(t, typeURL, 1)[0]
			assertRefs(first, name)
			stream.send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: typeURL, ResponseNonce: first.Nonce})
			server.resources.publish(selectionSnapshot(t, []model.Resource{resourceWithRefs()}))
			second := stream.awaitResponses(t, typeURL, 2)[1]
			assertRefs(second)
			if first.Resources[0].Version == second.Resources[0].Version {
				t.Fatal("binding removal did not change resource version")
			}
			stream.send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: typeURL, ResponseNonce: second.Nonce})
			server.resources.publish(selectionSnapshot(t, nil))
			third := stream.awaitResponses(t, typeURL, 3)[2]
			if !slices.Equal(third.RemovedResources, []string{"client"}) {
				t.Fatalf("resource deletion: %v", third)
			}
			if err := server.finish(t, stream, done); err != nil {
				t.Fatal(err)
			}
		})
	}
}
