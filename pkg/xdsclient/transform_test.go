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

package xdsclient

import (
	"errors"
	"testing"
	"testing/synctest"
	"time"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestTransformPublicationAndFailure(t *testing.T) {
	type projection struct{ Text string }
	calls, deletes := 0, 0
	failure := errors.New("invalid projected value")
	type change struct {
		name    string
		current *Resource
		err     error
	}
	var changes []change
	watch := Watch{
		TypeURL:  testType,
		Wildcard: true,
		OnChange: func(name string, current *Resource, err error) {
			changes = append(changes, change{name, current, err})
		},
		OnDelete: func(string) DeleteAction {
			deletes++
			return ReleaseSubscription
		},
		Transform: func(wire *anypb.Any) (any, error) {
			calls++
			value := &wrapperspb.StringValue{}
			if err := wire.UnmarshalTo(value); err != nil {
				return nil, err
			}
			if value.Value == "bad" {
				return nil, failure
			}
			return &projection{Text: value.Value}, nil
		},
	}
	withSubscriptionClient(t, watch, func(t *testing.T, client *Client) {
		publishString(t, client, "a", "one")
		before := client.Snapshot()
		first := before.Resources[testType]["a"]
		if _, ok := first.Value.(*projection); !ok {
			t.Fatalf("raw payload cached: %T", first.Value)
		}
		for range 3 {
			value, err := client.Demand(t.Context(), testType, "a")
			if err != nil || value != first {
				t.Fatal(value, err)
			}
		}
		if calls != 1 {
			t.Fatal("transform ran during demand")
		}
		if len(changes) != 1 || changes[0].current != first || changes[0].err != nil {
			t.Fatal("accepted publication was not observed", changes)
		}
		publishString(t, client, "a", "two")
		if first.Value.(*projection).Text != "one" {
			t.Fatal("prior publication mutated")
		}
		good, err := anypb.New(wrapperspb.String("new"))
		if err != nil {
			t.Fatal(err)
		}
		bad, err := anypb.New(wrapperspb.String("bad"))
		if err != nil {
			t.Fatal(err)
		}
		changes = nil
		if err := client.apply(&discovery.DeltaDiscoveryResponse{TypeUrl: testType,
			Resources:        []*discovery.Resource{{Name: "b", Resource: good}, {Name: "c", Resource: bad}},
			RemovedResources: []string{"a"},
		}); !errors.Is(err, failure) {
			t.Fatal(err)
		}
		if len(changes) != 1 || changes[0].name != "c" || changes[0].current != nil ||
			!errors.Is(changes[0].err, failure) {
			t.Fatal("rejected batch reported a commit or lost the failed resource", changes)
		}
		after := client.Snapshot()
		if !after.Synced[testType] || len(after.Resources[testType]) != 1 ||
			after.Resources[testType]["a"].Value.(*projection).Text != "two" ||
			deletes != 0 {
			t.Fatal("failed transform partially published or released subscription")
		}
		publishString(t, client, "a", "recovered")
		if _, ready := client.Observe(testType); !ready {
			t.Fatal("valid update did not recover")
		}
	})
}

func TestResourceChangesIncludeRejectedUpdatesAndRemoval(t *testing.T) {
	var current *Resource
	var rejected error
	changes := 0
	watch := Watch{
		TypeURL:        testType,
		ReconnectGrace: time.Second,
		OnDelete:       func(string) DeleteAction { return ReleaseSubscription },
		OnChange: func(_ string, value *Resource, err error) {
			current, rejected = value, err
			changes++
		},
		Transform: func(wire *anypb.Any) (any, error) {
			value := &wrapperspb.StringValue{}
			if err := wire.UnmarshalTo(value); err != nil {
				return nil, err
			}
			if value.Value == "bad" {
				return nil, errors.New("invalid")
			}
			return value, nil
		},
	}
	withSubscriptionClient(t, watch, func(t *testing.T, client *Client) {
		for _, removal := range []string{"delete", "release", "grace"} {
			lease, err := client.Acquire(testType, "a")
			if err != nil {
				t.Fatal(err)
			}
			publishString(t, client, "a", "good")
			accepted := current
			bad, err := anypb.New(wrapperspb.String("bad"))
			if err != nil {
				t.Fatal(err)
			}
			if err := client.apply(
				&discovery.DeltaDiscoveryResponse{
					TypeUrl:   testType,
					Resources: []*discovery.Resource{{Name: "a", Resource: bad}},
				},
			); err == nil {
				t.Fatal("bad update accepted")
			}
			if current != accepted || rejected == nil {
				t.Fatal("rejection lost retained resource")
			}
			before := changes
			switch removal {
			case "delete":
				removeNames(t, client, "a")
			case "release":
				lease.Release()
			case "grace":
				client.reset()
				time.Sleep(2 * time.Second)
				synctest.Wait()
			}
			if changes <= before || current != nil || rejected != nil {
				t.Fatalf("%s did not clear resource state", removal)
			}
			lease.Release()
		}
		lease, err := client.Acquire(testType, "first-invalid")
		if err != nil {
			t.Fatal(err)
		}
		bad, err := anypb.New(wrapperspb.String("bad"))
		if err != nil {
			t.Fatal(err)
		}
		if err := client.apply(
			&discovery.DeltaDiscoveryResponse{
				TypeUrl:   testType,
				Resources: []*discovery.Resource{{Name: "first-invalid", Resource: bad}},
			},
		); err == nil {
			t.Fatal("bad first version accepted")
		}
		if current != nil || rejected == nil {
			t.Fatal("first rejection not observed")
		}
		lease.Release()
		if current != nil || rejected != nil {
			t.Fatal("eviction retained failed first version")
		}
	})
}

func TestRejectedAliasLifecycle(t *testing.T) {
	for _, action := range []string{"release", "shared-release", "recover", "replace", "remove"} {
		t.Run(action, func(t *testing.T) {
			rejected := map[string]error{}
			watch := Watch{
				TypeURL: testType,
				OnChange: func(name string, _ *Resource, err error) {
					if err != nil {
						rejected[name] = err
					} else {
						delete(rejected, name)
					}
				},
				Transform: func(wire *anypb.Any) (any, error) {
					value := &wrapperspb.StringValue{}
					if err := wire.UnmarshalTo(value); err != nil {
						return nil, err
					}
					if value.Value == "bad" {
						return nil, errors.New("invalid")
					}
					return value, nil
				},
			}
			withSubscriptionClient(t, watch, func(t *testing.T, client *Client) {
				lease, err := client.Acquire(testType, "ns/pod")
				if err != nil {
					t.Fatal(err)
				}
				defer lease.Release()
				var other *Subscription
				if action == "shared-release" {
					other, err = client.Acquire(testType, "uid")
					if err != nil {
						t.Fatal(err)
					}
					defer other.Release()
				}
				bad, err := anypb.New(wrapperspb.String("bad"))
				if err != nil {
					t.Fatal(err)
				}
				if err := client.apply(&discovery.DeltaDiscoveryResponse{
					TypeUrl:   testType,
					Resources: []*discovery.Resource{{Name: "uid", Aliases: []string{"ns/pod"}, Resource: bad}},
				}); err == nil {
					t.Fatal("invalid aliased resource accepted")
				}
				if len(rejected) != 1 || rejected["uid"] == nil {
					t.Fatal("canonical rejection not observed", rejected)
				}
				st := client.types[testType]
				if len(st.resources) != 0 || len(st.aliases) != 0 || len(st.resourceAliases) != 0 {
					t.Fatal("NACK published candidate data or aliases")
				}
				switch action {
				case "release":
					lease.Release()
				case "shared-release":
					lease.Release()
					if rejected["uid"] == nil {
						t.Fatal("alias release cleared a rejection still watched by UID")
					}
					other.Release()
				case "recover":
					publishString(t, client, "uid", "good", "ns/pod")
				case "replace":
					publishString(t, client, "replacement", "good", "ns/pod")
				case "remove":
					removeNames(t, client, "ns/pod")
				}
				if len(rejected) != 0 {
					t.Fatal("unavailable candidate retained its rejection", rejected)
				}
				if len(st.rejectedInterests) != 0 || len(lease.generation.rejected) != 0 {
					t.Fatal("rejection interest tracking survived cleanup")
				}
			})
		})
	}
}
