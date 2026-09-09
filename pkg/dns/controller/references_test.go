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

package controller

import (
	"context"
	"github.com/openkruise/agentio/pkg/dns"
	"net/netip"
	"testing"
	"time"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

var _ func(*Resolver, krt.EventStream[Reference]) krt.HandlerRegistration = (*Resolver).Track

func TestReferencesRetainSharedHostnameUntilLastOwnerIsDeleted(t *testing.T) {
	ctx := t.Context()
	options := []krt.CollectionOption{krt.WithStop(ctx.Done())}
	policies := krt.NewStaticCollection[model.TrafficPolicy](nil, nil, options...)
	configurations := krt.NewStaticCollection[model.AgentioConfiguration](nil, nil, options...)
	references := NewReferences(policies, configurations, options...)
	resolver, err := New(ctx, Options{RefreshInterval: time.Hour}, func(context.Context, string) (dns.LookupResult, error) {
		return dns.LookupResult{Addresses: []netip.Addr{netip.MustParseAddr("203.0.113.7")}}, nil
	}, options...)
	if err != nil {
		t.Fatal(err)
	}
	registration := resolver.Track(references)
	defer registration.UnregisterHandler()

	policies.ConditionalUpdateObject(model.TrafficPolicy{
		Name: "api", Namespace: "demo",
		Spec: agentsv1alpha1.TrafficPolicySpec{Egress: &agentsv1alpha1.TrafficPolicyDirection{
			Rules: []agentsv1alpha1.TrafficPolicyRule{{
				From: []agentsv1alpha1.TrafficPolicyPeer{{FQDN: "API.EXAMPLE.COM."}},
				To:   []agentsv1alpha1.TrafficPolicyPeer{{FQDN: "api.example.com"}},
			}},
		}},
	})
	configurations.ConditionalUpdateObject(model.AgentioConfiguration{Value: &configv1.AgentioConfig{
		EgressPolicies: []*extensionsv1.EgressPolicy{{MatchHosts: []string{"api.example.com"}}},
	}})

	eventuallyDNS(t, func() bool {
		return len(references.List()) == 2 && resolver.Results().GetKey("api.example.com") != nil
	}, "both owners retained one normalized DNS result")

	policies.DeleteObject("namespaced/demo/api")
	eventuallyDNS(t, func() bool { return len(references.List()) == 1 }, "traffic policy reference deleted")
	if resolver.Results().GetKey("api.example.com") == nil {
		t.Fatal("shared DNS result was deleted while AgentioConfig still referenced it")
	}

	configurations.DeleteObject("effective")
	eventuallyDNS(t, func() bool {
		return len(references.List()) == 0 && resolver.Results().GetKey("api.example.com") == nil
	}, "last owner released the DNS result")
}

func TestTrackUnregisterStopsEvents(t *testing.T) {
	ctx := t.Context()
	options := []krt.CollectionOption{krt.WithStop(ctx.Done())}
	references := krt.NewStaticCollection[Reference](nil, nil, options...)
	resolver, err := New(ctx, Options{RefreshInterval: time.Hour}, func(context.Context, string) (dns.LookupResult, error) {
		return dns.LookupResult{Addresses: []netip.Addr{netip.MustParseAddr("203.0.113.7")}}, nil
	}, options...)
	if err != nil {
		t.Fatal(err)
	}
	registration := resolver.Track(references)

	reference := Reference{Owner: "owner", Hostname: "api.example.com"}
	references.UpdateObject(reference)
	eventuallyDNS(t, func() bool { return resolver.Results().GetKey(reference.Hostname) != nil }, "reference event added DNS result")

	registration.UnregisterHandler()
	references.DeleteObject(reference.ResourceName())
	time.Sleep(50 * time.Millisecond)
	if resolver.Results().GetKey(reference.Hostname) == nil {
		t.Fatal("unregistered tracker handled a delete event")
	}
}

func eventuallyDNS(t testing.TB, condition func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("condition never held: %s", message)
}
