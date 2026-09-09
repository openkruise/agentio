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
	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

// Reference is one policy/config object's use of a hostname. Owner is part of
// the key so multiple objects can retain the same DNS result independently.
type Reference struct {
	Owner    string
	Hostname string
}

func (r Reference) ResourceName() string { return r.Owner + "/" + r.Hostname }

func (r Reference) Equals(other Reference) bool {
	return r.Owner == other.Owner && r.Hostname == other.Hostname
}

// NewReferences extracts every hostname used by TrafficPolicy or AgentioConfig
// into a krt collection.
func NewReferences(
	trafficPolicies krt.Collection[model.TrafficPolicy],
	configurations krt.Collection[model.AgentioConfiguration],
	options ...krt.CollectionOption,
) krt.Collection[Reference] {
	traffic := krt.NewManyCollection(trafficPolicies, func(_ krt.HandlerContext, policy model.TrafficPolicy) []Reference {
		return trafficPolicyReferences(policy)
	}, namedOptions(options, "dns-traffic-policy-references")...)
	config := krt.NewManyCollection(configurations, func(_ krt.HandlerContext, configuration model.AgentioConfiguration) []Reference {
		return configurationReferences(configuration)
	}, namedOptions(options, "dns-agentio-config-references")...)
	return krt.JoinCollection([]krt.Collection[Reference]{traffic, config}, namedOptions(options, "dns-references")...)
}

// Track retains DNS entries for the lifetime of their source references.
func (r *Resolver) Track(events krt.EventStream[Reference]) krt.HandlerRegistration {
	return events.Register(func(event krt.Event[Reference]) {
		if event.Old != nil {
			r.HandleDelete(event.Old.Hostname)
		}
		if event.New != nil {
			r.HandleAdd(event.New.Hostname)
		}
	})
}

func trafficPolicyReferences(policy model.TrafficPolicy) []Reference {
	hosts := sets.New[string]()
	collectPeers := func(peers []agentsv1alpha1.TrafficPolicyPeer) {
		for _, peer := range peers {
			if normalized := normalizeHostname(peer.FQDN); normalized != "" {
				hosts.Insert(normalized)
			}
		}
	}
	collectDirection := func(direction *agentsv1alpha1.TrafficPolicyDirection) {
		if direction == nil {
			return
		}
		for _, rule := range direction.Rules {
			collectPeers(rule.From)
			collectPeers(rule.To)
		}
	}
	collectDirection(policy.Spec.Egress)
	collectDirection(policy.Spec.Ingress)
	return referencesFor(policy.ResourceName(), hosts)
}

func configurationReferences(configuration model.AgentioConfiguration) []Reference {
	hosts := sets.New[string]()
	for _, policy := range configuration.Value.GetEgressPolicies() {
		for _, host := range policy.GetMatchHosts() {
			if normalized := normalizeHostname(host); normalized != "" {
				hosts.Insert(normalized)
			}
		}
	}
	return referencesFor("agentio-config/"+configuration.ResourceName(), hosts)
}

func referencesFor(owner string, hosts sets.Set[string]) []Reference {
	result := make([]Reference, 0, len(hosts))
	for host := range hosts {
		result = append(result, Reference{Owner: owner, Hostname: host})
	}
	return result
}

func namedOptions(options []krt.CollectionOption, name string) []krt.CollectionOption {
	result := append([]krt.CollectionOption(nil), options...)
	return append(result, krt.WithName(name))
}
