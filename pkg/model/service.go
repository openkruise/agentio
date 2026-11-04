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
	"slices"
)

// AppProtocol is the small application-protocol subset represented by the
// current WDS Service wire contract.
type AppProtocol string

const (
	AppProtocolUnknown AppProtocol = ""
	AppProtocolHTTP11  AppProtocol = "HTTP11"
	AppProtocolHTTP2   AppProtocol = "HTTP2"
	AppProtocolGRPC    AppProtocol = "GRPC"
)

type ServicePort struct {
	Name           string
	Port           uint32
	TargetPortName string
	TargetPort     uint32
	Protocol       string
	AppProtocol    AppProtocol
}

// TrafficDistribution is the topology routing preference expressed by a
// Service, mirroring Agentio's model.TrafficDistribution.
type TrafficDistribution int

const (
	// TrafficDistributionAny allows any destination.
	TrafficDistributionAny TrafficDistribution = iota
	// TrafficDistributionPreferSameZone prefers same-zone endpoints, failing
	// over to same region and then network.
	TrafficDistributionPreferSameZone
	// TrafficDistributionPreferSameNode prefers same-node endpoints, failing
	// over to same subzone, zone, region, and network.
	TrafficDistributionPreferSameNode
)

// IPFamilies is the address-family subset served by a Service.
type IPFamilies int

const (
	IPFamiliesAutomatic IPFamilies = iota
	IPFamiliesIPv4Only
	IPFamiliesIPv6Only
	IPFamiliesDual
)

// Service is a networking-only name, address, and port definition. Service
// membership is never identity evidence and policies do not attach to it.
type Service struct {
	Namespace string
	Name      string
	Hostname  string
	Network   string
	Addresses []string
	Ports     []ServicePort
	// InternalTrafficPolicyLocal restricts routing to same-node endpoints
	// (Kubernetes spec.internalTrafficPolicy=Local).
	InternalTrafficPolicyLocal bool
	// TrafficDistribution is the topology preference for endpoint selection.
	TrafficDistribution TrafficDistribution
	// IPFamilies is the address-family subset served by this Service.
	IPFamilies IPFamilies
	// PublishNotReadyAddresses makes unready endpoints eligible for this
	// Service's routing membership.
	PublishNotReadyAddresses bool
	// Canonical marks the authoritative Service definition for its hostname.
	Canonical bool
}

func (s Service) ResourceName() string {
	return s.Namespace + "/" + s.Hostname
}

// Equals compares all fields, preserving the distinction between nil and empty collections.
func (s Service) Equals(other Service) bool {
	return s.Namespace == other.Namespace &&
		s.Name == other.Name &&
		s.Hostname == other.Hostname &&
		s.Network == other.Network &&
		s.InternalTrafficPolicyLocal == other.InternalTrafficPolicyLocal &&
		s.TrafficDistribution == other.TrafficDistribution &&
		s.IPFamilies == other.IPFamilies &&
		s.PublishNotReadyAddresses == other.PublishNotReadyAddresses &&
		s.Canonical == other.Canonical &&
		(s.Addresses == nil) == (other.Addresses == nil) &&
		slices.Equal(s.Addresses, other.Addresses) &&
		(s.Ports == nil) == (other.Ports == nil) &&
		slices.Equal(s.Ports, other.Ports)
}

// Endpoint relates a Service to a reachable network target. Runtime
// targetRefs are routing inputs only; they never establish Attester authority.
// Serving preserves readiness independently of publishNotReadyAddresses.
type Endpoint struct {
	ServiceKey      string
	SourceKey       string
	Address         string
	PortName        string
	Port            uint32
	Protocol        string
	Ready           bool
	Serving         bool
	Terminating     bool
	Zone            string
	HasTargetRef    bool
	TargetKind      string
	TargetUID       string
	TargetName      string
	TargetNamespace string
}

func (e Endpoint) ResourceName() string {
	var name string
	if e.SourceKey != "" {
		name = fmt.Sprintf("%s/%s/%s:%d", e.ServiceKey, e.SourceKey, e.Address, e.Port)
	} else {
		name = fmt.Sprintf("%s/%s:%d", e.ServiceKey, e.Address, e.Port)
	}
	if e.PortName != "" || e.Protocol != "" {
		name += "/port/" + e.PortName + "/" + e.Protocol
	}
	if e.HasTargetRef {
		name += "/target/" + e.TargetKind + "/" + e.TargetNamespace + "/" + e.TargetName + "/" + e.TargetUID
	}
	return name
}

func (e Endpoint) Equals(other Endpoint) bool {
	return e == other
}
