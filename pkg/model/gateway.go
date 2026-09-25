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
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"
	"k8s.io/apimachinery/pkg/util/validation"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
)

type GatewaySource string

const (
	GatewaySourceAgentioConfig  GatewaySource = "agentio-config"
	GatewaySourceGatewayAPI     GatewaySource = "gateway-api"
	GatewaySourceLegacyFallback GatewaySource = "legacy-fallback"
	GatewaySourceConflict       GatewaySource = "conflict"
)

// Gateway is one declared egress-gateway configuration. Namespace and Name
// are collection identity; Config is non-nil outside conflict values and reuses
// the transfer protobuf with its legacy identity fields cleared.
type Gateway struct {
	Namespace string
	Name      string
	Config    *configv1.EgressGateway
	Source    GatewaySource
}

func (g Gateway) ResourceName() string { return g.Namespace + "/" + g.Name }

func (g Gateway) Equals(other Gateway) bool {
	return g.Namespace == other.Namespace &&
		g.Name == other.Name &&
		g.Source == other.Source &&
		proto.Equal(g.Config, other.Config)
}

// ValidateForUse checks the normalized declaration invariants shared by
// authorization and xDS generation. Conflict values intentionally fail here.
func (g Gateway) ValidateForUse() error {
	if strings.TrimSpace(g.Namespace) == "" || strings.TrimSpace(g.Name) == "" {
		return fmt.Errorf("gateway namespace and name are required")
	}
	if g.Source == GatewaySourceConflict {
		return fmt.Errorf("gateway %s has conflicting declarations", g.ResourceName())
	}
	if g.Config == nil {
		return fmt.Errorf("gateway %s configuration is required", g.ResourceName())
	}
	if g.Config.GetName() != "" || g.Config.GetNamespace() != "" {
		return fmt.Errorf("gateway %s configuration contains source identity", g.ResourceName())
	}
	if service := g.Config.GetExtProc().GetService(); service != "" && strings.TrimSpace(service) == "" {
		return fmt.Errorf("gateway %s has a whitespace-only ext_proc service", g.ResourceName())
	}
	if err := ValidateExtProcTLS(g.Config.GetExtProc().GetTls()); err != nil {
		return fmt.Errorf("gateway %s: %w", g.ResourceName(), err)
	}
	if err := ValidateUpstreamTLS(g.Config.GetUpstreamTls()); err != nil {
		return fmt.Errorf("gateway %s: %w", g.ResourceName(), err)
	}
	if err := ValidateAccessLogFormat(g.Config.GetAccessLogFormat()); err != nil {
		return fmt.Errorf("gateway %s: %w", g.ResourceName(), err)
	}
	normalized, err := NormalizeEgressGatewayServiceEntries(g.Config)
	if err != nil {
		return fmt.Errorf("gateway %s: %w", g.ResourceName(), err)
	}
	if !proto.Equal(normalized, g.Config) {
		return fmt.Errorf("gateway %s static service entries are not normalized", g.ResourceName())
	}
	return nil
}

// NormalizeEgressGatewayServiceEntries validates and canonicalizes static
// service entries without mutating the caller's protobuf.
func NormalizeEgressGatewayServiceEntries(config *configv1.EgressGateway) (*configv1.EgressGateway, error) {
	if config == nil {
		return nil, nil
	}
	result := proto.Clone(config).(*configv1.EgressGateway)
	hosts := make(map[string]struct{})
	for serviceIndex, service := range result.GetServiceEntries() {
		field := fmt.Sprintf("serviceEntries[%d]", serviceIndex)
		if service == nil {
			return nil, fmt.Errorf("%s must not be nil", field)
		}
		if len(service.GetHosts()) == 0 {
			return nil, fmt.Errorf("%s.hosts must contain at least one host", field)
		}
		if len(service.GetEndpoints()) == 0 {
			return nil, fmt.Errorf("%s.endpoints must contain at least one endpoint", field)
		}

		addresses := make(map[string]struct{}, len(service.GetEndpoints()))
		for endpointIndex, endpoint := range service.GetEndpoints() {
			endpointField := fmt.Sprintf("%s.endpoints[%d]", field, endpointIndex)
			if endpoint == nil {
				return nil, fmt.Errorf("%s must not be nil", endpointField)
			}
			address, err := netip.ParseAddr(strings.TrimSpace(endpoint.GetAddress()))
			if err != nil || !address.Is4() {
				return nil, fmt.Errorf("%s.address must be an IPv4 address", endpointField)
			}
			canonicalAddress := address.String()
			if _, found := addresses[canonicalAddress]; found {
				return nil, fmt.Errorf("%s.address duplicates endpoint %q in the same service entry", endpointField, canonicalAddress)
			}
			addresses[canonicalAddress] = struct{}{}
			endpoint.Address = canonicalAddress
		}

		for hostIndex, value := range service.GetHosts() {
			host := strings.ToLower(strings.TrimSpace(value))
			host = strings.TrimSuffix(host, ".")
			if host == "" || strings.HasSuffix(host, ".") {
				return nil, fmt.Errorf("%s.hosts[%d] is not a valid FQDN", field, hostIndex)
			}
			if problem := validateExactFQDN(host); problem != "" {
				return nil, fmt.Errorf("%s.hosts[%d] is not a valid FQDN: %s", field, hostIndex, problem)
			}
			if _, found := hosts[host]; found {
				return nil, fmt.Errorf("%s.hosts[%d] duplicates host %q in the same gateway", field, hostIndex, host)
			}
			hosts[host] = struct{}{}
			service.Hosts[hostIndex] = host
		}
	}
	return result, nil
}

// validateExactFQDN validates a DNS name under the static egress contract.
func validateExactFQDN(host string) string {
	if len(host) > 255 {
		return "domain name is longer than 255 bytes"
	}
	labels := strings.Split(host, ".")
	if _, err := strconv.Atoi(labels[len(labels)-1]); err == nil {
		return "top-level domain cannot be all-numeric"
	}
	for _, label := range labels {
		if problems := validation.IsDNS1123Label(label); len(problems) > 0 {
			return strings.Join(problems, "; ")
		}
	}
	return ""
}

// GatewayKeyFromService extracts namespace/name from a Kubernetes service DNS
// name while accepting both service.namespace and longer cluster DNS suffixes.
func GatewayKeyFromService(service string) (string, bool) {
	parts := strings.Split(strings.TrimSuffix(strings.TrimSpace(service), "."), ".")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", false
	}
	if slices.Contains(parts, "") {
		return "", false
	}
	return parts[1] + "/" + parts[0], true
}

// GatewaysFromAgentioConfig projects AgentioConfig gateway declarations into
// identity-keyed values. Duplicate declarations remain visible as conflicts so
// downstream authorization and generation fail closed.
func GatewaysFromAgentioConfig(config *configv1.AgentioConfig) []Gateway {
	if config == nil {
		return nil
	}
	byKey := make(map[string]Gateway, len(config.GetEgressGateways()))
	order := make([]string, 0, len(config.GetEgressGateways()))
	for _, candidate := range config.GetEgressGateways() {
		if candidate == nil {
			continue
		}
		namespace, name := candidate.GetNamespace(), candidate.GetName()
		key := namespace + "/" + name
		if existing, found := byKey[key]; found {
			existing.Config = nil
			existing.Source = GatewaySourceConflict
			byKey[key] = existing
			continue
		}
		selected := proto.Clone(candidate).(*configv1.EgressGateway)
		selected.Namespace = ""
		selected.Name = ""
		byKey[key] = Gateway{
			Namespace: namespace,
			Name:      name,
			Config:    selected,
			Source:    GatewaySourceAgentioConfig,
		}
		order = append(order, key)
	}
	// A GATEWAY policy service declares an otherwise-default gateway even without
	// an explicit egressGateways entry.
	for _, policy := range config.GetEgressPolicies() {
		if policy.GetPolicy() != extensionsv1.EgressPolicyAction_GATEWAY {
			continue
		}
		key, valid := GatewayKeyFromService(policy.GetGateway().GetService())
		if !valid {
			continue
		}
		if _, found := byKey[key]; found {
			continue
		}
		parts := strings.SplitN(key, "/", 2)
		byKey[key] = Gateway{
			Namespace: parts[0],
			Name:      parts[1],
			Config:    &configv1.EgressGateway{},
			Source:    GatewaySourceLegacyFallback,
		}
		order = append(order, key)
	}
	result := make([]Gateway, 0, len(order))
	for _, key := range order {
		result = append(result, byKey[key])
	}
	return result
}

// MergeGatewaySources is the key-local merge used by KRT. Real declaration
// overlap is an explicit conflict rather than source precedence. A legacy
// GATEWAY policy reference is only a compatibility fallback, so it is ignored
// when exactly one real declaration exists and collapsed when inferred twice
// across the registry/compiler boundary.
func MergeGatewaySources(gateways []Gateway) *Gateway {
	if len(gateways) == 0 {
		return nil
	}
	explicit := make([]Gateway, 0, len(gateways))
	for _, gateway := range gateways {
		if gateway.Source != GatewaySourceLegacyFallback {
			explicit = append(explicit, gateway)
		}
	}
	selected := gateways
	if len(explicit) > 0 {
		selected = explicit
	}
	if len(selected) == 1 || len(explicit) == 0 {
		result := selected[0]
		if result.Config != nil {
			result.Config = proto.Clone(result.Config).(*configv1.EgressGateway)
		}
		return &result
	}
	result := Gateway{
		Namespace: selected[0].Namespace,
		Name:      selected[0].Name,
		Source:    GatewaySourceConflict,
	}
	return &result
}
