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
	"net/url"
	"strings"

	configv1 "github.com/openkruise/agentio/api/config/v1"
)

// Proxy type prefixes in xDS node IDs, independent of authenticated client classes.
const (
	ProxyTypeResourceConsumer = "resource-consumer"
	ProxyTypeZTunnel          = "ztunnel"
	ProxyTypeWaypoint         = "waypoint"
	ProxyTypeAgentioEgress    = "agentio-egress"
	ProxyTypeAgentioPorter    = "agentio-porter"
)

type ClientClass string

// Client classes select resource visibility independently of the authentication method.
const (
	ClientResourceConsumer ClientClass = "resource-consumer"
	ClientSharedZTunnel    ClientClass = "shared-ztunnel"
	ClientDedicatedZTunnel ClientClass = "dedicated-ztunnel"
	ClientEgressGateway    ClientClass = "egress-gateway"
	ClientAgentioEgress    ClientClass = "agentio-egress"
)

// Principal is a canonical SPIFFE URI. Its zero value represents no identity.
type Principal struct{ uri string }

func (p Principal) String() string { return p.uri }

// TrustDomain returns the principal's SPIFFE trust domain.
func (p Principal) TrustDomain() string {
	authority, _, _ := strings.Cut(strings.TrimPrefix(p.uri, "spiffe://"), "/")
	return authority
}
func (p Principal) Validate() error {
	_, err := ParsePrincipal(p.uri, p.TrustDomain())
	return err
}

// MarshalText encodes the principal as its canonical SPIFFE URI.
func (p Principal) MarshalText() ([]byte, error) { return []byte(p.uri), nil }

// NewPrincipal constructs a principal from a trust domain and path.
func NewPrincipal(trustDomain, path string) (Principal, error) {
	return ParsePrincipal("spiffe://"+canonicalTrustDomain(trustDomain)+"/"+path, trustDomain)
}

// Preserve Agentio's configured trust-domain encoding at URI boundaries.
func canonicalTrustDomain(trustDomain string) string {
	return strings.ReplaceAll(trustDomain, "@", ".")
}

// ParseSPIFFEID validates a peer URI without restricting it to a Kubernetes
// ServiceAccount path. Formatting normalization is left to the caller.
func ParseSPIFFEID(raw string) (*url.URL, error) {
	identity, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid SPIFFE ID %q: %w", raw, err)
	}
	if identity.Scheme != "spiffe" || identity.Hostname() == "" ||
		identity.Host != identity.Hostname() || identity.User != nil || identity.Path == "" ||
		identity.RawQuery != "" || identity.ForceQuery || strings.Contains(raw, "#") {
		return nil, fmt.Errorf(
			"invalid SPIFFE ID %q: expected spiffe://<trust-domain>/<path> without userinfo, port, query or fragment",
			raw,
		)
	}
	return identity, nil
}

// ParsePrincipal parses a SPIFFE URI and validates its syntax and trust domain.
func ParsePrincipal(raw, trustDomain string) (Principal, error) {
	const prefix = "spiffe://"
	if !strings.HasPrefix(raw, prefix) || len(raw) > 2048 {
		return Principal{}, fmt.Errorf("invalid SPIFFE identity %q", raw)
	}
	parts := strings.Split(strings.TrimPrefix(raw, prefix), "/")
	td := parts[0]
	if td != canonicalTrustDomain(trustDomain) || td != strings.ToLower(td) || len(td) > 255 {
		return Principal{}, fmt.Errorf("invalid SPIFFE trust domain %q", td)
	}
	for _, part := range parts {
		if !validIdentitySegment(part) {
			return Principal{}, fmt.Errorf("invalid SPIFFE identity %q", raw)
		}
	}
	return Principal{uri: raw}, nil
}

func ParsePrincipalURL(identity *url.URL, trustDomain string) (Principal, error) {
	if identity == nil {
		return Principal{}, fmt.Errorf("SPIFFE identity is required")
	}
	return ParsePrincipal(identity.String(), trustDomain)
}

// SPIFFE paths forbid percent encoding and relative/empty segments.
func validIdentitySegment(value string) bool {
	if value == "" || value == "." || value == ".." {
		return false
	}
	for _, c := range value {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

type ClientScope struct {
	// Access is the immutable explicit type grant; nil uses built-in permissions.
	Access *configv1.XDSClient
	// WorkloadUID + Source bind a dedicated stream to its authenticated
	// runtime object. Its Sandbox set is resolved dynamically on each update.
	WorkloadUID string
	Source      SourceRef
	Class       ClientClass
	Principal   Principal
	NodeName    string

	// GatewayKey identifies the gateway whose membership the registry verified.
	GatewayKey string
}

func (s ClientScope) Validate() error {
	if err := s.Principal.Validate(); err != nil && (s.Class != ClientSharedZTunnel || s.Principal != (Principal{})) {
		return fmt.Errorf("principal: %w", err)
	}
	switch s.Class {
	case ClientResourceConsumer:
		// The attestation owns instance verification; explicit grants authorize discovery.
	case ClientSharedZTunnel:
		if strings.TrimSpace(s.NodeName) == "" {
			return fmt.Errorf("shared ztunnel scope requires node name")
		}
	case ClientDedicatedZTunnel:
		if strings.TrimSpace(s.WorkloadUID) == "" || s.Source.Validate() != nil {
			return fmt.Errorf("dedicated ztunnel scope requires Workload UID and source reference")
		}
	case ClientEgressGateway, ClientAgentioEgress:
		if strings.TrimSpace(s.GatewayKey) == "" || strings.TrimSpace(s.WorkloadUID) == "" ||
			s.Source.Validate() != nil {
			return fmt.Errorf("egress gateway scope requires gateway key and bound Workload/source references")
		}
	default:
		return fmt.Errorf("unknown client class %q", s.Class)
	}
	return nil
}
