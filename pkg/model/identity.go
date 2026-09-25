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
)

type ClientClass string

const (
	ClientSharedZTunnel    ClientClass = "shared-ztunnel"
	ClientDedicatedZTunnel ClientClass = "dedicated-ztunnel"
	ClientEgressGateway    ClientClass = "egress-gateway"
)

// PrincipalKind selects the canonical identity shape carried by a Principal.
// It describes the authenticated identity, not the runtime or attestation
// mechanism that produced it.
type PrincipalKind string

const (
	// PrincipalServiceAccount is the Agentio-compatible identity
	// spiffe://<td>/ns/<namespace>/sa/<service-account>.
	PrincipalServiceAccount PrincipalKind = "service-account"
)

// ServiceAccountRef is the payload of a Kubernetes-shaped identity.
type ServiceAccountRef struct {
	Namespace      string
	ServiceAccount string
}

// Principal is a comparable SPIFFE identity value; exactly the payload of its Kind is populated.
type Principal struct {
	Kind           PrincipalKind
	TrustDomain    string
	ServiceAccount ServiceAccountRef
}

func (p Principal) Validate() error {
	if strings.TrimSpace(p.TrustDomain) == "" {
		return fmt.Errorf("trust domain is required")
	}
	switch p.Kind {
	case PrincipalServiceAccount:
		if strings.TrimSpace(p.ServiceAccount.Namespace) == "" {
			return fmt.Errorf("namespace is required")
		}
		if strings.TrimSpace(p.ServiceAccount.ServiceAccount) == "" {
			return fmt.Errorf("service account is required")
		}
	default:
		return fmt.Errorf("unknown identity kind %q", p.Kind)
	}
	return nil
}

func (p Principal) String() string {
	if p.Kind != PrincipalServiceAccount {
		return ""
	}
	return fmt.Sprintf("spiffe://%s/ns/%s/sa/%s", canonicalTrustDomain(p.TrustDomain), p.ServiceAccount.Namespace, p.ServiceAccount.ServiceAccount)
}

// Agentio preserves the configured trust domain as the identity domain value,
// but replaces '@' when encoding it into the authority component of a SPIFFE URI.
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

// ParsePrincipal parses a canonical SPIFFE service-account URI in the given trust domain.
func ParsePrincipal(raw, trustDomain string) (Principal, error) {
	identity, err := url.Parse(raw)
	if err != nil {
		return Principal{}, fmt.Errorf("invalid SPIFFE identity %q: %w", raw, err)
	}
	return ParsePrincipalURL(identity, trustDomain)
}

// ParsePrincipalURL is ParsePrincipal over an already-parsed URL.
func ParsePrincipalURL(identity *url.URL, trustDomain string) (Principal, error) {
	if identity == nil || identity.Scheme != "spiffe" || identity.Host != canonicalTrustDomain(trustDomain) ||
		identity.User != nil || identity.RawQuery != "" || identity.Fragment != "" {
		return Principal{}, fmt.Errorf("invalid SPIFFE identity %q", identity)
	}
	parts := strings.Split(strings.Trim(identity.Path, "/"), "/")
	var principal Principal
	switch {
	case len(parts) == 4 && parts[0] == "ns" && parts[2] == "sa":
		principal = Principal{
			Kind:        PrincipalServiceAccount,
			TrustDomain: trustDomain,
			ServiceAccount: ServiceAccountRef{
				Namespace:      parts[1],
				ServiceAccount: parts[3],
			},
		}
	default:
		return Principal{}, fmt.Errorf("unsupported SPIFFE identity %q", identity.String())
	}
	if err := principal.Validate(); err != nil {
		return Principal{}, fmt.Errorf("invalid SPIFFE identity %q: %w", identity.String(), err)
	}
	if identity.String() != principal.String() {
		return Principal{}, fmt.Errorf("non-canonical SPIFFE identity %q", identity.String())
	}
	return principal, nil
}

type ClientScope struct {
	// WorkloadUID + SourceUID bind a dedicated stream to its authenticated
	// runtime object. Its Sandbox set is resolved dynamically on each update.
	WorkloadUID string
	SourceUID   string
	Class       ClientClass
	Principal   Principal
	NodeName    string
	GatewayKey  string
}

func (s ClientScope) Validate() error {
	if err := s.Principal.Validate(); err != nil {
		return fmt.Errorf("principal: %w", err)
	}
	switch s.Class {
	case ClientSharedZTunnel:
		if strings.TrimSpace(s.NodeName) == "" {
			return fmt.Errorf("shared ztunnel scope requires node name")
		}
	case ClientDedicatedZTunnel:
		if strings.TrimSpace(s.WorkloadUID) == "" || strings.TrimSpace(s.SourceUID) == "" {
			return fmt.Errorf("dedicated ztunnel scope requires Workload UID and source UID")
		}
	case ClientEgressGateway:
		if strings.TrimSpace(s.GatewayKey) == "" {
			return fmt.Errorf("egress gateway scope requires gateway key")
		}
		if s.Principal.Kind != PrincipalServiceAccount {
			return fmt.Errorf("egress gateway scope requires a service account principal")
		}
		if expected := s.Principal.ServiceAccount.Namespace + "/" + s.Principal.ServiceAccount.ServiceAccount; s.GatewayKey != expected {
			return fmt.Errorf("egress gateway scope %q is not owned by principal %s", s.GatewayKey, s.Principal.String())
		}
	default:
		return fmt.Errorf("unknown client class %q", s.Class)
	}
	return nil
}
