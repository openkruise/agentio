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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"iter"
	"slices"
	"sort"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	ClusterType                = "type.googleapis.com/envoy.config.cluster.v3.Cluster"
	EndpointType               = "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment"
	ListenerType               = "type.googleapis.com/envoy.config.listener.v3.Listener"
	RouteType                  = "type.googleapis.com/envoy.config.route.v3.RouteConfiguration"
	SecretType                 = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret"
	ExtensionConfigurationType = "type.googleapis.com/envoy.config.core.v3.TypedExtensionConfig"
	ProxyConfigType            = "type.googleapis.com/istio.mesh.v1alpha1.ProxyConfig"
	AddressType                = "type.googleapis.com/istio.workload.Address"
	TrafficPolicyType          = "type.googleapis.com/agentio.security.TrafficPolicy"
	SandboxType                = "type.googleapis.com/agentio.sandbox.Sandbox"
	WorkloadType               = "type.googleapis.com/istio.workload.Workload"
	WorkloadAuthorizationType  = "type.googleapis.com/istio.security.Authorization"
	SniTrafficPolicyType       = "type.googleapis.com/kruise.networking.extensions.v1.SniTrafficPolicy"
	// SecurityProfileType identifies binding references; profile bodies are not served through xDS.
	SecurityProfileType = "type.googleapis.com/agentio.security.SecurityProfile"
)

type AuthorizationScope uint8

const (
	AuthorizationScopeWorkload AuthorizationScope = iota + 1
	AuthorizationScopeNamespace
	AuthorizationScopeGlobal
)

// ResourceFacts holds immutable metadata used by pkg/xds to select resources for clients.
// At most one of Workload, Sandbox, Service, and Authorization may be set,
// matching the resource's type; other resource types leave all four nil.
// GatewayOwner may be set independently for any gateway-owned resource.
type ResourceFacts struct {
	// References declares acyclic dependencies whose bodies must outlive this resource.
	// Optional indirection keeps reference-free publication entries compact.
	References *ResourceReferences
	// SourceIdentity identifies the source of a complete Sandbox publication,
	// independently of its payload version. Other resource families leave it empty.
	SourceIdentity SourceIdentity
	// Workload records endpoint identity, placement, and service and policy references for resource selection.
	Workload *WorkloadResourceFacts
	// Sandbox links a Sandbox to its attesting Workload for visibility checks.
	Sandbox *SandboxResourceFacts
	// Service identifies the Service used to match Workload dependencies.
	Service *ServiceResourceFacts
	// Authorization records the policy scope used to select visible Authorization resources.
	Authorization *AuthorizationResourceFacts
	// GatewayOwner is the owning gateway's namespace/name key; empty means no gateway owner.
	GatewayOwner string
	// AgentioEgress distinguishes agentio egress resources from the upgrade-compatible legacy graph.
	AgentioEgress bool
}

// ResourceReferences records dependencies that must remain published with their referrers.
type ResourceReferences struct {
	Keys []ResourceKey
}

func (facts ResourceFacts) referenceKeys() []ResourceKey {
	if facts.References == nil {
		return nil
	}
	return facts.References.Keys
}

type WorkloadResourceFacts struct {
	Namespace         string
	WorkloadUID       string
	Source            SourceRef
	NodeName          string
	Principal         Principal
	ServiceKeys       []string
	GatewayReferences []string
	AuthorizationRefs []string
	// TrafficPolicyRefs is selection metadata; evaluation order lives in the wire binding.
	TrafficPolicyRefs []string
}

// SandboxResourceFacts records the Workload binding used for discovery visibility.
type SandboxResourceFacts struct {
	AttesterWorkloadUID string
}

type ServiceResourceFacts struct {
	ServiceKey string
}

type AuthorizationResourceFacts struct {
	Scope     AuthorizationScope
	Namespace string
}

// WorkloadQuery matches the conjunction of its populated fields. It is the
// typed query seam over Workload facts; arbitrary cross-family combinations
// are intentionally not representable.
type WorkloadQuery struct {
	// AuthorizationRefsOnly selects Workloads with Authorization references for older data planes.
	AuthorizationRefsOnly  bool
	TrafficPolicyRefsOnly  bool
	WorkloadUID            string
	Source                 SourceRef
	NodeName               string
	Principal              *Principal
	Namespace              string
	ServiceKey             string
	GatewayReference       string
	AuthorizationReference string
	TrafficPolicyReference string
}

func (r Resource) IsWorkloadAddress() bool {
	return r.Facts.Workload != nil
}

type ResourceKey struct {
	TypeURL string
	Name    string
}

func (k ResourceKey) String() string {
	return k.TypeURL + "/" + k.Name
}

// ReferencedResources includes the existing Workload selection metadata without
// allocating a second TrafficPolicy reference list or reverse index.
func (r Resource) ReferencedResources() iter.Seq[ResourceKey] {
	return func(yield func(ResourceKey) bool) {
		if w := r.Facts.Workload; w != nil {
			for _, name := range w.TrafficPolicyRefs {
				if !yield(ResourceKey{TypeURL: TrafficPolicyType, Name: name}) {
					return
				}
			}
		}
		for _, key := range r.Facts.referenceKeys() {
			if key.TypeURL == TrafficPolicyType && r.Facts.Workload != nil &&
				slices.Contains(r.Facts.Workload.TrafficPolicyRefs, key.Name) {
				continue
			}
			if !yield(key) {
				return
			}
		}
	}
}

// ReferencesResource reports whether this resource depends on key.
func (r Resource) ReferencesResource(key ResourceKey) bool {
	for reference := range r.ReferencedResources() {
		if reference == key {
			return true
		}
	}
	return false
}

// ResourceChange is the immutable boundary between the KRT resource graph and
// the push pipeline. New is nil for a deletion. Old is populated on published
// updates so a connection can withdraw a resource whose wire name or scope
// changed without scanning the complete snapshot.
type ResourceChange struct {
	Key ResourceKey
	Old *Resource
	New *Resource
}

// Resource is an immutable, pre-hashed xDS resource; Value is shared by reference and must not be mutated.
type Resource struct {
	Key ResourceKey
	// XDSName is the name exposed on the xDS wire. It may differ from Key.Name
	// when gateway-scoped resources share an Envoy name but not their contents.
	// Empty means Key.Name.
	XDSName string
	Value   *anypb.Any
	Aliases []string
	Hash    string
	Facts   ResourceFacts
}

// ResourceName makes Resource usable as a krt collection member. Type URL and
// name together are what uniquely identify a resource; Key.Name alone is not
// unique across types.
func (r Resource) ResourceName() string {
	return r.Key.TypeURL + "|" + r.Key.Name
}

// Equals reports whether two resources are interchangeable. Hash covers the type
// URL, both names, the encoded value, the aliases, and the selection facts, so hash
// equality is full equality and krt can use it to suppress no-op events.
func (r Resource) Equals(other Resource) bool {
	return r.Hash == other.Hash
}

// NewResource validates and hashes a resource once, at construction. Producers
// should build resources through this function so that assembling a snapshot
// never has to re-encode or re-hash anything.
func NewResource(
	key ResourceKey,
	xdsName string,
	value *anypb.Any,
	aliases []string,
	facts ResourceFacts,
) (Resource, error) {
	return normalizeResource(Resource{
		Key:     key,
		XDSName: xdsName,
		Value:   value,
		Aliases: aliases,
		Facts:   facts,
	})
}

func validateResource(resource Resource) error {
	if strings.TrimSpace(resource.Key.TypeURL) == "" {
		return fmt.Errorf("resource type URL is required")
	}
	if strings.TrimSpace(resource.Key.Name) == "" {
		return fmt.Errorf("resource name is required")
	}
	if resource.Value == nil {
		return fmt.Errorf("resource %s/%s has no value", resource.Key.TypeURL, resource.Key.Name)
	}
	if resource.Value.TypeUrl != resource.Key.TypeURL {
		return fmt.Errorf(
			"resource %s/%s value type URL %q does not match key",
			resource.Key.TypeURL, resource.Key.Name, resource.Value.TypeUrl,
		)
	}
	return validateResourceFacts(resource.Key, resource.Facts)
}

func validateResourceFacts(key ResourceKey, facts ResourceFacts) error {
	for _, reference := range facts.referenceKeys() {
		if strings.TrimSpace(reference.TypeURL) == "" || strings.TrimSpace(reference.Name) == "" {
			return fmt.Errorf("resource %s has an empty reference key", key)
		}
	}
	families := 0
	if facts.Sandbox != nil {
		families++
		if key.TypeURL != SandboxType {
			return fmt.Errorf("resource %s/%s carries Sandbox facts", key.TypeURL, key.Name)
		}
		if uid := facts.Sandbox.AttesterWorkloadUID; uid != strings.TrimSpace(uid) {
			return fmt.Errorf("Sandbox %s has a non-canonical attester UID", key.Name)
		}
	}
	if facts.Workload != nil {
		families++
	}
	if facts.Service != nil {
		families++
	}
	if facts.Authorization != nil {
		families++
	}
	if families > 1 {
		return fmt.Errorf("resource %s/%s carries incompatible resource facts", key.TypeURL, key.Name)
	}
	if facts.Workload != nil {
		if key.TypeURL != AddressType && key.TypeURL != WorkloadType {
			return fmt.Errorf("resource %s/%s carries Workload facts", key.TypeURL, key.Name)
		}
		if uid := facts.Workload.WorkloadUID; uid != strings.TrimSpace(uid) {
			return fmt.Errorf(
				"resource %s/%s Workload facts contain a non-canonical workload UID",
				key.TypeURL,
				key.Name,
			)
		}
		if facts.Workload.NodeName != strings.TrimSpace(facts.Workload.NodeName) {
			return fmt.Errorf("resource %s/%s Workload facts contain a non-canonical node name", key.TypeURL, key.Name)
		}
		if err := validateWorkloadResourcePrincipal(facts.Workload.Principal); err != nil {
			return fmt.Errorf("resource %s/%s Workload principal: %w", key.TypeURL, key.Name, err)
		}
		for label, values := range map[string][]string{
			"Service":       facts.Workload.ServiceKeys,
			"Gateway":       facts.Workload.GatewayReferences,
			"Authorization": facts.Workload.AuthorizationRefs,
			"TrafficPolicy": facts.Workload.TrafficPolicyRefs,
		} {
			for _, value := range values {
				if strings.TrimSpace(value) == "" {
					return fmt.Errorf(
						"resource %s/%s Workload facts contain an empty %s key",
						key.TypeURL,
						key.Name,
						label,
					)
				}
			}
		}
	}
	if facts.Service != nil {
		if key.TypeURL != AddressType {
			return fmt.Errorf("resource %s/%s carries Service facts", key.TypeURL, key.Name)
		}
		if strings.TrimSpace(facts.Service.ServiceKey) == "" {
			return fmt.Errorf("resource %s/%s Service facts require a service key", key.TypeURL, key.Name)
		}
	}
	if facts.Authorization != nil {
		if key.TypeURL != WorkloadAuthorizationType {
			return fmt.Errorf("resource %s/%s carries Authorization facts", key.TypeURL, key.Name)
		}
		switch facts.Authorization.Scope {
		case AuthorizationScopeGlobal, AuthorizationScopeWorkload:
			if facts.Authorization.Namespace != "" {
				return fmt.Errorf(
					"resource %s/%s %v Authorization must not carry a namespace",
					key.TypeURL,
					key.Name,
					facts.Authorization.Scope,
				)
			}
		case AuthorizationScopeNamespace:
			if strings.TrimSpace(facts.Authorization.Namespace) == "" {
				return fmt.Errorf("resource %s/%s namespace Authorization requires a namespace", key.TypeURL, key.Name)
			}
		default:
			return fmt.Errorf(
				"resource %s/%s has unknown Authorization scope %d",
				key.TypeURL,
				key.Name,
				facts.Authorization.Scope,
			)
		}
	}

	switch key.TypeURL {
	case SandboxType:
		if facts.Sandbox == nil {
			return fmt.Errorf("Sandbox resource %s requires Sandbox facts", key.Name)
		}
	case AddressType:
		if facts.Workload == nil && facts.Service == nil {
			return fmt.Errorf("Address resource %s requires Workload or Service facts", key.Name)
		}
	case WorkloadType:
		if facts.Workload == nil {
			return fmt.Errorf("Workload resource %s requires Workload facts", key.Name)
		}
	case WorkloadAuthorizationType:
		if facts.Authorization == nil {
			return fmt.Errorf("Authorization resource %s requires Authorization facts", key.Name)
		}
	default:
		if families != 0 {
			return fmt.Errorf("resource %s/%s carries facts for another resource family", key.TypeURL, key.Name)
		}
	}

	if facts.GatewayOwner != "" {
		if strings.TrimSpace(facts.GatewayOwner) != facts.GatewayOwner {
			return fmt.Errorf("resource %s/%s carries a non-canonical Gateway owner", key.TypeURL, key.Name)
		}
		switch key.TypeURL {
		case AddressType, WorkloadType, ClusterType, EndpointType, ListenerType, RouteType,
			SecretType, ExtensionConfigurationType, ProxyConfigType:
		default:
			return fmt.Errorf("resource %s/%s cannot be owned by a Gateway", key.TypeURL, key.Name)
		}
	}
	return nil
}

func validateWorkloadResourcePrincipal(principal Principal) error {
	if principal == (Principal{}) {
		return nil
	}
	return principal.Validate()
}

func cloneResourceFacts(facts ResourceFacts) ResourceFacts {
	result := ResourceFacts{
		SourceIdentity: facts.SourceIdentity,
		GatewayOwner:   facts.GatewayOwner,
		AgentioEgress:  facts.AgentioEgress,
	}
	if len(facts.referenceKeys()) > 0 {
		result.References = &ResourceReferences{Keys: slices.Clone(facts.References.Keys)}
	}
	if facts.Sandbox != nil {
		sandbox := *facts.Sandbox
		result.Sandbox = &sandbox
	}
	if facts.Workload != nil {
		workload := *facts.Workload
		workload.ServiceKeys = append([]string(nil), workload.ServiceKeys...)
		workload.GatewayReferences = append([]string(nil), workload.GatewayReferences...)
		workload.AuthorizationRefs = append([]string(nil), workload.AuthorizationRefs...)
		workload.TrafficPolicyRefs = append([]string(nil), workload.TrafficPolicyRefs...)
		result.Workload = &workload
	}
	if facts.Service != nil {
		service := *facts.Service
		result.Service = &service
	}
	if facts.Authorization != nil {
		authorization := *facts.Authorization
		result.Authorization = &authorization
	}
	return result
}

func normalizeResourceFacts(facts *ResourceFacts) {
	if facts.References != nil {
		keys := facts.References.Keys
		slices.SortFunc(keys, func(a, b ResourceKey) int {
			if order := strings.Compare(a.TypeURL, b.TypeURL); order != 0 {
				return order
			}
			return strings.Compare(a.Name, b.Name)
		})
		facts.References.Keys = slices.Compact(keys)
	}
	if facts.Workload == nil {
		return
	}
	facts.Workload.ServiceKeys = sortedUnique(facts.Workload.ServiceKeys)
	facts.Workload.GatewayReferences = sortedUnique(facts.Workload.GatewayReferences)
	facts.Workload.AuthorizationRefs = sortedUnique(facts.Workload.AuthorizationRefs)
	facts.Workload.TrafficPolicyRefs = sortedUnique(facts.Workload.TrafficPolicyRefs)
}

func sortedUnique(values []string) []string {
	sort.Strings(values)
	return compactSorted(values)
}

func hashResourceFacts(hasher hash.Hash, facts ResourceFacts) {
	write := func(tag, value string) {
		hasher.Write([]byte{0})
		hasher.Write([]byte(tag))
		hasher.Write([]byte{0})
		hasher.Write([]byte(value))
	}
	for _, reference := range facts.referenceKeys() {
		write("reference-type", reference.TypeURL)
		write("reference-name", reference.Name)
	}
	if facts.SourceIdentity != (SourceIdentity{}) {
		write("source-uid", facts.SourceIdentity.UID)
	}
	if facts.Sandbox != nil {
		write("family", "sandbox")
		write("attester-workload-uid", facts.Sandbox.AttesterWorkloadUID)
	}
	if facts.Workload != nil {
		write("family", "workload")
		write("workload-uid", facts.Workload.WorkloadUID)
		write("source", facts.Workload.Source.String())
		write("node", facts.Workload.NodeName)
		write("principal", facts.Workload.Principal.String())
		write("namespace", facts.Workload.Namespace)
		for _, value := range facts.Workload.ServiceKeys {
			write("service", value)
		}
		for _, value := range facts.Workload.GatewayReferences {
			write("gateway-reference", value)
		}
		for _, value := range facts.Workload.AuthorizationRefs {
			write("authorization-reference", value)
		}
		for _, value := range facts.Workload.TrafficPolicyRefs {
			write("traffic-policy-reference", value)
		}
	}
	if facts.Service != nil {
		write("family", "service")
		write("service", facts.Service.ServiceKey)
	}
	if facts.Authorization != nil {
		write("family", "authorization")
		write("authorization-scope", fmt.Sprintf("%d", facts.Authorization.Scope))
		write("authorization-namespace", facts.Authorization.Namespace)
	}
	if facts.GatewayOwner != "" {
		write("gateway-owner", facts.GatewayOwner)
		if facts.AgentioEgress {
			write("gateway-config", "agentio-egress")
		}
	}
}

func (facts ResourceFacts) Equal(other ResourceFacts) bool {
	if facts.SourceIdentity != other.SourceIdentity || facts.GatewayOwner != other.GatewayOwner ||
		!slices.Equal(facts.referenceKeys(), other.referenceKeys()) ||
		facts.AgentioEgress != other.AgentioEgress ||
		(facts.Workload == nil) != (other.Workload == nil) ||
		(facts.Sandbox == nil) != (other.Sandbox == nil) ||
		(facts.Service == nil) != (other.Service == nil) ||
		(facts.Authorization == nil) != (other.Authorization == nil) {
		return false
	}
	if facts.Workload != nil &&
		(facts.Workload.Namespace != other.Workload.Namespace ||
			facts.Workload.WorkloadUID != other.Workload.WorkloadUID ||
			facts.Workload.Source != other.Workload.Source ||
			facts.Workload.NodeName != other.Workload.NodeName ||
			facts.Workload.Principal != other.Workload.Principal ||
			!slices.Equal(facts.Workload.ServiceKeys, other.Workload.ServiceKeys) ||
			!slices.Equal(facts.Workload.GatewayReferences, other.Workload.GatewayReferences) ||
			!slices.Equal(facts.Workload.AuthorizationRefs, other.Workload.AuthorizationRefs) ||
			!slices.Equal(facts.Workload.TrafficPolicyRefs, other.Workload.TrafficPolicyRefs)) {
		return false
	}
	if facts.Sandbox != nil && *facts.Sandbox != *other.Sandbox {
		return false
	}
	if facts.Service != nil && *facts.Service != *other.Service {
		return false
	}
	return facts.Authorization == nil || *facts.Authorization == *other.Authorization
}

func normalizeResource(resource Resource) (Resource, error) {
	if err := validateResource(resource); err != nil {
		return Resource{}, err
	}

	// The single defensive copy in the lifetime of a resource: from here on the
	// value belongs to the Resource and is shared with every reader.
	cloned := Resource{
		Key:     resource.Key,
		XDSName: resource.XDSName,
		Value:   proto.Clone(resource.Value).(*anypb.Any),
		Aliases: append([]string(nil), resource.Aliases...),
		Facts:   cloneResourceFacts(resource.Facts),
	}
	if cloned.XDSName == "" {
		cloned.XDSName = cloned.Key.Name
	}
	sort.Strings(cloned.Aliases)
	normalizeResourceFacts(&cloned.Facts)
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(cloned.Value)
	if err != nil {
		return Resource{}, fmt.Errorf("marshal resource %s/%s: %w", resource.Key.TypeURL, resource.Key.Name, err)
	}
	hasher := sha256.New()
	hasher.Write([]byte(cloned.Key.TypeURL))
	hasher.Write([]byte{0})
	hasher.Write([]byte(cloned.Key.Name))
	hasher.Write([]byte{0})
	hasher.Write([]byte(cloned.XDSName))
	hasher.Write([]byte{0})
	hasher.Write(encoded)
	for _, alias := range cloned.Aliases {
		hasher.Write([]byte{0})
		hasher.Write([]byte(alias))
	}
	hashResourceFacts(hasher, cloned.Facts)
	cloned.Hash = hex.EncodeToString(hasher.Sum(nil))
	return cloned, nil
}
