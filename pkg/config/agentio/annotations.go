// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// Package agentio defines Agentio configuration metadata.
package agentio

// SidecarStatus records containers and volumes managed by Agentio injection.
const SidecarStatus = "sidecar.agentio.kruise.io/status"

// annotationAliases maps supported Istio annotations to Agentio keys.
var annotationAliases = map[string]string{
	"traffic.sidecar.istio.io/includeOutboundIPRanges": "traffic.sidecar.agentio.kruise.io/include-outbound-ip-ranges",
	"traffic.sidecar.istio.io/excludeOutboundIPRanges": "traffic.sidecar.agentio.kruise.io/exclude-outbound-ip-ranges",
	"traffic.sidecar.istio.io/includeInboundPorts":     "traffic.sidecar.agentio.kruise.io/include-inbound-ports",
	"traffic.sidecar.istio.io/excludeInboundPorts":     "traffic.sidecar.agentio.kruise.io/exclude-inbound-ports",
	"traffic.sidecar.istio.io/includeOutboundPorts":    "traffic.sidecar.agentio.kruise.io/include-outbound-ports",
	"traffic.sidecar.istio.io/excludeOutboundPorts":    "traffic.sidecar.agentio.kruise.io/exclude-outbound-ports",
	"traffic.sidecar.istio.io/excludeInterfaces":       "traffic.sidecar.agentio.kruise.io/exclude-interfaces",
	"traffic.sidecar.istio.io/kubevirtInterfaces":      "traffic.sidecar.agentio.kruise.io/kubevirt-interfaces",
	"istio.io/reroute-virtual-interfaces":              "agentio.kruise.io/reroute-virtual-interfaces",
	"sidecar.istio.io/interceptionMode":                "sidecar.agentio.kruise.io/interception-mode",
	"status.sidecar.istio.io/port":                     "status.sidecar.agentio.kruise.io/port",
	"sidecar.istio.io/status":                          SidecarStatus,
	"sidecar.istio.io/statsFlushInterval":              "sidecar.agentio.kruise.io/stats-flush-interval",
	"sidecar.istio.io/statsEvictionInterval":           "sidecar.agentio.kruise.io/stats-eviction-interval",
	"networking.istio.io/traffic-distribution":         "networking.agentio.kruise.io/traffic-distribution",
}

// Annotation reads an Agentio key first, falling back to its Istio alias.
// An explicitly empty Agentio value overrides the legacy value as well.
func Annotation(annotations map[string]string, legacyKey string) (string, bool) {
	if key, ok := annotationAliases[legacyKey]; ok {
		if value, found := annotations[key]; found {
			return value, true
		}
	}
	value, found := annotations[legacyKey]
	return value, found
}

// NormalizeAnnotations returns a copy with both aliases set to the
// effective value, allowing existing validators and templates to share semantics.
func NormalizeAnnotations(annotations map[string]string) map[string]string {
	result := make(map[string]string, len(annotations))
	for key, value := range annotations {
		result[key] = value
	}
	for legacy, key := range annotationAliases {
		if value, found := Annotation(annotations, legacy); found {
			result[legacy] = value
			result[key] = value
		}
	}
	return result
}
