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

package agentio

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

func chartValues(config Config) ([]byte, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	agentiodImage, err := pinnedImageValues(config.AgentiodImage)
	if err != nil {
		return nil, fmt.Errorf("agentiod image: %w", err)
	}
	cniImage, err := pinnedImageValues(config.CNIImage)
	if err != nil {
		return nil, fmt.Errorf("CNI image: %w", err)
	}
	ztunnelImage, err := pinnedImageValues(config.ZtunnelImage)
	if err != nil {
		return nil, fmt.Errorf("ztunnel image: %w", err)
	}
	gatewayImage, err := pinnedImageValues(config.GatewayImage)
	if err != nil {
		return nil, fmt.Errorf("gateway image: %w", err)
	}
	epeImage, err := pinnedImageValues(config.EPEImage)
	if err != nil {
		return nil, fmt.Errorf("epe image: %w", err)
	}

	values := map[string]any{
		"profile": config.Profile,
		"global": map[string]any{
			"imagePullPolicy": "IfNotPresent",
			"clusterId":       "Kubernetes",
			"trustDomain":     "cluster.local",
			"clusterDomain":   "cluster.local",
		},
		"agentiod": map[string]any{
			"image":                     agentiodImage,
			"trustedNodeServiceAccount": config.Namespace + "/ztunnel",
			"meshInternalTrafficPolicy": "PASSTHROUGH",
			"enableSNITrafficPolicy":    true,
			"injector": map[string]any{
				"clientTrust":    map[string]any{"enabled": config.EnableClientTrust},
				"nativeSidecars": false,
				"ztunnel": map[string]any{
					"image":               config.ZtunnelImage,
					"enableFirewallRules": config.EnableFirewallRules,
					"firewallBackend":     config.FirewallBackend,
				},
				"proxyInit": map[string]any{"image": config.ProxyInitImage},
			},
			"config": map[string]any{"values": map[string]any{
				"egressPolicies": []any{map[string]any{"policy": "PASSTHROUGH"}},
			}},
		},
		"cni": map[string]any{"image": cniImage},
		"ztunnel": map[string]any{
			"image":               ztunnelImage,
			"enableFirewallRules": config.EnableFirewallRules,
			"env": map[string]any{
				"FIREWALL_BACKEND": config.FirewallBackend,
			},
		},
		"egressGateway": map[string]any{
			"mode":                "static",
			"nameOverride":        "egress-gateway",
			"image":               gatewayImage,
			"replicaCount":        1,
			"autoscaling":         map[string]any{"enabled": false},
			"podDisruptionBudget": map[string]any{"enabled": false},
			"sniTrafficPolicy":    map[string]any{"enabled": true},
			"resources": map[string]any{
				"requests": map[string]any{"cpu": "100m", "memory": "128Mi"},
				"limits":   map[string]any{"cpu": "1", "memory": "512Mi"},
			},
		},
		"epe": map[string]any{
			"mode":                "managed",
			"image":               epeImage,
			"replicaCount":        1,
			"autoscaling":         map[string]any{"enabled": false},
			"podDisruptionBudget": map[string]any{"enabled": false},
			"credentialProvider": map[string]any{
				"mtls": map[string]any{"source": "none"},
			},
			"resources": map[string]any{
				"requests": map[string]any{"cpu": "100m", "memory": "256Mi"},
				"limits":   map[string]any{"cpu": "1", "memory": "512Mi"},
			},
		},
	}
	if config.GatewayDataplane == "agentgateway" {
		values["agentiod"].(map[string]any)["enableSNITrafficPolicy"] = false
		values["egressGateway"] = map[string]any{
			"mode":       "gatewayAPI",
			"gatewayAPI": map[string]any{"create": false},
			"agentgateway": map[string]any{
				"image":        config.GatewayImage,
				"ca":           map[string]any{"enabled": true},
				"replicaCount": 1,
				"resources": map[string]any{
					"requests": map[string]any{"cpu": "100m", "memory": "128Mi"},
					"limits":   map[string]any{"cpu": "1", "memory": "512Mi"},
				},
			},
		}
	}
	return yaml.Marshal(values)
}

func pinnedImageValues(reference string) (map[string]any, error) {
	repository, digest, found := strings.Cut(reference, "@")
	if !found || repository == "" || digest == "" {
		return nil, fmt.Errorf("image %q is not an immutable digest reference", reference)
	}
	return map[string]any{"repository": repository, "digest": digest}, nil
}
