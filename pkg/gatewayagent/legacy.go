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

package gatewayagent

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// This is the proxy compatibility version of the pinned legacy image, not the
// gateway-agent version. Keep it aligned with LEGACY_ENVOY_IMAGE in the Dockerfile.
const legacyProxyVersion = "1.29"

func (c Config) nodeID() string {
	if c.Legacy {
		return "waypoint~" + c.IP + "~" + c.PodName + "." + c.Namespace + "~" + c.DNSDomain
	}
	return "agentio-egress/" + c.Namespace + "/" + c.PodUID
}

func (c *Config) legacyDefaults() {
	c.DNSDomain = envString("AGENTIO_DNS_DOMAIN", c.Namespace+".svc.cluster.local")
	c.Proxy.ConfigPath = envString("AGENTIO_CONFIG_DIR", "/etc/istio/proxy")
	c.XDSSocket = filepath.Join(c.Proxy.ConfigPath, "XDS")
	c.RootCertFile = envString("AGENTIO_ROOT_CA", "/var/run/secrets/istio/root-cert.pem")
	c.CARootCertFile = c.RootCertFile
	c.TokenFile = envString("AGENTIO_TOKEN_FILE", "/var/run/secrets/tokens/istio-token")
	if c.Proxy.DiscoveryAddress == "" {
		c.Proxy.DiscoveryAddress = c.CAAddress
	}
	if c.NodeName == "" {
		c.NodeName = os.Getenv("ISTIO_META_NODE_NAME")
	}
	if os.Getenv("CLUSTER_ID") == "" {
		c.ClusterID = envString("ISTIO_META_CLUSTER_ID", c.ClusterID)
	}
}

func (c Config) legacyMetadata(metadata map[string]any) error {
	for key, value := range map[string]any{
		"ISTIO_VERSION":         legacyProxyVersion,
		"NAMESPACE":             c.Namespace,
		"NAME":                  c.PodName,
		"INSTANCE_IPS":          strings.Join(c.nodeIPs(), ","),
		"SERVICE_ACCOUNT":       c.ServiceAccount,
		"METADATA_DISCOVERY":    strconv.FormatBool(c.discoveryEnabled()),
		"ENABLE_POLICY_STORE":   strconv.FormatBool(c.policyEnabled()),
		"ENABLE_HBONE":          "true",
		"ENVOY_STATUS_PORT":     portOption(c.EnvoyStatusPort, 15021),
		"ENVOY_PROMETHEUS_PORT": portOption(c.PrometheusPort, 15090),
	} {
		if _, exists := metadata[key]; exists {
			return fmt.Errorf("metadata key %q is reserved in legacy mode", key)
		}
		metadata[key] = value
	}
	for key, value := range map[string]string{
		"WORKLOAD_NAME": envString("ISTIO_META_WORKLOAD_NAME", c.PodName),
		"MESH_ID":       c.TrustDomain,
	} {
		if _, exists := metadata[key]; !exists {
			metadata[key] = value
		}
	}
	// Labels select gateway policy on the legacy control plane. Mounted Pod labels
	// take precedence over explicit custom metadata, as they did in pilot-agent.
	labels, err := readLegacyPodLabels("/etc/istio/pod/labels")
	if err != nil {
		return err
	}
	if len(labels) > 0 {
		metadata["LABELS"] = labels
	}
	return nil
}

func readLegacyPodLabels(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer closeResource(file)
	labels := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			return nil, fmt.Errorf("invalid Pod label in %s", path)
		}
		value, err = strconv.Unquote(value)
		if err != nil {
			return nil, fmt.Errorf("decode Pod label %q: %w", key, err)
		}
		if key != "pod-template-hash" {
			labels[key] = value
		}
	}
	return labels, scanner.Err()
}
