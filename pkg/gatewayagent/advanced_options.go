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
	"cmp"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"istio.io/istio/pkg/ptr"
)

// AdvancedOptions uses native Envoy JSON for telemetry resources.
type AdvancedOptions struct {
	StatsEvictionInterval    string               `json:"statsEvictionInterval,omitempty"`
	StatsMatcher             *StatsMatcher        `json:"statsMatcher,omitempty"`
	ExtraStatTags            []string             `json:"extraStatTags,omitempty"`
	HistogramBuckets         map[string][]float64 `json:"histogramBuckets,omitempty"`
	RuntimeValues            map[string]any       `json:"runtimeValues,omitempty"`
	MaxDownstreamConnections *uint64              `json:"maxDownstreamConnections,omitempty"`
	SkipDeprecatedLogs       *bool                `json:"skipDeprecatedLogs,omitempty"`
	StatsCompression         *bool                `json:"statsCompression,omitempty"`
	MetricsLocalhostOnly     bool                 `json:"metricsLocalhostOnly,omitempty"`
	StatusProxyProtocol      bool                 `json:"statusProxyProtocol,omitempty"`
	StatusPort               int                  `json:"statusPort,omitempty"`
	EnvoyStatusPort          int                  `json:"envoyStatusPort,omitempty"`
	PrometheusPort           int                  `json:"prometheusPort,omitempty"`
	AdminPort                int                  `json:"adminPort,omitempty"`
	WorkloadSocket           string               `json:"workloadSocket,omitempty"`
	InstanceIPs              []string             `json:"instanceIPs,omitempty"`
	Locality                 json.RawMessage      `json:"locality,omitempty"`
	XDSHeaders               map[string]string    `json:"xdsHeaders,omitempty"`
	CAHeaders                map[string]string    `json:"caHeaders,omitempty"`
	RSAKeySize               int                  `json:"rsaKeySize,omitempty"`
	ECCCurve                 string               `json:"eccCurve,omitempty"`
	PKCS8                    bool                 `json:"pkcs8,omitempty"`
	CertSigner               string               `json:"certSigner,omitempty"`
	RotationGraceRatio       *float64             `json:"rotationGraceRatio,omitempty"`
	RotationJitter           *float64             `json:"rotationJitter,omitempty"`
	TelemetryClusters        []json.RawMessage    `json:"telemetryClusters,omitempty"`
	StatsSinks               []json.RawMessage    `json:"statsSinks,omitempty"`
	Tracing                  json.RawMessage      `json:"tracing,omitempty"`
	LoadStatsConfig          json.RawMessage      `json:"loadStatsConfig,omitempty"`
	OutlierEventLog          string               `json:"outlierEventLog,omitempty"`
	Profiling                bool                 `json:"profiling,omitempty"`
}

// StatsMatcher selects additional metrics while retaining agent-required stats.
type StatsMatcher struct {
	InclusionPrefixes []string `json:"inclusionPrefixes,omitempty"`
	InclusionSuffixes []string `json:"inclusionSuffixes,omitempty"`
	InclusionRegexps  []string `json:"inclusionRegexps,omitempty"`
}

func (c Config) nodeIPs() []string {
	if len(c.InstanceIPs) > 0 {
		return c.InstanceIPs
	}
	return []string{c.IP}
}

func (c Config) validateAdvanced() error {
	if c.StatsEvictionInterval != "" {
		eviction, err := time.ParseDuration(c.StatsEvictionInterval)
		if err != nil || eviction <= 0 || c.StatsFlushInterval <= 0 || eviction%c.StatsFlushInterval != 0 {
			return fmt.Errorf("statsEvictionInterval must be a positive multiple of statsFlushInterval")
		}
	}
	for _, check := range []func() error{c.validateNetworkOptions, c.validateKeyOptions, c.validateHeaders} {
		if err := check(); err != nil {
			return err
		}
	}
	return nil
}

func (c Config) validateNetworkOptions() error {
	ports := map[int]bool{}
	for _, port := range []int{int(c.Proxy.AdminPort), cmp.Or(c.StatusPort, 15020), cmp.Or(c.EnvoyStatusPort, 15021), cmp.Or(c.PrometheusPort, 15090)} {
		if port < 1 || port > 65535 || ports[port] {
			return fmt.Errorf("gateway ports must be distinct and in 1..65535")
		}
		ports[port] = true
	}
	if c.AdminPort < 0 || c.AdminPort > 65535 {
		return fmt.Errorf("invalid adminPort")
	}
	if c.WorkloadSocket != "" && !strings.HasPrefix(c.WorkloadSocket, "/") {
		return fmt.Errorf("workloadSocket must be absolute")
	}
	for _, ip := range c.InstanceIPs {
		if _, err := netip.ParseAddr(ip); err != nil {
			return fmt.Errorf("invalid instanceIPs: %w", err)
		}
	}
	if len(c.InstanceIPs) > 0 && c.InstanceIPs[0] != c.IP {
		return fmt.Errorf("instanceIPs must start with INSTANCE_IP")
	}
	return nil
}

func (c Config) validateKeyOptions() error {
	if c.RSAKeySize != 0 && c.RSAKeySize != 2048 && c.RSAKeySize != 3072 && c.RSAKeySize != 4096 {
		return fmt.Errorf("rsaKeySize must be 2048, 3072 or 4096")
	}
	if c.ECCCurve != "" && c.ECCCurve != "P256" && c.ECCCurve != "P384" {
		return fmt.Errorf("eccCurve must be P256 or P384")
	}
	grace, jitter := ptr.OrDefault(c.RotationGraceRatio, .5), ptr.OrDefault(c.RotationJitter, .01)
	if grace <= 0 || grace >= 1 || jitter < 0 || jitter >= grace || grace+jitter >= 1 {
		return fmt.Errorf("rotation ratio and jitter must keep renewal strictly within certificate lifetime")
	}
	return nil
}

func (c Config) validateHeaders() error {
	for _, headers := range []map[string]string{c.XDSHeaders, c.CAHeaders} {
		for key, value := range headers {
			if key == "" || strings.ToLower(key) != key || key == "authorization" || key == "clusterid" ||
				strings.HasPrefix(key, "grpc-") ||
				strings.HasSuffix(key, "-bin") {
				return fmt.Errorf("invalid or reserved RPC header %q", key)
			}
			for _, ch := range key {
				if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_' || ch == '.') {
					return fmt.Errorf("invalid RPC header %q", key)
				}
			}
			for _, ch := range value {
				if ch < 32 || ch > 126 {
					return fmt.Errorf("invalid RPC header value for %q", key)
				}
			}
		}
	}
	return nil
}

func (c *Config) applyCredentialPaths() {
	c.CATokenFile = cmp.Or(caTokenFileEnv.Get(), c.TokenFile)
	if root, set := rootCAEnv.Lookup(); set {
		c.RootCertFile = cmp.Or(root, c.RootCertFile)
	}
	c.CARootCertFile = cmp.Or(caRootCAEnv.Get(), c.RootCertFile)
	c.XDSRootCertFile = cmp.Or(xdsRootCAEnv.Get(), c.RootCertFile)
	if c.WorkloadSocket != "" {
		c.SDSSocket = c.WorkloadSocket
	}
	if c.AdminPort != 0 {
		c.Proxy.AdminPort = int32(c.AdminPort)
	}
}
