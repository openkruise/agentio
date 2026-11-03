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

// Package gatewayagent owns the community Envoy gateway and its local credentials.
package gatewayagent

import (
	"cmp"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"time"

	"github.com/openkruise/agentio/pkg/model"
)

// ProxyConfig contains Envoy process and shutdown settings.
type ProxyConfig struct {
	DiscoveryAddress         string
	ConfigPath               string
	BinaryPath               string
	AdminPort                int32
	Concurrency              int32
	DrainDuration            time.Duration
	TerminationDrainDuration time.Duration
	FileFlushInterval        time.Duration
	FileFlushMinSizeKB       uint32
}

// Config contains the gateway identity, credential paths and runtime settings.
type Config struct {
	AdvancedOptions
	XDSRootCertFile             string
	Proxy                       ProxyConfig
	PodName                     string
	Namespace                   string
	PodUID                      string
	NodeName                    string
	ServiceAccount              string
	IP                          string
	DNSDomain                   string
	ClusterID                   string
	TrustDomain                 string
	TokenFile                   string
	CATokenFile                 string
	RootCertFile                string
	CARootCertFile              string
	CAAddress                   string
	XDSServerName               string
	CAServerName                string
	XDSSocket                   string
	SDSSocket                   string
	AgentLogLevel               string
	KeepaliveInterval           time.Duration
	KeepaliveTimeout            time.Duration
	Metadata                    map[string]any
	metrics                     *agentMetrics
	LogLevel                    string
	ComponentLogLevel           string
	OutlierLogPath              string
	LogAsJSON                   bool
	SecretTTL                   time.Duration
	MinimumDrainDuration        time.Duration
	StatsFlushInterval          time.Duration
	ExitOnZeroActiveConnections bool
}

// FromEnvironment loads operator-supplied identity and paths with runtime defaults.
func FromEnvironment() Config {
	address := xdsAddressEnv.Get()
	root := cmp.Or(rootCAEnv.Get(), rootCAEnv.DefaultValue)
	dir := cmp.Or(configDirEnv.Get(), configDirEnv.DefaultValue)
	return Config{
		Proxy: ProxyConfig{DiscoveryAddress: address,
			ConfigPath:               dir,
			BinaryPath:               cmp.Or(envoyBinaryEnv.Get(), envoyBinaryEnv.DefaultValue),
			AdminPort:                15000,
			DrainDuration:            45 * time.Second,
			TerminationDrainDuration: 25 * time.Second,
			FileFlushInterval:        time.Second},
		PodName:              podNameEnv.Get(),
		Namespace:            namespaceEnv.Get(),
		PodUID:               podUIDEnv.Get(),
		NodeName:             nodeNameEnv.Get(),
		ServiceAccount:       serviceAccountEnv.Get(),
		IP:                   instanceIPEnv.Get(),
		ClusterID:            cmp.Or(clusterIDEnv.Get(), clusterIDEnv.DefaultValue),
		TrustDomain:          cmp.Or(trustDomainEnv.Get(), trustDomainEnv.DefaultValue),
		TokenFile:            cmp.Or(tokenFileEnv.Get(), tokenFileEnv.DefaultValue),
		RootCertFile:         root,
		CARootCertFile:       root,
		CAAddress:            cmp.Or(caAddressEnv.Get(), address),
		XDSServerName:        xdsServerNameEnv.Get(),
		CAServerName:         caServerNameEnv.Get(),
		XDSSocket:            filepath.Join(dir, "XDS"),
		SDSSocket:            "/var/run/secrets/workload-spiffe-uds/socket",
		AgentLogLevel:        "info",
		KeepaliveInterval:    30 * time.Second,
		KeepaliveTimeout:     10 * time.Second,
		LogLevel:             "warning",
		ComponentLogLevel:    "misc:error",
		SecretTTL:            24 * time.Hour,
		MinimumDrainDuration: 5 * time.Second,
		StatsFlushInterval:   5 * time.Second,
	}
}

func (c Config) validate() error {
	if c.PodName == "" || c.Namespace == "" || c.PodUID == "" || c.ServiceAccount == "" {
		return fmt.Errorf("POD_NAME, POD_NAMESPACE, POD_UID and SERVICE_ACCOUNT are required")
	}
	if _, err := netip.ParseAddr(c.IP); err != nil {
		return fmt.Errorf("invalid INSTANCE_IP: %w", err)
	}
	for _, address := range []string{c.Proxy.DiscoveryAddress, c.CAAddress} {
		host, port, err := net.SplitHostPort(address)
		if err != nil || host == "" || port == "" {
			return fmt.Errorf("invalid control-plane address %q", address)
		}
	}
	return c.validateRuntime()
}

func localAddresses(ip string) (string, string) {
	if address, err := netip.ParseAddr(ip); err == nil && address.Is6() {
		return "::1", "::"
	}
	return "127.0.0.1", "0.0.0.0"
}

func (c Config) nodeID() string {
	return fmt.Sprintf("%s~%s~%s.%s~%s", model.ProxyTypeAgentioEgress, c.IP, c.PodName, c.Namespace,
		cmp.Or(c.DNSDomain, c.Namespace+".svc.cluster.local"))
}
