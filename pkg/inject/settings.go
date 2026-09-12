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

package inject

import (
	"fmt"

	"github.com/openkruise/agentio/pkg/clienttrust"
)

const (
	defaultStatusPort        = 15020
	defaultProxyListenPort   = 15001
	defaultProxyInboundPort  = 15006
	defaultInterceptionMode  = "REDIRECT"
	prometheusMergeValuesKey = "enablePrometheusMerge"
	holdApplicationValuesKey = "holdApplicationUntilProxyStarts"
	proxyMetadataValuesKey   = "proxyMetadata"
)

// ProxyConfig is the ztunnel template's small runtime view. It deliberately
// excludes the Istio MeshConfig/ProxyConfig API: egress-gateway bootstrap keeps
// its separate wire-compatible PROXY_CONFIG contract in pkg/gatewaydeployer.
type ProxyConfig struct {
	DiscoveryAddress string
	InterceptionMode string
	ProxyMetadata    map[string]string
}

// TemplateMeshConfig preserves the two fields read by the current Agentio
// ztunnel template. It is a rendering view, not the Istio MeshConfig API and
// is never populated from a separate ConfigMap.
type TemplateMeshConfig struct {
	ProxyListenPort        int
	ProxyInboundListenPort int
}

// InjectionSettings is the complete process-local configuration needed to
// inject an in-pod ztunnel.
type InjectionSettings struct {
	Proxy                           ProxyConfig
	ClientTrust                     clienttrust.Settings
	StatusPort                      int
	ProxyListenPort                 int
	ProxyInboundListenPort          int
	EnablePrometheusMerge           bool
	HoldApplicationUntilProxyStarts bool
}

func defaultInjectionSettings(discoveryAddress string) InjectionSettings {
	return InjectionSettings{
		Proxy: ProxyConfig{
			DiscoveryAddress: discoveryAddress,
			InterceptionMode: defaultInterceptionMode,
		},
		StatusPort:             defaultStatusPort,
		ProxyListenPort:        defaultProxyListenPort,
		ProxyInboundListenPort: defaultProxyInboundPort,
		EnablePrometheusMerge:  true,
	}
}

func injectionSettingsFromValues(
	values ValuesConfig,
	discoveryAddress string,
) (InjectionSettings, error) {
	settings := defaultInjectionSettings(discoveryAddress)
	trust, err := clienttrust.Parse(values.Map())
	if err != nil {
		return InjectionSettings{}, fmt.Errorf("client trust: %w", err)
	}
	settings.ClientTrust = trust
	if configured := values.stringValue("global", "xdsAddress"); configured != "" {
		settings.Proxy.DiscoveryAddress = configured
	} else if configured := values.stringValue("global", "caAddress"); configured != "" {
		settings.Proxy.DiscoveryAddress = configured
	}
	if configured, ok := values.intValue("global", "proxy", "statusPort"); ok && configured > 0 {
		settings.StatusPort = configured
	}
	if configured, ok := values.boolValueWithPresence("sidecarInjectorWebhook", prometheusMergeValuesKey); ok {
		settings.EnablePrometheusMerge = configured
	}
	settings.HoldApplicationUntilProxyStarts = values.boolValue("global", "proxy", holdApplicationValuesKey)
	settings.Proxy.ProxyMetadata = values.stringMapValue("global", "proxy", proxyMetadataValuesKey)
	return settings, nil
}
