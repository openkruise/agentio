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
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/openkruise/agentio/test/e2e/components/forwardproxy"
	"gopkg.in/yaml.v3"
)

const (
	ProfileSidecar     = "sidecar"
	ProfileAmbient     = "ambient"
	DataplaneModeLabel = "agentio.kruise.io/dataplane-mode"
)

type Config struct {
	GatewayDataplane    string `yaml:"gateway-dataplane" json:"gatewayDataplane"`
	Profile             string `yaml:"profile" json:"profile"`
	ReleaseName         string `yaml:"release-name" json:"releaseName"`
	ChartPath           string `yaml:"chart-path" json:"chartPath"`
	Namespace           string `yaml:"namespace" json:"namespace"`
	AgentiodImage       string `yaml:"agentiod-image" json:"agentiodImage"`
	CNIImage            string `yaml:"cni-image" json:"cniImage"`
	ZtunnelImage        string `yaml:"ztunnel-image" json:"ztunnelImage"`
	ProxyInitImage      string `yaml:"proxy-init-image" json:"proxyInitImage"`
	GatewayImage        string `yaml:"gateway-image" json:"gatewayImage"`
	EPEImage            string `yaml:"epe-image" json:"epeImage"`
	ExtProcImage        string `yaml:"ext-proc-image" json:"extProcImage"`
	ForwardProxyImage   string `yaml:"forward-proxy-image" json:"forwardProxyImage"`
	Reuse               bool   `yaml:"reuse" json:"reuse"`
	EnableFirewallRules bool   `yaml:"enable-firewall-rules" json:"enableFirewallRules"`
	EnableClientTrust   bool   `yaml:"enable-client-trust" json:"enableClientTrust"`
	FirewallBackend     string `yaml:"firewall-backend" json:"firewallBackend"`
}

type FlagInputs struct {
	fs                *flag.FlagSet
	profile           *string
	configFile        *string
	releaseName       *string
	chartPath         *string
	namespace         *string
	agentiodImage     *string
	cniImage          *string
	ztunnelImage      *string
	proxyInitImage    *string
	gatewayImage      *string
	gatewayDataplane  *string
	epeImage          *string
	extProcImage      *string
	forwardProxyImage *string
	reuse             *bool
	enableFirewall    *bool
	firewallBackend   *string
}

func RegisterFlags(fs *flag.FlagSet) *FlagInputs {
	inputs := &FlagInputs{fs: fs}
	inputs.profile = fs.String("agentio.profile", "", "Agentio deployment profile: sidecar or ambient")
	inputs.configFile = fs.String("agentio.config", "", "strict Agentio E2E YAML configuration")
	inputs.releaseName = fs.String("agentio.release-name", "", "Agentio Helm release name")
	inputs.chartPath = fs.String("agentio.chart-path", "", "path to the production Agentio Helm chart")
	inputs.namespace = fs.String("agentio.namespace", "", "Agentio control-plane namespace")
	inputs.agentiodImage = fs.String("agentio.agentiod-image", "", "immutable agentiod image")
	inputs.cniImage = fs.String("agentio.cni-image", "", "immutable CNI image")
	inputs.ztunnelImage = fs.String("agentio.ztunnel-image", "", "immutable ztunnel image")
	inputs.proxyInitImage = fs.String("agentio.proxy-init-image", "", "immutable proxy-init image")
	inputs.gatewayDataplane = fs.String("agentio.gateway-dataplane", "", "gateway data plane: envoy or agentgateway")
	inputs.gatewayImage = fs.String("agentio.gateway-image", "", "immutable gateway image")
	inputs.epeImage = fs.String("agentio.epe-image", "", "immutable epe image")
	inputs.extProcImage = fs.String("agentio.ext-proc-image", "", "immutable ext-proc image")
	inputs.forwardProxyImage = fs.String("agentio.forward-proxy-image", "", "optional immutable forward-proxy fixture image override")
	inputs.reuse = fs.Bool("agentio.reuse", false, "reuse an exact matching Agentio installation")
	inputs.enableFirewall = fs.Bool("agentio.enable-firewall-rules", false, "enable ztunnel firewall rules for UDP and ICMP policy tests")
	inputs.firewallBackend = fs.String("agentio.firewall-backend", "auto", "ztunnel firewall backend: auto or iptables")
	return inputs
}

func ResolveConfig(inputs *FlagInputs) (Config, error) {
	if inputs == nil || inputs.fs == nil {
		return Config{}, errors.New("Agentio flag inputs are required")
	}
	config := Config{Profile: ProfileSidecar, ReleaseName: "agentio", Namespace: "agentio-system", FirewallBackend: "auto"}
	explicit := make(map[string]bool)
	inputs.fs.Visit(func(value *flag.Flag) { explicit[value.Name] = true })
	configPath := os.Getenv("AGENTIO_E2E_CONFIG")
	if explicit["agentio.config"] {
		configPath = *inputs.configFile
	}
	if configPath != "" {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return Config{}, fmt.Errorf("read Agentio config %q: %w", configPath, err)
		}
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		decoder.KnownFields(true)
		if err := decoder.Decode(&config); err != nil {
			return Config{}, fmt.Errorf("decode Agentio config %q: %w", configPath, err)
		}
		var extra any
		if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
			return Config{}, fmt.Errorf("decode Agentio config %q: multiple documents are not supported", configPath)
		}
	}
	applyStringEnv("AGENTIO_E2E_PROFILE", &config.Profile)
	applyStringEnv("AGENTIO_E2E_RELEASE_NAME", &config.ReleaseName)
	applyStringEnv("AGENTIO_E2E_CHART_PATH", &config.ChartPath)
	applyStringEnv("AGENTIO_E2E_NAMESPACE", &config.Namespace)
	applyStringEnv("AGENTIO_E2E_AGENTIOD_IMAGE", &config.AgentiodImage)
	applyStringEnv("AGENTIO_E2E_CNI_IMAGE", &config.CNIImage)
	applyStringEnv("AGENTIO_E2E_ZTUNNEL_IMAGE", &config.ZtunnelImage)
	applyStringEnv("AGENTIO_E2E_PROXY_INIT_IMAGE", &config.ProxyInitImage)
	applyStringEnv("AGENTIO_E2E_GATEWAY_IMAGE", &config.GatewayImage)
	applyStringEnv("AGENTIO_E2E_GATEWAY_DATAPLANE", &config.GatewayDataplane)
	applyStringEnv("AGENTIO_E2E_EPE_IMAGE", &config.EPEImage)
	applyStringEnv("AGENTIO_E2E_EXT_PROC_IMAGE", &config.ExtProcImage)
	applyStringEnv("AGENTIO_E2E_FORWARD_PROXY_IMAGE", &config.ForwardProxyImage)
	applyStringEnv("AGENTIO_E2E_FIREWALL_BACKEND", &config.FirewallBackend)
	if value, found := os.LookupEnv("AGENTIO_E2E_REUSE"); found {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return Config{}, fmt.Errorf("parse AGENTIO_E2E_REUSE: %w", err)
		}
		config.Reuse = parsed
	}
	if value, found := os.LookupEnv("AGENTIO_E2E_ENABLE_FIREWALL_RULES"); found {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return Config{}, fmt.Errorf("parse AGENTIO_E2E_ENABLE_FIREWALL_RULES: %w", err)
		}
		config.EnableFirewallRules = parsed
	}
	if explicit["agentio.namespace"] {
		config.Namespace = *inputs.namespace
	}
	if explicit["agentio.profile"] {
		config.Profile = *inputs.profile
	}
	if explicit["agentio.release-name"] {
		config.ReleaseName = *inputs.releaseName
	}
	if explicit["agentio.chart-path"] {
		config.ChartPath = *inputs.chartPath
	}
	if explicit["agentio.agentiod-image"] {
		config.AgentiodImage = *inputs.agentiodImage
	}
	if explicit["agentio.cni-image"] {
		config.CNIImage = *inputs.cniImage
	}
	if explicit["agentio.ztunnel-image"] {
		config.ZtunnelImage = *inputs.ztunnelImage
	}
	if explicit["agentio.proxy-init-image"] {
		config.ProxyInitImage = *inputs.proxyInitImage
	}
	if explicit["agentio.gateway-dataplane"] {
		config.GatewayDataplane = *inputs.gatewayDataplane
	}
	if explicit["agentio.gateway-image"] {
		config.GatewayImage = *inputs.gatewayImage
	}
	if explicit["agentio.epe-image"] {
		config.EPEImage = *inputs.epeImage
	}
	if explicit["agentio.ext-proc-image"] {
		config.ExtProcImage = *inputs.extProcImage
	}
	if explicit["agentio.forward-proxy-image"] {
		config.ForwardProxyImage = *inputs.forwardProxyImage
	}
	if explicit["agentio.reuse"] {
		config.Reuse = *inputs.reuse
	}
	if explicit["agentio.enable-firewall-rules"] {
		config.EnableFirewallRules = *inputs.enableFirewall
	}
	if explicit["agentio.firewall-backend"] {
		config.FirewallBackend = *inputs.firewallBackend
	}
	if config.ForwardProxyImage == "" {
		config.ForwardProxyImage = forwardproxy.DefaultImage
	}
	if config.ChartPath == "" {
		chartPath, err := findProductionChart()
		if err != nil {
			return Config{}, err
		}
		config.ChartPath = chartPath
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

var immutableImage = regexp.MustCompile(`^[^[:space:]@]+@sha256:[0-9a-f]{64}$`)

func (c Config) Validate() error {
	if c.GatewayDataplane != "" && c.GatewayDataplane != "envoy" && c.GatewayDataplane != "agentgateway" {
		return fmt.Errorf("gateway data plane must be envoy or agentgateway, got %q", c.GatewayDataplane)
	}
	if c.Profile != ProfileSidecar && c.Profile != ProfileAmbient {
		return fmt.Errorf("Agentio profile must be sidecar or ambient, got %q", c.Profile)
	}
	if c.Namespace == "" {
		return errors.New("Agentio namespace is required")
	}
	for _, image := range []struct {
		name  string
		value string
	}{
		{name: "agentiod", value: c.AgentiodImage},
		{name: "cni", value: c.CNIImage},
		{name: "ztunnel", value: c.ZtunnelImage},
		{name: "proxy-init", value: c.ProxyInitImage},
		{name: "gateway", value: c.GatewayImage},
		{name: "epe", value: c.EPEImage},
		{name: "ext-proc", value: c.ExtProcImage},
		{name: "forward-proxy", value: c.ForwardProxyImage},
	} {
		if !immutableImage.MatchString(image.value) {
			return fmt.Errorf("%s image must use repository@sha256 followed by a 64-character digest", image.name)
		}
	}
	if c.FirewallBackend != "auto" && c.FirewallBackend != "iptables" {
		return fmt.Errorf("firewall backend must be auto or iptables, got %q", c.FirewallBackend)
	}
	return nil
}

func findProductionChart() (string, error) {
	directory, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("resolve working directory for Agentio chart: %w", err)
	}
	for {
		candidate := filepath.Join(directory, "manifests", "charts", "agentio")
		if info, statErr := os.Stat(filepath.Join(candidate, "Chart.yaml")); statErr == nil && info.Mode().IsRegular() {
			return candidate, nil
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			break
		}
		directory = parent
	}
	return "", errors.New("locate production Agentio chart: manifests/charts/agentio/Chart.yaml not found in this source tree")
}

func applyStringEnv(name string, target *string) {
	if value, found := os.LookupEnv(name); found {
		*target = value
	}
}
