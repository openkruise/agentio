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
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveConfigDefaultsToProductionChart(t *testing.T) {
	image := "registry.example/image@sha256:" + strings.Repeat("a", 64)
	fs := flag.NewFlagSet("agentio", flag.ContinueOnError)
	inputs := RegisterFlags(fs)
	if err := fs.Parse(validImageArgs(image)); err != nil {
		t.Fatal(err)
	}
	config, err := ResolveConfig(inputs)
	if err != nil {
		t.Fatal(err)
	}
	if config.ReleaseName != "agentio" {
		t.Fatalf("release name = %q, want agentio", config.ReleaseName)
	}
	chartFile := filepath.Join(config.ChartPath, "Chart.yaml")
	if _, err := os.Stat(chartFile); err != nil {
		t.Fatalf("default chart path %q is not the production Agentio chart: %v", config.ChartPath, err)
	}
}

func TestResolveConfigDefaultsForwardProxyFixtureImage(t *testing.T) {
	image := "registry.example/image@sha256:" + strings.Repeat("a", 64)
	t.Setenv("AGENTIO_E2E_FORWARD_PROXY_IMAGE", "")
	fs := flag.NewFlagSet("agentio", flag.ContinueOnError)
	inputs := RegisterFlags(fs)
	args := make([]string, 0, len(validImageArgs(image))-1)
	for _, argument := range validImageArgs(image) {
		if !strings.HasPrefix(argument, "-agentio.forward-proxy-image=") {
			args = append(args, argument)
		}
	}
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	config, err := ResolveConfig(inputs)
	if err != nil {
		t.Fatal(err)
	}
	const want = "docker.io/envoyproxy/envoy@sha256:57e14a549d7bd43c8d3f6d03e8cfa653e037d4b38e133acd9b54f38c524401b4"
	if config.ForwardProxyImage != want {
		t.Fatalf("forward proxy image = %q, want %q", config.ForwardProxyImage, want)
	}
}

func TestResolveConfigRequiresImmutableImages(t *testing.T) {
	valid := "registry.example/image@sha256:" + strings.Repeat("a", 64)
	tests := []struct {
		name, component, image string
	}{
		{name: "missing agentiod", component: "agentiod", image: ""},
		{name: "tagged cni", component: "cni", image: "repo/cni:v1"},
		{name: "missing cni", component: "cni", image: ""},
		{name: "tagged ztunnel", component: "ztunnel", image: "repo/ztunnel:v1"},
		{name: "short proxy init digest", component: "proxy-init", image: "repo/proxy@sha256:abc"},
		{name: "missing gateway", component: "gateway", image: ""},
		{name: "tagged epe", component: "epe", image: "repo/epe:latest"},
		{name: "tagged porter", component: "porter", image: "repo/porter:latest"},
		{name: "short ext proc digest", component: "ext-proc", image: "repo/ext-proc@sha256:abc"},
		{name: "tagged forward proxy", component: "forward-proxy", image: "repo/envoy:v1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("agentio", flag.ContinueOnError)
			inputs := RegisterFlags(fs)
			args := validImageArgs(valid)
			if tc.component == "cni" {
				args = append(args, "-agentio.profile=ambient")
			}
			for index, argument := range args {
				if strings.HasPrefix(argument, "-agentio."+tc.component+"-image=") {
					args[index] = "-agentio." + tc.component + "-image=" + tc.image
				}
			}
			if err := fs.Parse(args); err != nil {
				t.Fatal(err)
			}
			_, err := ResolveConfig(inputs)
			if err == nil || !strings.Contains(err.Error(), tc.component) ||
				!strings.Contains(err.Error(), "repository@sha256") {
				t.Fatalf("ResolveConfig() error = %v", err)
			}
		})
	}
}

func TestResolveConfigUsesEnvironmentThenCLI(t *testing.T) {
	envImage := "registry.example/env@sha256:" + strings.Repeat("a", 64)
	cliImage := "registry.example/cli@sha256:" + strings.Repeat("b", 64)
	t.Setenv("AGENTIO_E2E_PROFILE", "sidecar")
	t.Setenv("AGENTIO_E2E_AGENTIOD_IMAGE", envImage)
	t.Setenv("AGENTIO_E2E_CNI_IMAGE", envImage)
	t.Setenv("AGENTIO_E2E_ZTUNNEL_IMAGE", envImage)
	t.Setenv("AGENTIO_E2E_PROXY_INIT_IMAGE", envImage)
	t.Setenv("AGENTIO_E2E_GATEWAY_IMAGE", envImage)
	t.Setenv("AGENTIO_E2E_EPE_IMAGE", envImage)
	t.Setenv("AGENTIO_E2E_PORTER_IMAGE", envImage)
	t.Setenv("AGENTIO_E2E_EXT_PROC_IMAGE", envImage)
	t.Setenv("AGENTIO_E2E_FORWARD_PROXY_IMAGE", envImage)
	t.Setenv("AGENTIO_E2E_ENABLE_FIREWALL_RULES", "true")
	t.Setenv("AGENTIO_E2E_FIREWALL_BACKEND", "iptables")
	fs := flag.NewFlagSet("agentio", flag.ContinueOnError)
	inputs := RegisterFlags(fs)
	if err := fs.Parse([]string{
		"-agentio.profile=ambient",
		"-agentio.agentiod-image=" + cliImage,
		"-agentio.cni-image=" + cliImage,
		"-agentio.gateway-image=" + cliImage,
		"-agentio.epe-image=" + cliImage,
		"-agentio.porter-image=" + cliImage,
		"-agentio.ext-proc-image=" + cliImage,
		"-agentio.forward-proxy-image=" + cliImage,
		"-agentio.enable-firewall-rules=false",
		"-agentio.firewall-backend=auto",
	}); err != nil {
		t.Fatal(err)
	}
	cfg, err := ResolveConfig(inputs)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Profile != "ambient" || cfg.AgentiodImage != cliImage || cfg.CNIImage != cliImage ||
		cfg.ZtunnelImage != envImage || cfg.ProxyInitImage != envImage ||
		cfg.GatewayImage != cliImage || cfg.EPEImage != cliImage || cfg.PorterImage != cliImage || cfg.ExtProcImage != cliImage || cfg.ForwardProxyImage != cliImage ||
		cfg.EnableFirewallRules || cfg.FirewallBackend != "auto" {
		t.Fatalf("config = %+v", cfg)
	}
}

func TestResolveConfigAdditionalImagePrecedenceFromFileEnvironmentAndCLI(t *testing.T) {
	fileImage := "registry.example/file@sha256:" + strings.Repeat("a", 64)
	envImage := "registry.example/env@sha256:" + strings.Repeat("b", 64)
	cliImage := "registry.example/cli@sha256:" + strings.Repeat("c", 64)
	configPath := filepath.Join(t.TempDir(), "agentio.yaml")
	if err := os.WriteFile(
		configPath,
		[]byte(
			"profile: sidecar\nnamespace: agentio-system\nagentiod-image: "+fileImage+"\ncni-image: "+fileImage+"\nztunnel-image: "+fileImage+"\nproxy-init-image: "+fileImage+"\ngateway-image: "+fileImage+"\nporter-image: "+fileImage+"\nepe-image: "+fileImage+"\next-proc-image: "+fileImage+"\nforward-proxy-image: "+fileImage+"\n",
		),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, environment, flagName string
		value                       func(Config) string
	}{
		{
			name:        "cni",
			environment: "AGENTIO_E2E_CNI_IMAGE",
			flagName:    "cni",
			value:       func(config Config) string { return config.CNIImage },
		},
		{
			name:        "gateway",
			environment: "AGENTIO_E2E_GATEWAY_IMAGE",
			flagName:    "gateway",
			value:       func(config Config) string { return config.GatewayImage },
		},
		{
			name:        "epe",
			environment: "AGENTIO_E2E_EPE_IMAGE",
			flagName:    "epe",
			value:       func(config Config) string { return config.EPEImage },
		},
		{
			name:        "porter",
			environment: "AGENTIO_E2E_PORTER_IMAGE",
			flagName:    "porter",
			value:       func(config Config) string { return config.PorterImage },
		},
		{
			name:        "ext proc",
			environment: "AGENTIO_E2E_EXT_PROC_IMAGE",
			flagName:    "ext-proc",
			value:       func(config Config) string { return config.ExtProcImage },
		},
		{
			name:        "forward proxy",
			environment: "AGENTIO_E2E_FORWARD_PROXY_IMAGE",
			flagName:    "forward-proxy",
			value:       func(config Config) string { return config.ForwardProxyImage },
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resolve := func(args ...string) Config {
				t.Helper()
				fs := flag.NewFlagSet("agentio", flag.ContinueOnError)
				inputs := RegisterFlags(fs)
				if err := fs.Parse(append([]string{"-agentio.config=" + configPath}, args...)); err != nil {
					t.Fatal(err)
				}
				config, err := ResolveConfig(inputs)
				if err != nil {
					t.Fatal(err)
				}
				return config
			}
			if got := tc.value(resolve()); got != fileImage {
				t.Fatalf("file image = %q, want %q", got, fileImage)
			}
			t.Setenv(tc.environment, envImage)
			if got := tc.value(resolve()); got != envImage {
				t.Fatalf("environment image = %q, want %q", got, envImage)
			}
			if got := tc.value(resolve("-agentio." + tc.flagName + "-image=" + cliImage)); got != cliImage {
				t.Fatalf("CLI image = %q, want %q", got, cliImage)
			}
		})
	}
}

func TestResolveConfigRejectsInvalidFirewallInputs(t *testing.T) {
	valid := "registry.example/image@sha256:" + strings.Repeat("a", 64)
	t.Run("boolean environment", func(t *testing.T) {
		t.Setenv("AGENTIO_E2E_ENABLE_FIREWALL_RULES", "sometimes")
		fs := flag.NewFlagSet("agentio", flag.ContinueOnError)
		inputs := RegisterFlags(fs)
		if err := fs.Parse(validImageArgs(valid)); err != nil {
			t.Fatal(err)
		}
		if _, err := ResolveConfig(
			inputs,
		); err == nil ||
			!strings.Contains(err.Error(), "AGENTIO_E2E_ENABLE_FIREWALL_RULES") {
			t.Fatalf("ResolveConfig() error = %v", err)
		}
	})
	t.Run("backend", func(t *testing.T) {
		fs := flag.NewFlagSet("agentio", flag.ContinueOnError)
		inputs := RegisterFlags(fs)
		if err := fs.Parse(append(validImageArgs(valid),
			"-agentio.firewall-backend=nftables",
		)); err != nil {
			t.Fatal(err)
		}
		if _, err := ResolveConfig(inputs); err == nil || !strings.Contains(err.Error(), "firewall backend") {
			t.Fatalf("ResolveConfig() error = %v", err)
		}
	})
}

func TestResolveConfigRejectsInvalidProfile(t *testing.T) {
	valid := "registry.example/image@sha256:" + strings.Repeat("a", 64)
	fs := flag.NewFlagSet("agentio", flag.ContinueOnError)
	inputs := RegisterFlags(fs)
	if err := fs.Parse(append(validImageArgs(valid), "-agentio.profile=mixed")); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveConfig(inputs); err == nil || !strings.Contains(err.Error(), "profile") {
		t.Fatalf("ResolveConfig() error = %v", err)
	}
}

func validImageArgs(image string) []string {
	return []string{
		"-agentio.agentiod-image=" + image,
		"-agentio.cni-image=" + image,
		"-agentio.ztunnel-image=" + image,
		"-agentio.proxy-init-image=" + image,
		"-agentio.gateway-image=" + image,
		"-agentio.epe-image=" + image,
		"-agentio.porter-image=" + image,
		"-agentio.ext-proc-image=" + image,
		"-agentio.forward-proxy-image=" + image,
	}
}

func TestGatewayDataplaneResolution(t *testing.T) {
	valid := "registry.example/image@sha256:" + strings.Repeat("a", 64)
	resolve := func(args ...string) (Config, error) {
		fs := flag.NewFlagSet("agentio", flag.ContinueOnError)
		inputs := RegisterFlags(fs)
		if err := fs.Parse(append(validImageArgs(valid), args...)); err != nil {
			t.Fatal(err)
		}
		return ResolveConfig(inputs)
	}
	if c, err := resolve(); err != nil || c.GatewayDataplane != "" {
		t.Fatalf("default: %v %v", c.GatewayDataplane, err)
	}
	t.Setenv("AGENTIO_E2E_GATEWAY_DATAPLANE", "agentgateway")
	if c, err := resolve(); err != nil || c.GatewayDataplane != "agentgateway" {
		t.Fatalf("environment: %v %v", c.GatewayDataplane, err)
	}
	if c, err := resolve("-agentio.gateway-dataplane=envoy"); err != nil || c.GatewayDataplane != "envoy" {
		t.Fatalf("CLI: %v %v", c.GatewayDataplane, err)
	}
	if _, err := resolve("-agentio.gateway-dataplane=unknown"); err == nil {
		t.Fatal("unsupported gateway data plane accepted")
	}
}
