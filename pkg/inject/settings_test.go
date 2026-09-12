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

import "testing"

func TestInjectionSettingsComeFromInjectorValues(t *testing.T) {
	values, err := NewValuesConfig(`
global:
  xdsAddress: agentiod.custom.svc:15012
  proxy:
    statusPort: 16020
    holdApplicationUntilProxyStarts: true
    proxyMetadata:
      AGENTIO_META_TEST: enabled
sidecarInjectorWebhook:
  enablePrometheusMerge: false
`)
	if err != nil {
		t.Fatal(err)
	}
	settings, err := injectionSettingsFromValues(values, "agentiod.default.svc:15012")
	if err != nil {
		t.Fatal(err)
	}
	if settings.Proxy.DiscoveryAddress != "agentiod.custom.svc:15012" {
		t.Fatalf("discovery address = %q, want injector value", settings.Proxy.DiscoveryAddress)
	}
	if settings.StatusPort != 16020 {
		t.Fatalf("status port = %d, want 16020", settings.StatusPort)
	}
	if settings.EnablePrometheusMerge {
		t.Fatal("Prometheus merge enabled, want explicit injector value false")
	}
	if !settings.HoldApplicationUntilProxyStarts {
		t.Fatal("holdApplicationUntilProxyStarts disabled, want true")
	}
	if settings.Proxy.ProxyMetadata["AGENTIO_META_TEST"] != "enabled" {
		t.Fatalf("proxy metadata = %v, want AGENTIO_META_TEST=enabled", settings.Proxy.ProxyMetadata)
	}
}

func TestInjectionSettingsUseAgentioDefaults(t *testing.T) {
	values, err := NewValuesConfig(`{}`)
	if err != nil {
		t.Fatal(err)
	}
	settings, err := injectionSettingsFromValues(values, "agentiod.agentio-system.svc:15012")
	if err != nil {
		t.Fatal(err)
	}
	if settings.Proxy.DiscoveryAddress != "agentiod.agentio-system.svc:15012" ||
		settings.StatusPort != 15020 || settings.ProxyListenPort != 15001 || settings.ProxyInboundListenPort != 15006 {
		t.Fatalf("default settings = %+v", settings)
	}
	if !settings.EnablePrometheusMerge {
		t.Fatal("Prometheus merge disabled by default")
	}
}
