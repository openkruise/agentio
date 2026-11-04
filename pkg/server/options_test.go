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

package server

import (
	"strings"
	"testing"

	"istio.io/istio/pkg/test"

	"github.com/openkruise/agentio/pkg/features"
)

func TestOptionsValidateAcceptsProductionDefaults(t *testing.T) {
	if err := DefaultOptions().Validate(); err != nil {
		t.Fatalf("valid options rejected: %v", err)
	}
}

func TestAgentioTrustedNodeAccountCompatibility(t *testing.T) {
	for _, tt := range []struct {
		name       string
		configured string
		want       string
	}{
		{name: "bare service account", configured: "ztunnel", want: "ztunnel"},
		{name: "Agentio namespaced service account", configured: "agentio-system/ztunnel", want: "ztunnel"},
		{name: "Agentio account list", configured: "other/node-proxy,agentio-system/ztunnel", want: "ztunnel"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := trustedNodeServiceAccount("agentio-system", tt.configured)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("trustedNodeServiceAccount() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestOptionsValidateRejectsPlaintextDiscoveryPort(t *testing.T) {
	options := DefaultOptions()
	options.DiscoveryAddress = ":15010"
	if err := options.Validate(); err == nil {
		t.Fatal("plaintext discovery port must be rejected")
	}
}

func TestOptionsValidateRejectsUnsafeValues(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Options)
		want   string
	}{
		{"monitoring address", func(o *Options) { o.MonitoringAddress = "" }, "monitoring address"},
		{"cluster ID", func(o *Options) { o.ClusterID = "" }, "cluster ID"},
		{"root namespace", func(o *Options) { o.RootNamespace = "" }, "root namespace"},
		{"cluster domain", func(o *Options) { o.ClusterDomain = "" }, "cluster domain"},
		{"trust domain", func(o *Options) { o.TrustDomain = "" }, "trust domain"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := DefaultOptions()
			tt.mutate(&options)
			err := options.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() error = %v, want error containing %q", err, tt.want)
			}
		})
	}
}

func TestFeaturesValidateRejectsUnsafeValues(t *testing.T) {
	t.Run("gateway connect timeout", func(t *testing.T) {
		test.SetForTest(t, &features.GatewayConnectTimeout, 0)
		if err := features.Validate(); err == nil || !strings.Contains(err.Error(), "gateway connect timeout") {
			t.Fatalf("Validate() error = %v, want gateway connect timeout error", err)
		}
	})
	t.Run("empty public CA package path", func(t *testing.T) {
		test.SetForTest(t, &features.ClientTrustPackagePath, "")
		if err := features.Validate(); err == nil ||
			!strings.Contains(err.Error(), "public CA trust package path is required") {
			t.Fatalf("Validate() error = %v, want required public CA package path error", err)
		}
	})
	t.Run("gateway deployer lease", func(t *testing.T) {
		test.SetForTest(t, &features.EnableGatewayDeployer, true)
		test.SetForTest(t, &features.GatewayLeaseName, " ")
		if err := features.Validate(); err == nil || !strings.Contains(err.Error(), "gateway deployer lease name") {
			t.Fatalf("Validate() error = %v, want gateway deployer lease error", err)
		}
	})
}
