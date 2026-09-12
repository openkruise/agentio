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
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/openkruise/agentio/pkg/features"
	"istio.io/istio/pkg/util/sets"
)

func TestDefaultOptionsContainsOnlyProcessWiring(t *testing.T) {
	options := DefaultOptions()
	if err := options.Validate(); err != nil {
		t.Fatalf("defaults are not valid process wiring: %v", err)
	}
	if options.DiscoveryAddress != ":15012" || options.MonitoringAddress != ":15014" {
		t.Fatalf("unexpected listener defaults: discovery=%q monitoring=%q",
			options.DiscoveryAddress, options.MonitoringAddress)
	}
	if options.ClusterID != "Kubernetes" || options.RootNamespace != "agentio-system" ||
		options.ClusterDomain != "cluster.local" || options.TrustDomain != "cluster.local" {
		t.Fatalf("unexpected identity defaults: %+v", options)
	}
}

func TestPilotCAConfigMapVariableIsIgnored(t *testing.T) {
	if os.Getenv("AGENTIO_ENV_ALIAS_HELPER") == "true" {
		if features.CAConfigMapName != "agentio-ca-certs" || features.TrustBundleConfigMapName != "agentio-ca-root-cert" {
			t.Fatalf("CA ConfigMaps = root %q distributed %q, want Agentio defaults",
				features.CAConfigMapName, features.TrustBundleConfigMapName)
		}
		return
	}

	command := exec.Command(os.Args[0], "-test.run=^TestPilotCAConfigMapVariableIsIgnored$")
	command.Env = append(environmentWithout(
		os.Environ(),
		"PILOT_CA_CERT_CONFIGMAP",
		"AGENTIO_CA_CONFIGMAP_NAME",
		"AGENTIO_TRUST_BUNDLE_CONFIGMAP_NAME",
		"AGENTIO_ENV_ALIAS_HELPER",
	),
		"PILOT_CA_CERT_CONFIGMAP=agentio-chart-ca",
		"AGENTIO_ENV_ALIAS_HELPER=true",
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("subprocess failed: %v\n%s", err, output)
	}
}

func TestPilotRequestRateLimitVariableIsIgnored(t *testing.T) {
	if os.Getenv("AGENTIO_REQUEST_RATE_HELPER") == "true" {
		if features.RequestRateLimit != float64(features.PushConcurrency) {
			t.Fatalf("request rate limit = %v, want derived Agentio default %v",
				features.RequestRateLimit, features.PushConcurrency)
		}
		return
	}

	command := exec.Command(os.Args[0], "-test.run=^TestPilotRequestRateLimitVariableIsIgnored$")
	command.Env = append(environmentWithout(
		os.Environ(),
		"AGENTIO_MAX_REQUESTS_PER_SECOND",
		"AGENTIO_PUSH_CONCURRENCY",
		"PILOT_MAX_REQUESTS_PER_SECOND",
		"AGENTIO_REQUEST_RATE_HELPER",
	),
		"PILOT_MAX_REQUESTS_PER_SECOND=11",
		"AGENTIO_REQUEST_RATE_HELPER=true",
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("subprocess failed: %v\n%s", err, output)
	}
}

func TestAgentioRequestRateLimitIsApplied(t *testing.T) {
	if os.Getenv("AGENTIO_REQUEST_RATE_VALUE_HELPER") == "true" {
		if features.RequestRateLimit != 23 {
			t.Fatalf("request rate limit = %v, want 23", features.RequestRateLimit)
		}
		return
	}

	command := exec.Command(os.Args[0], "-test.run=^TestAgentioRequestRateLimitIsApplied$")
	command.Env = append(environmentWithout(
		os.Environ(),
		"AGENTIO_MAX_REQUESTS_PER_SECOND",
		"PILOT_MAX_REQUESTS_PER_SECOND",
		"AGENTIO_REQUEST_RATE_VALUE_HELPER",
	),
		"AGENTIO_MAX_REQUESTS_PER_SECOND=23",
		"AGENTIO_REQUEST_RATE_VALUE_HELPER=true",
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("subprocess failed: %v\n%s", err, output)
	}
}

func TestAgentioMaxServerConnectionAgeIsApplied(t *testing.T) {
	if os.Getenv("AGENTIO_CONNECTION_AGE_VALUE_HELPER") == "true" {
		if features.MaxServerConnectionAge != 47*time.Second {
			t.Fatalf("max server connection age = %v, want 47s", features.MaxServerConnectionAge)
		}
		return
	}

	command := exec.Command(os.Args[0], "-test.run=^TestAgentioMaxServerConnectionAgeIsApplied$")
	command.Env = append(environmentWithout(
		os.Environ(),
		"AGENTIO_KEEPALIVE_MAX_SERVER_CONNECTION_AGE",
		"AGENTIO_CONNECTION_AGE_VALUE_HELPER",
	),
		"AGENTIO_KEEPALIVE_MAX_SERVER_CONNECTION_AGE=47s",
		"AGENTIO_CONNECTION_AGE_VALUE_HELPER=true",
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("subprocess failed: %v\n%s", err, output)
	}
}

func TestAgentioMaxServerConnectionAgeRejectsInvalidDuration(t *testing.T) {
	if os.Getenv("AGENTIO_CONNECTION_AGE_INVALID_HELPER") == "true" {
		if err := features.Validate(); err == nil || !strings.Contains(err.Error(), "max server connection age") {
			t.Fatalf("Validate() error = %v, want max server connection age error", err)
		}
		return
	}

	command := exec.Command(os.Args[0], "-test.run=^TestAgentioMaxServerConnectionAgeRejectsInvalidDuration$")
	command.Env = append(environmentWithout(
		os.Environ(),
		"AGENTIO_KEEPALIVE_MAX_SERVER_CONNECTION_AGE",
		"AGENTIO_CONNECTION_AGE_INVALID_HELPER",
	),
		"AGENTIO_KEEPALIVE_MAX_SERVER_CONNECTION_AGE=not-a-duration",
		"AGENTIO_CONNECTION_AGE_INVALID_HELPER=true",
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("subprocess failed: %v\n%s", err, output)
	}
}

func environmentWithout(environment []string, names ...string) []string {
	excluded := sets.NewWithLength[string](len(names))
	for _, name := range names {
		excluded.Insert(name)
	}
	result := make([]string, 0, len(environment))
	for _, variable := range environment {
		name, _, _ := strings.Cut(variable, "=")
		if !excluded.Contains(name) {
			result = append(result, variable)
		}
	}
	return result
}

func TestPrintEnvironmentListsRegisteredVariables(t *testing.T) {
	var out strings.Builder
	if err := PrintEnvironment(&out); err != nil {
		t.Fatal(err)
	}
	body := out.String()
	for _, variable := range []string{
		"AGENTIO_TOKEN_AUDIENCE",
		"AGENTIO_SCOPED_SECRETS",
		"AGENTIO_CONFIGMAP_NAME",
		"AGENTIO_ENABLE_DEBUG_ON_HTTP",
		"AGENTIO_PRIMARY_CONFIGMAP_NAME",
		"AGENTIO_KRT_DEBOUNCE",
		"AGENTIO_CA_SECRET_NAME",
		"AGENTIO_MITM_CA_SECRET_NAMESPACE",
		"AGENTIO_GATEWAY_CONNECT_TIMEOUT",
		"AGENTIO_ENABLE_GATEWAY_DEPLOYER",
		"AGENTIO_ENABLE_SIDECAR_INJECTOR",
		"AGENTIO_ENABLE_CLIENT_TRUST_DISTRIBUTOR",
		"AGENTIO_MAX_REQUESTS_PER_SECOND",
		"AGENTIO_KEEPALIVE_MAX_SERVER_CONNECTION_AGE",
		"AGENTIO_ENABLE_SNI_TRAFFIC_POLICY",
		"AGENTIO_MESH_INTERNAL_TRAFFIC_POLICY",
	} {
		if !strings.Contains(body, variable) {
			t.Errorf("missing %s in the environment dump", variable)
		}
	}
	if !strings.Contains(body, "agentiod-ca-leader") {
		t.Fatalf("defaults are not shown:\n%s", body)
	}
	if strings.Contains(body, "Requires PILOT_ENABLE_AMBIENT") {
		t.Fatalf("environment help contains a removed Pilot dependency:\n%s", body)
	}
	for _, removed := range []string{
		"CA_TRUSTED_NODE_ACCOUNTS",
		"ENABLE_DEBUG_ON_HTTP",
		"ENABLE_SNI_TRAFFIC_POLICY",
		"INJECTION_WEBHOOK_CONFIG_NAME",
		"KRT_EVENT_DISTRIBUTE_DEBOUNCE",
		"MESH_INTERNAL_TRAFFIC_POLICY",
		"PRIMARY_AGENTIO_CONFIGMAP_NAME",
		"REVISION",
		"AGENTIO_GATEWAY_DEPLOYER",
		"AGENTIO_GATEWAY_VALUES_FILE",
		"AGENTIO_SIDECAR_INJECTOR",
		"AGENTIO_MESH_CONFIGMAP_NAME",
	} {
		if strings.Contains(body, "\n"+removed+" ") {
			t.Errorf("removed variable %s is still present in the environment dump", removed)
		}
	}
}

func TestSecretNamespaceScopeFeatureFlag(t *testing.T) {
	const variable = "AGENTIO_SCOPED_SECRETS"
	const helper = "AGENTIO_SECRET_SCOPE_TEST_HELPER"
	if expected := os.Getenv(helper); expected != "" {
		if features.ScopedSecrets != (expected == "true") {
			t.Fatalf("ScopedSecrets = %v, want %s", features.ScopedSecrets, expected)
		}
		return
	}
	for _, value := range []string{"", "true", "false"} {
		command := exec.Command(os.Args[0], "-test.run=^TestSecretNamespaceScopeFeatureFlag$")
		command.Env = environmentWithout(os.Environ(), variable, helper)
		expected := "true"
		if value != "" {
			command.Env = append(command.Env, variable+"="+value)
			expected = value
		}
		command.Env = append(command.Env, helper+"="+expected)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("flag %q failed: %v\n%s", value, err, output)
		}
	}
}
