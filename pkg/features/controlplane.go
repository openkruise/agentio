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

package features

import (
	"fmt"
	"math"
	"os"
	"strings"

	"istio.io/istio/pkg/env"
)

var (
	// EnablePolicyStatus enables advisory policy validation and status reporting.
	EnablePolicyStatus = env.Register(
		"ENABLE_POLICY_STATUS",
		true,
		"Enable advisory validation and status reporting for SecurityProfile and TrafficPolicy resources, including global variants. False disables the status controller and its leader election; existing status is retained.",
	).Get()
	// SandboxMode enables Kruise discovery and Sandbox resources alongside Workloads.
	SandboxMode = env.Register(
		"AGENTIO_SANDBOX_MODE",
		false,
		"Enable Kruise Sandbox discovery and Sandbox xDS resources. Inline SNI also projects to the bound Workload when it hosts one Sandbox for legacy compatibility; shared policies remain on Workloads.",
	).Get()
	// ScopedSecrets restricts the shared Secret informer to the control-plane namespace.
	// Dedicated named Secret informers keep their own scope.
	ScopedSecrets = env.Register(
		"AGENTIO_SCOPED_SECRETS",
		true,
		"Watch only the root namespace in the shared Secret informer. False watches all namespaces and requires cluster-wide Secret list/watch RBAC.",
	).Get()
	// KubernetesAPIQPS configures client-side Kubernetes API request throttling.
	KubernetesAPIQPS = env.Register(
		"AGENTIO_KUBERNETES_API_QPS",
		80.0,
		"Client-side Kubernetes API requests per second. Must be finite and positive.",
	).Get()
	// KubernetesAPIBurst bounds bursts allowed by Kubernetes client throttling.
	KubernetesAPIBurst = env.Register(
		"AGENTIO_KUBERNETES_API_BURST",
		160,
		"Client-side Kubernetes API request burst. Must be positive.",
	).Get()
	TokenAudience = env.Register(
		"AGENTIO_TOKEN_AUDIENCE",
		"agentio-ca",
		"Audience a client token must carry to be accepted.",
	).Get()
	KubernetesWorkloadAuthMode = env.Register(
		"AGENTIO_KUBERNETES_WORKLOAD_AUTH_MODE",
		"tokenreview",
		"Kubernetes workload authentication: tokenreview or local. Local JWT verification requires active Pod and ServiceAccount bindings.",
	).Get()
	ServiceName = env.Register(
		"AGENTIO_SERVICE_NAME",
		"agentiod",
		"Kubernetes service name placed in the xDS server certificate.",
	).Get()
	ZTunnelAccount = env.Register(
		"AGENTIO_TRUSTED_NODE_ACCOUNTS",
		"",
		"If set, the list of service accounts that are allowed to use node authentication for CSRs. "+
			"Node authentication allows an identity to create CSRs on behalf of other identities, but only if there is a pod "+
			"running on the same node with that identity. This is intended for use with node proxies.",
	).Get()
	AgentioConfigMapName = env.Register(
		"AGENTIO_CONFIGMAP_NAME",
		"agentio-config",
		"ConfigMap name of Agentio configuration.",
	).Get()
	PrimaryAgentioConfigMapName = env.Register(
		"AGENTIO_PRIMARY_CONFIGMAP_NAME",
		"agentio-config-primary",
		"ConfigMap name of primary Agentio configuration. Empty disables the primary overlay.",
	).Get()
	IgnoreResources = env.Register(
		"AGENTIO_IGNORE_RESOURCES",
		"",
		"Comma-separated CRD names excluded from the CRD watcher; a \"*.\" prefix excludes a whole group by suffix (e.g. \"*.istio.io\").",
	).Get()
	IncludeResources = env.Register(
		"AGENTIO_INCLUDE_RESOURCES",
		"",
		"Comma-separated CRD names always admitted to the CRD watcher, overriding AGENTIO_IGNORE_RESOURCES; same \"*.\" group-suffix syntax.",
	).Get()
	EnableDebugOnHTTP = env.Register(
		"AGENTIO_ENABLE_DEBUG_ON_HTTP",
		true,
		"Enable authenticated debug handlers on the monitoring HTTP listener.",
	).Get()
)

func validateControlPlane() error {
	if _, set := os.LookupEnv("AGENTIO_SANDBOX_RUNTIMES"); set {
		return fmt.Errorf("AGENTIO_SANDBOX_RUNTIMES is no longer supported; remove it and use AGENTIO_SANDBOX_MODE")
	}
	if KubernetesWorkloadAuthMode != "tokenreview" && KubernetesWorkloadAuthMode != "local" {
		return fmt.Errorf("unsupported Kubernetes workload authentication mode %q", KubernetesWorkloadAuthMode)
	}
	if strings.TrimSpace(TokenAudience) == "" {
		return fmt.Errorf("token audience is required")
	}
	return ValidateKubernetesAPILimits()
}

// ValidateKubernetesAPILimits checks the settings shared by agentiod and EPE.
func ValidateKubernetesAPILimits() error {
	// client-go stores QPS as float32; validate the value it will actually use.
	qps := float32(KubernetesAPIQPS)
	if qps <= 0 || math.IsNaN(float64(qps)) || math.IsInf(float64(qps), 0) {
		return fmt.Errorf("Kubernetes API QPS must be finite and positive as a float32")
	}
	if KubernetesAPIBurst <= 0 {
		return fmt.Errorf("Kubernetes API burst must be positive")
	}
	return nil
}
