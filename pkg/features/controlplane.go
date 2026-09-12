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
	"strings"

	"istio.io/istio/pkg/env"
)

var (
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
	if strings.TrimSpace(TokenAudience) == "" {
		return fmt.Errorf("token audience is required")
	}
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
