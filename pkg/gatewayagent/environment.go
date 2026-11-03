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

import "istio.io/istio/pkg/env"

// Register descriptors once; Get reads the environment when configuration is loaded.
var (
	xdsAddressEnv = env.Register("AGENTIO_XDS_ADDRESS", "", "Control-plane ADS address (host:port).")
	rootCAEnv     = env.Register(
		"AGENTIO_ROOT_CA",
		"/var/run/secrets/agentio/root-cert.pem",
		"Workload trust bundle path.",
	)
	configDirEnv = env.Register(
		"AGENTIO_CONFIG_DIR",
		"/etc/agentio/proxy",
		"Writable Envoy configuration and ADS socket directory.",
	)
	envoyBinaryEnv    = env.Register("ENVOY_BINARY", "/usr/local/bin/envoy", "Envoy executable path.")
	podNameEnv        = env.Register("POD_NAME", "", "Pod name.")
	namespaceEnv      = env.Register("POD_NAMESPACE", "", "Pod namespace.")
	podUIDEnv         = env.Register("POD_UID", "", "Pod UID.")
	nodeNameEnv       = env.Register("NODE_NAME", "", "Kubernetes node name.")
	serviceAccountEnv = env.Register("SERVICE_ACCOUNT", "", "Workload service account.")
	instanceIPEnv     = env.Register("INSTANCE_IP", "", "Primary Pod IP address.")
	clusterIDEnv      = env.Register("CLUSTER_ID", "Kubernetes", "Cluster identity.")
	trustDomainEnv    = env.Register("TRUST_DOMAIN", "cluster.local", "SPIFFE trust domain.")
	tokenFileEnv      = env.Register(
		"AGENTIO_TOKEN_FILE",
		"/var/run/secrets/tokens/agentio-token",
		"Projected service account token path.",
	)
	caAddressEnv     = env.Register("CA_ADDR", "", "Certificate authority address; empty uses AGENTIO_XDS_ADDRESS.")
	caTokenFileEnv   = env.Register("AGENTIO_CA_TOKEN_FILE", "", "Projected CA token path; empty uses AGENTIO_TOKEN_FILE.")
	xdsServerNameEnv = env.Register("AGENTIO_XDS_SERVER_NAME", "", "TLS server name for ADS.")
	caServerNameEnv  = env.Register("AGENTIO_CA_SERVER_NAME", "", "TLS server name for the certificate authority.")
	caRootCAEnv      = env.Register(
		"AGENTIO_CA_ROOT_CA",
		"",
		"CA connection trust bundle; empty uses AGENTIO_ROOT_CA.",
	)
	xdsRootCAEnv = env.Register(
		"AGENTIO_XDS_ROOT_CA",
		"",
		"ADS connection trust bundle; empty uses AGENTIO_ROOT_CA.",
	)
	serviceClusterEnv = env.Register("AGENTIO_SERVICE_CLUSTER", "agentio-egress", "Envoy node cluster name.")
	gatewayConfigEnv  = env.Register("AGENTIO_GATEWAY_CONFIG", "", "Gateway runtime options as YAML or JSON.")
	cpuLimitEnv       = env.Register(
		"AGENTIO_CPU_LIMIT",
		"",
		"CPU limit as a positive integer, used when concurrency is omitted.",
	)
	terminationGraceEnv = env.Register(
		"AGENTIO_TERMINATION_GRACE_PERIOD_SECONDS",
		"",
		"Pod termination grace period in seconds.",
	)
)
