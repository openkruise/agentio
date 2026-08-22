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
	"time"

	"istio.io/istio/pkg/env"
)

var (
	MeshInternalTrafficPolicy = env.Register("MESH_INTERNAL_TRAFFIC_POLICY", "PEER_AWARE",
		"Controls how mesh-internal (east-west) traffic is handled for sandbox tunnel proxies. "+
			"'PASSTHROUGH': skip upstream discovery for in-cluster destinations. "+
			"'PEER_AWARE': full peer identity matching for mTLS and policy enforcement.").Get()

	RestrictedSecretsScope = env.Register("RESTRICTED_SECRETS_SCOPE", "",
		"If set, the agentio controller will restrict the secrets it reads in the specified namespace instead of all secrets in the cluster."+
			"This is required in environments with strict RBAC policies that limit secret access, but can cause issues if sandbox workloads need to read additional secrets.").Get()

	EnableOnDemandCerts = env.Register("ENABLE_ON_DEMAND_CERTS", false,
		"If enabled, the agentio controller will sign certs for requested hostnames.").Get()

	ValidateTlsTerminatedSNI = env.Register("VALIDATE_TLS_TERMINATED_SNI", true, "Validate if sni and host header is consistent after tls terminated.").Get()

	EnableSecurityProfileStatus = env.Register("ENABLE_SECURITY_PROFILE_STATUS", true,
		"If enabled, the agentio controller writes status to SecurityProfile resources. "+
			"Only the elected leader for the revision writes; disabling this stops all "+
			"status writes without affecting the data plane.").Get()

	MeshConfigMapName = env.Register("MESH_CONFIG_MAP_NAME", "istio",
		"Name of the ConfigMap (without revision suffix) that holds the mesh configuration. "+
			"When a non-default revision is used, the suffix '-<revision>' is still appended to this name.").Get()

	InjectorConfigMapName = env.Register("INJECTOR_CONFIG_MAP_NAME", "istio-sidecar-injector",
		"Name of the ConfigMap (without revision suffix) that holds the sidecar injection template. "+
			"When a non-default revision is used, the suffix '-<revision>' is still appended to this name.").Get()

	LeaderElectionPrefix = env.Register("LEADER_ELECTION_PREFIX", "istio",
		"Prefix used for built-in leader-election lock names (ConfigMap/Lease). "+
			"For example, with the default 'istio', the gateway-status lock is named 'istio-gateway-status-leader'. "+
			"Does not affect NAMESPACE_CONTROLLER_ELECTION_NAME, which is configured separately.").Get()

	KrtEventDistributeDebounce = env.Register("KRT_EVENT_DISTRIBUTE_DEBOUNCE", time.Duration(0),
		"Debounce interval for outbound events from KRT collections. Each new event resets this timer.").Get()
	KrtEventDistributeDebounceMax = env.Register("KRT_EVENT_DISTRIBUTE_DEBOUNCE_MAX", time.Duration(0),
		"Max debounce interval for outbound events from KRT collections. Events flush when this is reached regardless.").Get()
)
