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
	"runtime"
	"runtime/debug"

	"github.com/openkruise/agentio/pkg/features"
)

// Log an allowlist of effective settings, not the environment, kubeconfig, or
// certificate contents. Reading the current Go memory limit does not change it.
func logStartup(options Options) {
	version, revision, modified := "unknown", "unknown", "unknown"
	if build, ok := debug.ReadBuildInfo(); ok {
		if build.Main.Version != "" {
			version = build.Main.Version
		}
		for _, setting := range build.Settings {
			switch setting.Key {
			case "vcs.revision":
				revision = setting.Value
			case "vcs.modified":
				modified = setting.Value
			}
		}
	}
	log.Info("starting agentiod", "version", version, "revision", revision, "modified", modified,
		"go_version", runtime.Version(), "gomaxprocs", runtime.GOMAXPROCS(0),
		"go_memory_limit_bytes", debug.SetMemoryLimit(-1),
		"xds_address", options.DiscoveryAddress, "monitoring_address", options.MonitoringAddress,
		"cluster_id", options.ClusterID, "namespace", options.RootNamespace, "trust_domain", options.TrustDomain,
		"sidecar_injector", features.EnableSidecarInjector,
		"sandbox_mode", features.SandboxMode,
		"kubernetes_api_qps", features.KubernetesAPIQPS, "kubernetes_api_burst", features.KubernetesAPIBurst,
		"xds_request_rate_limit", features.RequestRateLimit, "push_concurrency", features.PushConcurrency,
		"xds_cpu_budget", features.XDSCPUBudget, "xds_effective_cpu_cores", features.XDSCPUCores,
		"xds_cpu_runtime_fallback", features.XDSCPUBudget == "",
		"max_connection_age", features.MaxServerConnectionAge,
		"krt_debounce", features.KRTDebounceAfter, "krt_debounce_max", features.KRTDebounceMax,
		"push_debounce", features.PushDebounceAfter, "push_debounce_max", features.PushDebounceMax)
}
