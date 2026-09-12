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

import "istio.io/istio/pkg/env"

var (
	// EnableClientTrustDistributor gates client CA distribution and injection at startup.
	EnableClientTrustDistributor = env.Register(
		"AGENTIO_ENABLE_CLIENT_TRUST_DISTRIBUTOR",
		false,
		"Enable client CA distribution and injection with the sidecar injector.",
	).Get()
	// ClientTrustPackagePath points to the versioned public certificate package.
	ClientTrustPackagePath = env.Register(
		"AGENTIO_CLIENT_TRUST_PACKAGE_PATH",
		"",
		"Path to the versioned public CA trust package JSON.",
	).Get()
	// EnableSidecarInjector enables the Pod admission endpoint.
	EnableSidecarInjector = env.Register(
		"AGENTIO_ENABLE_SIDECAR_INJECTOR",
		false,
		"If true, serve the Agentio ztunnel injection webhook at the Istio-compatible /inject endpoint.",
	).Get()
	InjectorConfigMapName = env.Register(
		"AGENTIO_INJECTOR_CONFIGMAP_NAME",
		"agentio-sidecar-injector",
		"ConfigMap carrying the ztunnel and egress-gateway templates and their shared values.",
	).Get()
	InjectionWebhookConfigName = env.Register(
		"AGENTIO_INJECTION_WEBHOOK_CONFIG_NAME",
		"",
		"Istio-compatible MutatingWebhookConfiguration whose caBundle is kept in sync with the workload root.",
	).Get()
	NativeSidecarMode = env.Register(
		"AGENTIO_NATIVE_SIDECARS",
		"auto",
		"Native sidecar injection mode: true, false, or auto (per-node kubelet version detection).",
	).Get()
)
