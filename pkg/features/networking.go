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
	"os"
	"strings"
	"time"

	"istio.io/istio/pkg/env"

	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
)

var (
	GatewayConnectTimeout = env.Register(
		"AGENTIO_GATEWAY_CONNECT_TIMEOUT",
		10*time.Second,
		"Connect timeout for passthrough and dynamic-forward-proxy gateway clusters.",
	).Get()
	GatewayRootCAPath = env.Register(
		"AGENTIO_GATEWAY_ROOT_CA_PATH",
		"",
		"Legacy gateway-local CA bundle path. Unused by Agentiod, which distributes its public CA trust package through xDS.",
	).Get()
	EnableSNITrafficPolicy = env.Register(
		"AGENTIO_ENABLE_SNI_TRAFFIC_POLICY",
		false,
		"If enabled, enforce SNI traffic policies in egress gateways, using HBONE TLS action headers when present.",
	).Get()
	MeshInternalTrafficPolicy = meshInternalTrafficPolicyFromString(env.Register(
		"AGENTIO_MESH_INTERNAL_TRAFFIC_POLICY",
		"PEER_AWARE",
		"Controls how mesh-internal (east-west) traffic is handled for sandbox tunnel proxies. "+
			"Allowed values are PEER_AWARE and PASSTHROUGH.",
	).Get())
)

// ResolveGatewayRootCAPath returns the gateway root CA bundle path used for
// TLS origination. An explicitly configured AGENTIO_GATEWAY_ROOT_CA_PATH wins;
// otherwise the first existing well-known OS CA bundle is detected, mirroring
// release-0.1 istio GetOSRootFilePath. Returns "" when nothing is found.
func ResolveGatewayRootCAPath() string {
	if path := strings.TrimSpace(GatewayRootCAPath); path != "" {
		return path
	}
	return getOSRootCAFilePath()
}

// getOSRootCAFilePath returns the first existing file among the well-known
// Linux/BSD CA certificate locations. Source of paths:
// https://golang.org/src/crypto/x509/root_linux.go
func getOSRootCAFilePath() string {
	certFiles := []string{
		"/etc/ssl/certs/ca-certificates.crt",                // Debian/Ubuntu/Gentoo etc.
		"/etc/pki/tls/certs/ca-bundle.crt",                  // Fedora/RHEL 6
		"/etc/ssl/ca-bundle.pem",                            // OpenSUSE
		"/etc/pki/tls/cacert.pem",                           // OpenELEC
		"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS/RHEL 7
		"/etc/ssl/cert.pem",                                 // Alpine Linux
		"/usr/local/etc/ssl/cert.pem",                       // FreeBSD
		"/etc/ssl/certs/ca-certificates",                    // Talos Linux
	}
	for _, cert := range certFiles {
		if _, err := os.Stat(cert); err == nil {
			return cert
		}
	}
	return ""
}

func validateNetworking() error {
	if GatewayConnectTimeout <= 0 {
		return fmt.Errorf("gateway connect timeout must be positive")
	}
	if strings.TrimSpace(ClientTrustPackagePath) == "" {
		return fmt.Errorf("public CA trust package path is required (AGENTIO_CLIENT_TRUST_PACKAGE_PATH)")
	}
	return nil
}

func meshInternalTrafficPolicyFromString(value string) extensionsv1.MeshInternalTrafficPolicy {
	if number, found := extensionsv1.MeshInternalTrafficPolicy_value["MESH_INTERNAL_"+value]; found {
		return extensionsv1.MeshInternalTrafficPolicy(number)
	}
	return extensionsv1.MeshInternalTrafficPolicy_MESH_INTERNAL_PEER_AWARE
}
