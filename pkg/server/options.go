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
	"fmt"
	"net"
	"strings"
	"time"
)

// Options contains the process wiring exposed as command-line flags.
// Restart-only behavior configured by environment variables lives in
// pkg/features and is read directly by its consumers.
type Options struct {
	SandboxQueryTTL   time.Duration
	DiscoveryAddress  string
	MonitoringAddress string
	ClusterID         string
	RootNamespace     string
	// ClusterDomain is the DNS suffix used to build service hostnames.
	ClusterDomain string
	Kubeconfig    string
	TrustDomain   string
}

// DefaultOptions returns the process-wiring defaults exposed by cmd/agentiod.
func DefaultOptions() Options {
	return Options{
		SandboxQueryTTL:   10 * time.Second,
		DiscoveryAddress:  ":15012",
		MonitoringAddress: ":15014",
		ClusterID:         "Kubernetes",
		RootNamespace:     "agentio-system",
		ClusterDomain:     "cluster.local",
		TrustDomain:       "cluster.local",
	}
}

func (o Options) Validate() error {
	if o.SandboxQueryTTL < 0 {
		return fmt.Errorf("sandbox query TTL must not be negative")
	}
	_, port, err := net.SplitHostPort(o.DiscoveryAddress)
	if err != nil {
		return fmt.Errorf("parse discovery address: %w", err)
	}
	if port == "15010" {
		return fmt.Errorf("plaintext discovery port 15010 is not supported")
	}
	if strings.TrimSpace(o.MonitoringAddress) == "" {
		return fmt.Errorf("monitoring address is required")
	}
	if strings.TrimSpace(o.ClusterID) == "" {
		return fmt.Errorf("cluster ID is required")
	}
	if strings.TrimSpace(o.RootNamespace) == "" {
		return fmt.Errorf("root namespace is required")
	}
	if strings.TrimSpace(o.ClusterDomain) == "" {
		return fmt.Errorf("cluster domain is required")
	}
	if strings.TrimSpace(o.TrustDomain) == "" {
		return fmt.Errorf("trust domain is required")
	}
	return nil
}

// trustedNodeServiceAccount resolves one service account in the root namespace from a bare name or namespace/name list.
func trustedNodeServiceAccount(rootNamespace, configured string) (string, error) {
	configured = strings.TrimSpace(configured)
	if configured == "" {
		return "ztunnel", nil
	}
	if !strings.Contains(configured, "/") && !strings.Contains(configured, ",") {
		return configured, nil
	}

	var matched string
	for account := range strings.SplitSeq(configured, ",") {
		namespace, serviceAccount, found := strings.Cut(strings.TrimSpace(account), "/")
		if !found || namespace == "" || serviceAccount == "" {
			return "", fmt.Errorf("trusted node account %q must be service-account or namespace/service-account", account)
		}
		if namespace != rootNamespace {
			continue
		}
		if matched != "" {
			return "", fmt.Errorf("multiple trusted node accounts are configured in root namespace %q", rootNamespace)
		}
		matched = serviceAccount
	}
	if matched == "" {
		return "", fmt.Errorf("no trusted node account is configured in root namespace %q", rootNamespace)
	}
	return matched, nil
}
