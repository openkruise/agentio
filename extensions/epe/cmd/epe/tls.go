// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package main

import (
	"errors"
	"fmt"

	"github.com/openkruise/agentio/extensions/epe/pkg/certs"
	"github.com/openkruise/agentio/extensions/epe/pkg/certs/certsource"
)

// extProcTLS is the serving material built from the --tls-* flags for the
// ext-proc listener.
type extProcTLS struct {
	// Secure reports whether the listener serves TLS at all; false means
	// plaintext (the default when no flags are set).
	Secure bool
	// Provider supplies the hot-rotating certificate material.
	Provider certs.Provider
	Workload *certsource.Workload
	// RequireClientCert accepts any client certificate verified by Provider's
	// trust bundle. Gateway-specific identity authorization is not implemented.
	RequireClientCert bool
}

type extProcTLSOptions struct {
	Source   string
	CertPath string
	KeyPath  string
	CAPath   string
	Workload certsource.WorkloadOptions
}

// buildExtProcTLS selects one explicit certificate source. CA mode starts
// without a certificate; its runnable retries until the CA becomes available.
func buildExtProcTLS(options extProcTLSOptions, stop <-chan struct{}) (*extProcTLS, error) {
	result := &extProcTLS{}
	switch options.Source {
	case "none":
		if options.CertPath != "" || options.KeyPath != "" || options.CAPath != "" {
			return nil, errors.New("TLS material requires --tls-source=file or ca")
		}
		return result, nil
	case "ca":
		if options.CertPath != "" || options.KeyPath != "" || options.CAPath != "" {
			return nil, errors.New("--tls-source=ca cannot use --tls-cert-path, --tls-key-path or --tls-ca-path")
		}
		provider, err := certsource.NewWorkload(options.Workload)
		if err != nil {
			return nil, err
		}
		result.Provider, result.Workload = provider, provider
	case "file":
		provider, err := options.fileProvider(stop)
		if err != nil {
			return nil, err
		}
		result.Provider = provider
	default:
		return nil, fmt.Errorf("--tls-source must be none, ca or file")
	}
	result.Secure = true
	result.RequireClientCert = options.Source == "ca" || options.CAPath != ""
	return result, nil
}

func (options extProcTLSOptions) fileProvider(stop <-chan struct{}) (certs.Provider, error) {
	if options.CertPath == "" || options.KeyPath == "" {
		return nil, errors.New("--tls-cert-path and --tls-key-path must be set together")
	}
	provider, err := certsource.FromFiles(options.CertPath, options.KeyPath, options.CAPath, stop)
	if err != nil {
		return nil, err
	}
	if options.CAPath != "" {
		pool, err := provider.RootCAs()
		if err != nil {
			return nil, err
		}
		if pool == nil {
			return nil, fmt.Errorf("no usable CA certificates in %s", options.CAPath)
		}
	}
	return provider, nil
}

func (s *extProcTLS) Ready() error {
	if !s.Secure {
		return nil
	}
	return certs.CheckServing(s.Provider, s.RequireClientCert)
}
