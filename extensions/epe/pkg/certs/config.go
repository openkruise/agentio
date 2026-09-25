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
package certs

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
)

// options collects the knobs accepted by ServerTLSConfig and ClientTLSConfig.
// InsecureSkipVerify is intentionally NOT an option: verification is always
// performed by the pipeline and can never be disabled by callers.
type options struct {
	serverName    string
	serverNameSet bool
	clientAuth    tls.ClientAuthType
	peerVerifier  func(chains [][]*x509.Certificate) error
}

// Option customizes a TLS configuration built from a Provider.
type Option func(*options)

// WithServerName sets the expected server name. On clients it drives both SNI
// and hostname verification. Mutually exclusive with WithPeerVerifier.
func WithServerName(name string) Option {
	return func(o *options) {
		o.serverName = name
		o.serverNameSet = true
	}
}

// WithClientAuth sets the server-side client certificate policy. For
// tls.VerifyClientCertIfGiven and stricter policies, client CAs are rebuilt
// from the Provider on every handshake.
func WithClientAuth(t tls.ClientAuthType) Option {
	return func(o *options) {
		o.clientAuth = t
	}
}

// WithPeerVerifier installs a custom identity verifier that runs INSTEAD of
// hostname verification. Chain-of-trust verification against the Provider's
// trust anchors always happens first; the verifier only adds identity
// assertions on the verified chains (e.g. SPIFFE URI SANs). Mutually
// exclusive with WithServerName. On servers it additionally requires
// WithClientAuth(tls.VerifyClientCertIfGiven) or stronger, otherwise
// ServerTLSConfig returns an error (crypto/tls verifies client chains only
// under those policies).
func WithPeerVerifier(fn func(chains [][]*x509.Certificate) error) Option {
	return func(o *options) {
		o.peerVerifier = fn
	}
}

// buildOptions applies opts and validates option combinations.
func buildOptions(opts []Option) (*options, error) {
	o := &options{}
	for _, apply := range opts {
		apply(o)
	}
	if o.serverNameSet && o.peerVerifier != nil {
		return nil, errors.New("certs: WithServerName and WithPeerVerifier are mutually exclusive")
	}
	return o, nil
}

// ServerTLSConfig builds a server *tls.Config from the Provider. With zero
// options it serves the Provider's certificate exactly like a plain
// tls.Config{Certificates: ...}. When client authentication requires
// verification, the client CA pool is rebuilt from the Provider on every
// handshake so CA rotation takes effect without a restart (fail-closed on
// Provider errors or missing anchors).
func ServerTLSConfig(p Provider, opts ...Option) (*tls.Config, error) {
	o, err := buildOptions(opts)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: p.GetCertificate,
		ClientAuth:     o.clientAuth,
		// Every new connection must verify the current trust anchors.
		SessionTicketsDisabled: o.clientAuth >= tls.VerifyClientCertIfGiven,
	}
	if o.peerVerifier != nil {
		// crypto/tls populates the verified chains passed to
		// VerifyPeerCertificate only when it performs CA verification, i.e.
		// ClientAuth >= tls.VerifyClientCertIfGiven. With a weaker policy the
		// verifier would run on nil/unverified chains and a lenient verifier
		// could accept arbitrary client certificates, so reject that
		// combination at construction time.
		if o.clientAuth < tls.VerifyClientCertIfGiven {
			return nil, errors.New("certs: WithPeerVerifier on a server requires WithClientAuth(tls.VerifyClientCertIfGiven) or stronger")
		}
		verifier := o.peerVerifier
		// Chain-of-trust against ClientCAs is performed by crypto/tls before
		// this callback runs (guaranteed by the ClientAuth check above); the
		// verifier only adds identity assertions on the verified chains.
		cfg.VerifyPeerCertificate = func(_ [][]byte, chains [][]*x509.Certificate) error {
			return verifier(chains)
		}
	}
	if o.clientAuth >= tls.VerifyClientCertIfGiven {
		base := cfg.Clone()
		cfg.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
			pool, err := p.RootCAs()
			if err != nil {
				return nil, fmt.Errorf("certs: resolving trust anchors for client certificate verification: %w", err)
			}
			if pool == nil {
				return nil, errors.New("certs: provider returned no trust anchors for client certificate verification")
			}
			perConn := base.Clone()
			perConn.ClientCAs = pool
			return perConn, nil
		}
	}
	return cfg, nil
}

// ClientTLSConfig builds a client *tls.Config from the Provider.
//
// Identity verification is mandatory: exactly one of WithServerName or
// WithPeerVerifier must be provided, otherwise a construction error is
// returned. Chain-only verification (trust anchors without an identity
// assertion) is intentionally not offered.
//
// The construction-time option governs identity verification for the whole
// lifetime of the config: a tls.Config.ServerName assigned at runtime (e.g.
// by net/http.Transport cloning the config per host) is NOT consulted by the
// verification pipeline and only affects SNI.
//
// The returned config sets InsecureSkipVerify internally ONLY to disable the
// stdlib's static-pool verification; an unconditional VerifyPeerCertificate
// re-implements it with trust anchors resolved from the Provider on every
// handshake (fail-closed), followed by hostname verification against the
// configured server name, or the custom peer verifier if one was set.
func ClientTLSConfig(p Provider, opts ...Option) (*tls.Config, error) {
	o, err := buildOptions(opts)
	if err != nil {
		return nil, err
	}
	if !o.serverNameSet && o.peerVerifier == nil {
		return nil, errors.New("certs: ClientTLSConfig requires exactly one of WithServerName or WithPeerVerifier")
	}
	return &tls.Config{
		MinVersion:           tls.VersionTLS12,
		GetClientCertificate: p.GetClientCertificate,
		ServerName:           o.serverName,
		// Verification is NOT skipped: it is performed by the unconditional
		// VerifyPeerCertificate below with per-handshake trust anchors.
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: clientPeerVerifier(p, o.serverName, o.peerVerifier),
	}, nil
}

// clientPeerVerifier returns the client-side verification pipeline:
//  1. Parse the peer chain and verify it against fresh Provider trust anchors
//     (system pool fallback when the Provider has no custom CA). Any Provider
//     error fails the handshake.
//  2. Run the custom peer verifier on the verified chains if set, otherwise
//     perform hostname verification against serverName. ClientTLSConfig
//     guarantees exactly one of the two is configured, so the pipeline never
//     stops at chain-only verification.
func clientPeerVerifier(p Provider, serverName string, custom func(chains [][]*x509.Certificate) error) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("certs: peer did not present any certificate")
		}
		peerCerts := make([]*x509.Certificate, 0, len(rawCerts))
		for _, raw := range rawCerts {
			cert, err := x509.ParseCertificate(raw)
			if err != nil {
				return fmt.Errorf("certs: parsing peer certificate: %w", err)
			}
			peerCerts = append(peerCerts, cert)
		}

		roots, err := clientTrustAnchors(p)
		if err != nil {
			return err
		}
		verifyOpts := x509.VerifyOptions{
			Roots:         roots,
			Intermediates: x509.NewCertPool(),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		for _, cert := range peerCerts[1:] {
			verifyOpts.Intermediates.AddCert(cert)
		}
		chains, err := peerCerts[0].Verify(verifyOpts)
		if err != nil {
			return fmt.Errorf("certs: verifying peer certificate: %w", err)
		}

		if custom != nil {
			return custom(chains)
		}
		if serverName != "" {
			return peerCerts[0].VerifyHostname(serverName)
		}
		// Unreachable when built through ClientTLSConfig, which enforces
		// exactly one identity option; fail closed instead of silently
		// accepting chain-only verification.
		return errors.New("certs: no identity verification configured")
	}
}

// systemCertPool memoizes the process-wide system trust anchors:
// x509.SystemCertPool deep-copies the entire root pool per call, and
// clientTrustAnchors runs on every handshake without a custom CA.
var systemCertPool = sync.OnceValues(x509.SystemCertPool)

// clientTrustAnchors resolves per-handshake trust anchors. Provider errors
// fail closed; a nil pool means the Provider has no custom CA, so the system
// certificate pool is used instead.
func clientTrustAnchors(p Provider) (*x509.CertPool, error) {
	pool, err := p.RootCAs()
	if err != nil {
		return nil, fmt.Errorf("certs: resolving trust anchors: %w", err)
	}
	if pool != nil {
		return pool, nil
	}
	sysPool, err := systemCertPool()
	if err != nil {
		return nil, fmt.Errorf("certs: loading system certificate pool: %w", err)
	}
	return sysPool, nil
}
