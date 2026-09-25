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
package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/go-logr/logr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/openkruise/agentio/extensions/epe/pkg/audit/accesslog"
	"github.com/openkruise/agentio/extensions/epe/pkg/certs"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/extproc"
	"github.com/openkruise/agentio/extensions/epe/pkg/runnable"
)

// Config carries everything the ext-proc gRPC server needs. It is consumed
// once by New; a zero-value Config serves plaintext. Resolve and GrpcPort
// must at least be set.
type Config struct {
	GrpcPort int
	// Listener serves an already-bound socket and makes GrpcPort unused. It
	// lets a caller that needs to know the address up front bind it first
	// rather than reserving a port by binding and closing one, which leaves the
	// port unowned until this server binds. See runnable.WithListener.
	Listener net.Listener
	// PluginBudget bounds each evaluation phase (one ext_proc message); 0 disables.
	PluginBudget time.Duration
	// FailClosedOnMissingIdentity denies requests when the source pod
	// identity never reached the filter (e.g. a misconfigured metadata
	// exchange). The default (false) passes them through.
	FailClosedOnMissingIdentity bool

	// SecureServing enables TLS. When true, CertProvider supplies the
	// serving certificate (and the client CA pool for mTLS); nil falls back
	// to a self-signed certificate via certs.SelfSigned. TLSOptions is
	// passed to certs.ServerTLSConfig (e.g. certs.WithClientAuth,
	// certs.WithPeerVerifier).
	SecureServing bool
	CertProvider  certs.Provider
	TLSOptions    []certs.Option
	// RequireClientCert requires TLS and a client certificate verified against
	// CertProvider's trust bundle. All verified clients are accepted; this does
	// not distinguish gateways from other workloads issued by the same CA.
	RequireClientCert bool

	// Resolve maps request identity to the policy units the engine evaluates.
	// Required. Policy-specific stores and binders are assembled by the caller.
	Resolve engine.Resolver
	// Registrations is the action order applied inside every rule.
	Registrations []filter.Registration
	// StreamLoggers are invoked once per stream at stream end (audit).
	StreamLoggers []filter.StreamLogger
	// AuditLogger is the per-request audit sink. nil is replaced with a
	// no-op logger inside extproc.NewServer.
	AuditLogger accesslog.Logger
}

// New assembles the ext-proc gRPC server as a runnable: TLS setup (when
// enabled), handler construction, and listener lifecycle. Configuration
// errors surface when the runnable starts.
func New(cfg Config, logger logr.Logger) runnable.Runnable {
	return runnable.Func(func(ctx context.Context) error {
		if cfg.Resolve == nil {
			return fmt.Errorf("ext-proc server config: Resolve is required")
		}

		if cfg.RequireClientCert && !cfg.SecureServing {
			return fmt.Errorf("client certificate verification requires TLS")
		}
		interceptors := []grpc.StreamServerInterceptor{recoverStreamPanic}
		var srv *grpc.Server
		if cfg.SecureServing {
			provider := cfg.CertProvider
			if provider == nil {
				selfSigned, err := certs.SelfSigned()
				if err != nil {
					logger.Error(err, "failed to create self signed certificate")
					return err
				}
				provider = selfSigned
			}
			if cfg.RequireClientCert {
				interceptors = append(interceptors, checkServing(provider))
			}
			options := append([]certs.Option(nil), cfg.TLSOptions...)
			if cfg.RequireClientCert {
				options = append(options, certs.WithClientAuth(tls.RequireAndVerifyClientCert))
			}
			tlsConfig, err := certs.ServerTLSConfig(provider, options...)
			if err != nil {
				logger.Error(err, "failed to build server TLS config")
				return err
			}
			srv = grpc.NewServer(
				grpc.Creds(credentials.NewTLS(tlsConfig)),
				grpc.ChainStreamInterceptor(interceptors...),
			)
		} else {
			srv = grpc.NewServer(grpc.ChainStreamInterceptor(interceptors...))
		}

		extProcPb.RegisterExternalProcessorServer(
			srv,
			extproc.NewServer(extproc.ServerDeps{
				Resolve:                     cfg.Resolve,
				Registrations:               cfg.Registrations,
				StreamLoggers:               cfg.StreamLoggers,
				AuditLogger:                 cfg.AuditLogger,
				PluginBudget:                cfg.PluginBudget,
				FailClosedOnMissingIdentity: cfg.FailClosedOnMissingIdentity,
			}),
		)

		return runnable.GRPCServer("ext-proc", srv, cfg.GrpcPort,
			runnable.WithListener(cfg.Listener)).Start(ctx)
	})
}

// checkServing rejects new streams on existing mTLS connections while serving
// material is unavailable. Client certificates are verified at the TLS handshake.
func checkServing(provider certs.Provider) grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := certs.CheckServing(provider, true); err != nil {
			return status.Error(codes.Unavailable, "EPE serving certificate or trust bundle is unavailable")
		}
		return handler(srv, stream)
	}
}
