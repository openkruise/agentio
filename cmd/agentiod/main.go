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

package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/openkruise/agentio/pkg/envdoc"
	agentiolog "github.com/openkruise/agentio/pkg/log"
	"github.com/openkruise/agentio/pkg/server"
)

func main() {
	// Report flag and export errors on stderr before runtime logging is configured.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:]); err != nil {
		slog.Error("agentiod failed", "error", err)
		os.Exit(1)
	}
}

// Flags cover process wiring only; behavioural options are environment variables (see -print-env).
func run(ctx context.Context, args []string) error {
	options, printEnv, err := parseFlags(args)
	if err != nil {
		return err
	}
	if printEnv.Enabled {
		return printEnv.Write(os.Stdout, envdoc.Options{
			Prefixes: []string{"AGENTIO_"},
			DefaultValues: map[string]string{
				"AGENTIO_PUSH_CONCURRENCY": "automatic (see description)",
			},
		})
	}
	logger, err := agentiolog.NewLogger(os.Stderr, logLevel, logFormat)
	if err != nil {
		return err
	}
	installLogger(logger)
	return server.Run(ctx, options)
}

// parseFlags parses the wiring flags and -print-env.
func parseFlags(args []string) (server.Options, envdoc.Flags, error) {
	options := server.DefaultOptions()
	printEnv := envdoc.Flags{}

	flags := flag.NewFlagSet("agentiod", flag.ContinueOnError)
	flags.StringVar(&options.DiscoveryAddress, "discovery-address", options.DiscoveryAddress,
		"TLS xDS listen address")
	flags.StringVar(&options.MonitoringAddress, "monitoring-address", options.MonitoringAddress,
		"health and metrics listen address")
	flags.StringVar(&options.ClusterID, "cluster-id", options.ClusterID,
		"cluster identifier reported in workload metadata")
	flags.StringVar(&options.RootNamespace, "namespace", options.RootNamespace,
		"namespace the control plane runs in, and where its CA and configuration live")
	flags.StringVar(&options.ClusterDomain, "domain", options.ClusterDomain,
		"DNS suffix used to build service hostnames")
	flags.StringVar(&options.TrustDomain, "trust-domain", options.TrustDomain,
		"SPIFFE trust domain")
	flags.StringVar(&options.Kubeconfig, "kubeconfig", os.Getenv("KUBECONFIG"),
		"out-of-cluster kubeconfig; in-cluster configuration is used when empty")
	printEnv.Bind(flags)
	if err := flags.Parse(args); err != nil {
		return server.Options{}, envdoc.Flags{}, err
	}
	if err := printEnv.Validate(); err != nil {
		return server.Options{}, envdoc.Flags{}, err
	}
	return options, printEnv, nil
}
