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

package gatewayagent

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	agentiolog "github.com/openkruise/agentio/pkg/log"
)

// Version is populated by image builds; local builds default to dev.
var Version = "dev"

// Revision is the source commit supplied by image builds.
var Revision string

// VersionInfo identifies the agent build independently of Envoy.
type VersionInfo struct {
	Version   string `json:"version"`
	Revision  string `json:"revision"`
	Modified  bool   `json:"modified"`
	GoVersion string `json:"goVersion"`
}

// BuildInfo returns the stamped version and Go VCS build information.
func BuildInfo() VersionInfo {
	v := VersionInfo{Version: Version, Revision: Revision, GoVersion: runtime.Version()}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" && v.Revision == "" {
				v.Revision = setting.Value
			}
			if setting.Key == "vcs.modified" {
				v.Modified = setting.Value == "true"
			}
		}
	}
	return v
}

// ConfigureLogging applies the agent log level and output format.
func ConfigureLogging(c Config, output io.Writer) error {
	var level slog.Level
	if err := level.UnmarshalText([]byte(c.AgentLogLevel)); err != nil {
		return fmt.Errorf("invalid agent log level: %w", err)
	}
	// Package log also filters by scope, so configure both layers.
	agentiolog.ConfigureOutputLevel(level)
	options := &slog.HandlerOptions{Level: level}
	var handler slog.Handler = slog.NewTextHandler(output, options)
	if c.LogAsJSON {
		handler = slog.NewJSONHandler(output, options)
	}
	slog.SetDefault(slog.New(handler))
	return nil
}

// Command executes diagnostic subcommands without requiring workload credentials.
func Command(ctx context.Context, args []string, output, errors io.Writer) error {
	if len(args) > 0 {
		switch args[0] {
		case "version":
			if len(args) != 1 {
				return fmt.Errorf("usage: gateway-agent version")
			}
			return writeJSON(output, BuildInfo())
		case "request":
			return adminRequest(ctx, args[1:], output, errors)
		case "wait":
			return waitReady(ctx, args[1:], errors)
		case "print-config":
			c, err := LoadConfig(args[1:], errors)
			if err != nil {
				return err
			}
			return writeJSON(output, effectiveConfig(c))
		}
	}
	c, err := LoadConfig(args, errors)
	if err != nil {
		return err
	}
	if err := ConfigureLogging(c, errors); err != nil {
		return err
	}
	slog.Info("starting gateway agent", "version", BuildInfo(), "config", effectiveConfig(c))
	return Run(ctx, c)
}

func writeJSON(w io.Writer, value any) error {
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(value)
}

func effectiveConfig(c Config) map[string]any {
	// Custom metadata may carry credentials; never include its values in diagnostics.
	metadata := maps.Clone(c.Metadata)
	for k := range metadata {
		metadata[k] = "<redacted>"
	}
	advanced := c.AdvancedOptions
	for target, source := range map[*map[string]string]map[string]string{&advanced.XDSHeaders: c.XDSHeaders, &advanced.CAHeaders: c.CAHeaders} {
		values := map[string]string{}
		for key := range source {
			values[key] = "<redacted>"
		}
		*target = values
	}
	// Native telemetry configuration may contain credentials or header values.
	advanced.TelemetryClusters = nil
	advanced.Tracing = nil
	advanced.StatsSinks = nil
	advanced.LoadStatsConfig = nil
	workers := int(c.Proxy.Concurrency)
	return map[string]any{
		"version":    BuildInfo(),
		"nodeID":     c.nodeID(),
		"legacy":     c.Legacy,
		"xdsAddress": c.Proxy.DiscoveryAddress,
		"caAddress":  c.CAAddress,
		"runtime": RuntimeOptions{
			AdvancedOptions:             advanced,
			Concurrency:                 &workers,
			DrainDuration:               c.Proxy.DrainDuration.String(),
			TerminationDrainDuration:    c.Proxy.TerminationDrainDuration.String(),
			MinimumDrainDuration:        c.MinimumDrainDuration.String(),
			ExitOnZeroActiveConnections: c.ExitOnZeroActiveConnections,
			StatsFlushInterval:          c.StatsFlushInterval.String(),
			SecretTTL:                   c.SecretTTL.String(),
			KeepaliveInterval:           c.KeepaliveInterval.String(),
			KeepaliveTimeout:            c.KeepaliveTimeout.String(),
			AgentLogLevel:               c.AgentLogLevel,
			EnvoyLogLevel:               c.LogLevel,
			EnvoyComponentLogLevel:      c.ComponentLogLevel,
			LogAsJSON:                   c.LogAsJSON,
			Metadata:                    metadata,
		},
	}
}

func adminRequest(ctx context.Context, args []string, output, errors io.Writer) error {
	flags := flag.NewFlagSet("request", flag.ContinueOnError)
	flags.SetOutput(errors)
	port := flags.Int("port", 15000, "Local Admin/status port")
	timeout := flags.Duration("timeout", 5*time.Second, "Request timeout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 2 || *port < 1 || *port > 65535 || *timeout <= 0 {
		return fmt.Errorf("usage: gateway-agent request [--port 15000] [--timeout 5s] METHOD /path")
	}
	path, err := url.ParseRequestURI(flags.Arg(1))
	if err != nil || path.IsAbs() || path.Host != "" || !strings.HasPrefix(path.Path, "/") {
		return fmt.Errorf("request requires a local absolute path")
	}
	localhost, _ := localAddresses(os.Getenv("INSTANCE_IP"))
	path.Scheme, path.Host = "http", net.JoinHostPort(localhost, strconv.Itoa(*port))
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, flags.Arg(0), path.String(), nil)
	if err != nil {
		return err
	}
	// Disable proxies and redirects: this command operates only on local endpoints.
	client := &http.Client{
		Transport:     &http.Transport{},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer client.CloseIdleConnections()
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer closeResource(response.Body)
	if _, err := io.Copy(output, response.Body); err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("local endpoint returned %s", response.Status)
	}
	return nil
}

func waitReady(ctx context.Context, args []string, errors io.Writer) error {
	flags := flag.NewFlagSet("wait", flag.ContinueOnError)
	flags.SetOutput(errors)
	timeout := flags.Duration("timeout", 60*time.Second, "Readiness deadline")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *timeout <= 0 {
		return fmt.Errorf("usage: gateway-agent wait [--timeout 60s]")
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	var last error
	for {
		last = adminRequest(
			ctx,
			[]string{"--port", "15020", "--timeout", "1s", "GET", "/healthz/ready"},
			io.Discard,
			errors,
		)
		if last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for gateway readiness: %w (last request: %w)", ctx.Err(), last)
		case <-ticker.C:
		}
	}
}
