// Copyright Istio Authors
// Modifications Copyright 2026 The Kruise Authors
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
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/openkruise/agentio/pkg/gatewayagent/internal/envoy"
)

// Run owns the gateway process and its local services. The lifecycle assembly is
// adapted from release-0.1 pilot-agent; process execution and drain are maintained
// locally in internal/envoy, without Istio Go dependencies.
func Run(ctx context.Context, c Config) error {
	if err := c.validate(); err != nil {
		return err
	}
	if c.metrics == nil {
		c.metrics = newAgentMetrics()
	}
	bootstrap, err := bootstrapConfig(c)
	if err != nil {
		return fmt.Errorf("generate gateway bootstrap: %w", err)
	}
	if err := bootstrap.ValidateAll(); err != nil {
		return fmt.Errorf("validate gateway bootstrap: %w", err)
	}
	content, err := protojson.MarshalOptions{Indent: "  "}.Marshal(bootstrap)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(c.Proxy.ConfigPath, 0o750); err != nil {
		return err
	}
	bootstrapPath := filepath.Join(c.Proxy.ConfigPath, "agentio-bootstrap.json")
	if err := os.WriteFile(bootstrapPath, content, 0o600); err != nil {
		return err
	}
	identity, err := startIdentity(c)
	if err != nil {
		return err
	}
	defer identity.Close()
	stopXDS, xdsDone, err := startXDS(c)
	if err != nil {
		return err
	}
	defer stopXDS()
	return runEnvoy(ctx, c, bootstrapPath, xdsDone, identity)
}

func runEnvoy(
	ctx context.Context,
	c Config,
	bootstrapPath string,
	xdsDone <-chan error,
	identity *identityManager,
) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	proxy := &observedProxy{
		Proxy: envoy.NewProxy(envoy.ProxyConfig{
			BinaryPath:         c.Proxy.BinaryPath,
			ConfigPath:         bootstrapPath,
			AdminPort:          c.Proxy.AdminPort,
			DrainDuration:      durationpb.New(c.Proxy.DrainDuration),
			Concurrency:        c.Proxy.Concurrency,
			LogLevel:           c.LogLevel,
			ComponentLogLevel:  c.ComponentLogLevel,
			LogAsJSON:          c.LogAsJSON,
			OutlierLogPath:     c.OutlierLogPath,
			NodeIPs:            c.nodeIPs(),
			SkipDeprecatedLogs: boolOption(c.SkipDeprecatedLogs, true),
			FileFlushInterval:  durationpb.New(c.Proxy.FileFlushInterval),
			FileFlushMinSizeKB: c.Proxy.FileFlushMinSizeKB,
		}),
	}
	localhost, _ := localAddresses(c.IP)
	agent := envoy.NewAgent(proxy, c.Proxy.TerminationDrainDuration,
		c.MinimumDrainDuration, localhost, int(c.Proxy.AdminPort),
		portOption(c.EnvoyStatusPort, 15021), portOption(c.PrometheusPort, 15090), c.ExitOnZeroActiveConnections)
	var draining atomic.Bool
	stopStatus, statusDone, err := startStatus(ctx, c, agent, cancel, &draining, identity.ready)
	if err != nil {
		return err
	}
	defer stopStatus()
	finished := make(chan struct{})
	go func() {
		agent.Run(ctx)
		close(finished)
	}()
	select {
	case <-finished:
		if ctx.Err() == nil {
			return errors.Join(errors.New("Envoy exited unexpectedly"), proxy.exitErr)
		}
		return nil
	case <-ctx.Done():
		draining.Store(true)
		c.metrics.draining.Set(1)
		c.metrics.ready.Set(0)
		<-finished
		return nil
	case err := <-xdsDone:
		draining.Store(true)
		c.metrics.draining.Set(1)
		c.metrics.ready.Set(0)
		cancel()
		<-finished
		return errors.Join(errors.New("ADS server stopped"), err)
	case err := <-identity.serverDone:
		draining.Store(true)
		c.metrics.draining.Set(1)
		c.metrics.ready.Set(0)
		cancel()
		<-finished
		return errors.Join(errors.New("SDS server stopped"), err)
	case err := <-statusDone:
		draining.Store(true)
		c.metrics.draining.Set(1)
		c.metrics.ready.Set(0)
		cancel()
		<-finished
		return errors.Join(errors.New("status server stopped"), err)
	}
}

// Upstream Agent.Run logs child errors rather than returning them. Capture the
// result so an unexpected Envoy exit also makes the container exit unsuccessfully.
type observedProxy struct {
	envoy.Proxy
	exitErr error
}

func (p *observedProxy) Run(abort <-chan error) error {
	p.exitErr = p.Proxy.Run(abort)
	return p.exitErr
}

func closeResource(resource io.Closer) {
	if err := resource.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		slog.Debug("resource cleanup failed", "error", err)
	}
}
