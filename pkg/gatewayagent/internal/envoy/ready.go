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

// Adapted from release-0.1 at 169bad3c36783711989757cd907465b8fe9cfc3a.
// Agentio maintains this copy; see ../UPSTREAM.md.
package envoy

import (
	"context"
	"fmt"
)

// Probe for readiness.
type Probe struct {
	LocalHostAddr       string
	AdminPort           uint16
	receivedFirstUpdate bool
	// Indicates that Envoy is ready at least once so that we can cache and reuse that probe.
	atleastOnceReady bool
	Context          context.Context
	// NoEnvoy so we only check config status
	NoEnvoy bool
}

// Prober checks whether Envoy can serve traffic.
type Prober interface {
	// Check executes the probe and returns an error if the probe fails.
	Check() error
}

var _ Prober = &Probe{}

// Check executes the probe and returns an error if the probe fails.
func (p *Probe) Check() error {
	// First, check that Envoy has received a configuration update from Pilot.
	if err := p.checkConfigStatus(); err != nil {
		return err
	}
	return p.isEnvoyReady()
}

// checkConfigStatus checks to make sure initial configs have been received from Pilot.
func (p *Probe) checkConfigStatus() error {
	if p.NoEnvoy {
		// TODO some way to verify XDS proxy -> control plane works
		return nil
	}
	if p.receivedFirstUpdate {
		return nil
	}

	s, err := GetUpdateStatusStats(p.LocalHostAddr, p.AdminPort)
	if err != nil {
		return err
	}

	CDSUpdated := s.CDSUpdatesSuccess > 0
	LDSUpdated := s.LDSUpdatesSuccess > 0
	if CDSUpdated && LDSUpdated {
		p.receivedFirstUpdate = true
		return nil
	}

	if !CDSUpdated && !LDSUpdated {
		return fmt.Errorf("config not received from XDS server (is agentiod running?): %s", s.String())
	} else if s.LDSUpdatesRejection > 0 || s.CDSUpdatesRejection > 0 {
		return fmt.Errorf("config received from XDS server, but was rejected: %s", s.String())
	}
	return fmt.Errorf("config not fully received from XDS server: %s", s.String())
}

// isEnvoyReady checks to ensure that Envoy is in the LIVE state and workers have started.
func (p *Probe) isEnvoyReady() error {
	if p.NoEnvoy {
		return nil
	}
	if p.Context == nil {
		return p.checkEnvoyReadiness()
	}
	select {
	case <-p.Context.Done():
		return fmt.Errorf("server is terminated: %w", context.Cause(p.Context))
	default:
		return p.checkEnvoyReadiness()
	}
}

func (p *Probe) checkEnvoyReadiness() error {
	// If Envoy is ready at least once i.e. server state is LIVE and workers
	// have started, they will not go back in the life time of Envoy process.
	// They will only change at hot restart or health check fails. Since the gateway
	// does not use both of them, it is safe to cache this value. Since the
	// actual readiness probe goes via Envoy, it ensures that Envoy is actively
	// serving traffic and we can rely on that.
	if p.atleastOnceReady {
		return nil
	}

	err := checkEnvoyStats(p.LocalHostAddr, p.AdminPort)
	if err == nil {
		// Startup is measured by the Pod startup probe.
		p.atleastOnceReady = true
	}
	return err
}

// ServerInfoState identifies an Envoy lifecycle state from Admin statistics.
type ServerInfoState int32

const (
	// Live indicates the server is live and serving traffic.
	Live ServerInfoState = 0
	// Draining indicates the server is draining listeners in response to external health checks failing.
	Draining ServerInfoState = 1
	// PreInitializing indicates the server has not yet completed cluster manager initialization.
	PreInitializing ServerInfoState = 2
	// Initializing indicates the server is running the cluster manager initialization callbacks (e.g., RDS).
	Initializing ServerInfoState = 3
)

// StateString returns the Envoy lifecycle state name.
func StateString(state ServerInfoState) string {
	switch state {
	case Live:
		return "LIVE"
	case Draining:
		return "DRAINING"
	case PreInitializing:
		return "PRE_INITIALIZING"
	case Initializing:
		return "INITIALIZING"
	}
	return "UNKNOWN"
}

// checkEnvoyStats actually executes the Stats Query on Envoy admin endpoint.
func checkEnvoyStats(host string, port uint16) error {
	state, ws, err := GetReadinessStats(host, port)
	if err != nil {
		return fmt.Errorf("failed to get readiness stats: %w", err)
	}

	if state != nil && ServerInfoState(*state) != Live {
		return fmt.Errorf("server is not live, current state is: %v", StateString(ServerInfoState(*state)))
	}

	if !ws {
		return fmt.Errorf("workers have not yet started")
	}

	return nil
}
