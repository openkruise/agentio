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
// Agentio maintains this copy.
package envoy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"istio.io/istio/pkg/util/sets"

	"sync/atomic"
)

var errAbort = errors.New("proxy aborted")

const errOutOfMemory = "signal: killed"

var activeConnectionCheckDelay = 1 * time.Second

// NewAgent creates a new proxy agent for the proxy start-up and clean-up functions.
func NewAgent(proxy Proxy, terminationDrainDuration, minDrainDuration time.Duration, localhost string,
	adminPort, statusPort, prometheusPort int, exitOnZeroActiveConnections bool,
) *Agent {
	internalListeners := sets.New(
		fmt.Sprintf("listener.0.0.0.0_%d.downstream_cx_active", statusPort),
		fmt.Sprintf("listener.0.0.0.0_%d.downstream_cx_active", prometheusPort),
		"listener.agentio_status.downstream_cx_active",
		"listener.agentio_metrics.downstream_cx_active",
		fmt.Sprintf("listener.[__]_%d.downstream_cx_active", statusPort),
		fmt.Sprintf("listener.[__]_%d.downstream_cx_active", prometheusPort),
		"listener.admin.downstream_cx_active",
		"listener.admin.main_thread.downstream_cx_active",
	)
	return &Agent{
		proxy:                       proxy,
		statusCh:                    make(chan exitStatus, 1), // context might stop drainage
		abortCh:                     make(chan error, 1),
		terminationDrainDuration:    terminationDrainDuration,
		minDrainDuration:            minDrainDuration,
		exitOnZeroActiveConnections: exitOnZeroActiveConnections,
		adminPort:                   adminPort,
		localhost:                   localhost,
		internalListeners:           internalListeners,
		skipDrain:                   &atomic.Bool{},
	}
}

// Proxy defines command interface for a proxy
type Proxy interface {
	// Run command with an abort channel
	Run(<-chan error) error

	// Drains the envoy process.
	Drain(skipExit bool) error

	// Cleanup command for cleans up the proxy.
	Cleanup()

	// UpdateConfig writes a new config file
	UpdateConfig(config []byte) error
}

// Agent owns an Envoy child process and coordinates its shutdown.
type Agent struct {
	// proxy commands
	proxy Proxy

	// channel for proxy exit notifications
	statusCh chan exitStatus

	abortCh chan error

	// time to allow for the proxy to drain before terminating all remaining proxy processes
	terminationDrainDuration time.Duration
	minDrainDuration         time.Duration

	adminPort int
	localhost string

	internalListeners sets.Set[string]

	exitOnZeroActiveConnections bool

	skipDrain *atomic.Bool
}

type exitStatus struct {
	err error
}

// Run starts the envoy and waits until it terminates.
// There are a few exit paths:
//  1. Envoy exits. In this case, we simply log and exit.
//  2. /quitquitquit (on agent, not Envoy) is called. We will set skipDrain and cancel the context, which triggers us to exit immediately.
//  3. SIGTERM. We will drain, wait termination drain duration, then exit. This is the standard pod shutdown; SIGTERM arrives when pod shutdown starts.
//     If the pod's terminationGracePeriod is shorter than our drain duration (rare), we may be a SIGKILL.
//  4. /drain + SIGTERM. This is the shutdown when using Kubernetes native sidecars.
//     /drain is called when the pod shutdown starts. We start draining, forever.
//     Once the app containers shutdown, we get a SIGTERM. We have no use to run anymore, so shutdown immediately.
//     If somehow we do not shutdown from the SIGTERM fast enough, we may get a SIGKILL later.
func (a *Agent) Run(ctx context.Context) {
	processLog.Info("Starting proxy agent")
	go a.runWait(a.abortCh)

	select {
	case status := <-a.statusCh:
		if status.err != nil {
			if status.err.Error() == errOutOfMemory {
				warnf("Envoy may have been out of memory killed. Check memory usage and limits.")
			}
			errorf("Envoy exited with error: %v", status.err)
		} else {
			infof("Envoy exited normally")
		}

	case <-ctx.Done():
		a.terminate()
		processLog.Info("Agent has successfully terminated")
	}
}

// DisableDraining skips graceful draining when the agent is stopped.
func (a *Agent) DisableDraining() {
	a.skipDrain.Store(true)
}

// DrainNow starts draining listeners without stopping the agent.
func (a *Agent) DrainNow() {
	infof("Agent draining proxy")
	err := a.proxy.Drain(true)
	if err != nil {
		warnf("Error in invoking drain listeners endpoint: %v", err)
	}
	// If we drained now, skip draining + waiting later
	// When we terminate, we will instead exit immediately
	a.DisableDraining()
}

// terminate starts exiting the process.
func (a *Agent) terminate() {
	started := time.Now()
	reason := "process_exited"
	lastActive := -1 // No connection count has been observed yet.
	defer func() {
		fields := []any{"reason", reason, "duration", time.Since(started)}
		if lastActive >= 0 {
			fields = append(fields, "last_active_connections", lastActive)
		}
		if reason == "deadline" || reason == "stats_error" {
			processLog.Warn("gateway Envoy drain ended", fields...)
		} else {
			processLog.Info("gateway Envoy drain ended", fields...)
		}
	}()
	processLog.Info("gateway Envoy drain started", "timeout", a.terminationDrainDuration,
		"minimum_duration", a.minDrainDuration, "wait_for_connections", a.exitOnZeroActiveConnections)
	if a.skipDrain.Load() {
		reason = "drain_disabled"
		a.abortCh <- errAbort
		<-a.statusCh
		return
	}
	e := a.proxy.Drain(false)
	if e != nil {
		warnf("Error in invoking drain listeners endpoint: %v", e)
	}
	// If exitOnZeroActiveConnections is enabled, always sleep minimumDrainDuration then exit
	// after min(all connections close, terminationGracePeriodSeconds-minimumDrainDuration).
	// exitOnZeroActiveConnections is disabled (default), retain the existing behavior.
	if a.exitOnZeroActiveConnections {
		expires := time.Now().Add(a.terminationDrainDuration)
		deadline := time.NewTimer(a.terminationDrainDuration)
		defer deadline.Stop()
		select {
		case <-time.After(a.minDrainDuration):
		case <-deadline.C:
			reason = "deadline"
			a.abortCh <- errAbort
			<-a.statusCh
			return
		case <-a.statusCh:
			return
		}
		ticker := time.NewTicker(activeConnectionCheckDelay)
		defer ticker.Stop()

		retryCount := 0
	graceful_loop:
		for {
			select {
			case <-ticker.C:
			case <-deadline.C:
				reason = "deadline"
				a.abortCh <- errAbort
				break graceful_loop
			case <-a.statusCh:
				return
			}
			ac, err := a.activeProxyConnectionsWithTimeout(max(time.Millisecond, min(2*time.Second, time.Until(expires))))
			select {
			case status := <-a.statusCh:
				infof("Envoy exited with status %v", status.err)
				infof("Graceful termination logic ended prematurely, envoy process terminated early")
				return
			default:
				if err != nil {
					retryCount++
					processLog.Warn("gateway Envoy connection count failed", "error", err, "attempt", retryCount)
					// Max retry 5 times
					if retryCount > 4 {
						reason = "stats_error"
						a.abortCh <- errAbort
						break graceful_loop
					}
					continue graceful_loop
				}
				if ac == -1 {
					reason = "connection_stats_unavailable"
					a.abortCh <- errAbort
					break graceful_loop
				}
				lastActive = ac
				if ac == 0 {
					reason = "connections_closed"
					a.abortCh <- errAbort
					break graceful_loop
				}
				processLog.Debug("gateway Envoy drain in progress", "active_connections", ac)
				// reset retry count
				retryCount = 0
			}
		}
	} else {
		select {
		case status := <-a.statusCh:
			infof("Envoy exited with status %v", status.err)
			infof("Graceful termination logic ended prematurely, envoy process terminated early")
			return
		case <-time.After(a.terminationDrainDuration):
			reason = "fixed_wait"
			a.abortCh <- errAbort
		}
	}
	status := <-a.statusCh
	if errors.Is(status.err, errAbort) {
		infof("Envoy aborted normally")
	} else {
		warnf("Envoy aborted abnormally: %v", status.err)
	}
}

func (a *Agent) activeProxyConnections() (int, error) {
	return a.activeProxyConnectionsWithTimeout(2 * time.Second)
}

func (a *Agent) activeProxyConnectionsWithTimeout(timeout time.Duration) (int, error) {
	adminHost := net.JoinHostPort(a.localhost, strconv.Itoa(a.adminPort))
	activeConnectionsURL := fmt.Sprintf("http://%s/stats?usedonly&filter=downstream_cx_active$", adminHost)
	stats, err := getWithTimeout(activeConnectionsURL, timeout)
	if err != nil {
		return -1, fmt.Errorf("unable to get listener stats from Envoy: %w", err)
	}
	if stats.Len() == 0 {
		return -1, nil
	}
	activeConnections := 0
	for line := range strings.SplitSeq(strings.TrimSuffix(stats.String(), "\n"), "\n") {
		name, value, ok := strings.Cut(strings.TrimSpace(line), ": ")
		parts := []string{name, value}
		if !ok {
			warnf("envoy stat line is missing separator. line:%s", line)
			continue
		}
		// downstream_cx_active is accounted under "http." and "listener." for http listeners.
		// Only consider listener stats. Listener stats also will have per worker stats, we can
		// ignore them.
		if !strings.HasPrefix(parts[0], "listener.") || strings.Contains(parts[0], "worker_") {
			continue
		}
		// Exclude admin, readiness and metrics listeners; retain all business and internal forwarding listeners.
		if a.internalListeners.Contains(parts[0]) {
			continue
		}
		val, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 64)
		if err != nil {
			warnf("failed parsing Envoy stat %s (error: %s) line: %s", parts[0], err.Error(), line)
			continue
		}
		activeConnections += int(val)
	}
	if activeConnections > 0 {
		debugf("Active connections stats: %s", stats.String())
	}
	return activeConnections, nil
}

// runWait runs the start-up command as a go routine and waits for it to finish
func (a *Agent) runWait(abortCh <-chan error) {
	err := a.proxy.Run(abortCh)
	a.proxy.Cleanup()
	a.statusCh <- exitStatus{err: err}
}
