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

package xds

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"golang.org/x/time/rate"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var errRequestRateLimited = errors.New("request rate limit exceeded")

type flowControlConfig struct {
	concurrency      int
	requestRateLimit float64
	requestWait      time.Duration
	sendTimeout      time.Duration
	ackTimeout       time.Duration
}

func defaultFlowControlConfig(concurrency int, requestRateLimit float64) flowControlConfig {
	return flowControlConfig{
		concurrency:      concurrency,
		requestRateLimit: requestRateLimit,
		requestWait:      time.Second,
		sendTimeout:      5 * time.Second,
		ackTimeout:       5 * time.Second,
	}
}

// One server owns these pools; each stream owns its response lease.
type flowController struct {
	config       flowControlConfig
	requestLimit *rate.Limiter
	initialSlots chan struct{}
	requestSlots chan struct{}
	pushSlots    chan struct{}
}

func newFlowController(config flowControlConfig) *flowController {
	return &flowController{
		config:       config,
		requestLimit: rate.NewLimiter(rate.Limit(config.requestRateLimit), 1),
		// Responses cannot borrow scheduler capacity: an assigned push may
		// be waiting for the same stream's request handler to finish.
		initialSlots: make(chan struct{}, config.concurrency),
		requestSlots: make(chan struct{}, config.concurrency),
		pushSlots:    make(chan struct{}, config.concurrency),
	}
}

func (f *flowController) newLease(ctx context.Context) *responseLease {
	return &responseLease{ctx: ctx, wait: f.config.requestWait, timeout: f.config.ackTimeout}
}

func (f *flowController) acceptRequest(ctx context.Context) error {
	if f.requestLimit.Limit() == 0 {
		return nil
	}
	wait, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if err := f.requestLimit.Wait(wait); err != nil {
		return fmt.Errorf("%w: %w", errRequestRateLimited, err)
	}
	return nil
}

func invalidRequestRateLimit(limit float64) bool {
	return limit < 0 || math.IsNaN(limit) || math.IsInf(limit, 0)
}

// A stream reuses one lease across response types so an initial subscription
// batch never waits for its own ACKs. Send returning only means data was queued.
type responseLease struct {
	ctx      context.Context
	wait     time.Duration
	timeout  time.Duration
	pool     chan struct{}
	timer    *time.Timer
	deadline time.Time
}

func (l *responseLease) acquire(pool chan struct{}) error {
	if l.timedOut() {
		return responseAckTimeout()
	}
	if l.pool != nil {
		return nil
	}
	wait, cancel := context.WithTimeout(l.ctx, l.wait)
	defer cancel()
	select {
	case pool <- struct{}{}:
		l.start(pool)
		return nil
	case <-wait.Done():
		if l.ctx.Err() != nil {
			return status.FromContextError(l.ctx.Err()).Err()
		}
		return status.Error(codes.ResourceExhausted, "xDS response concurrency limit exceeded")
	}
}

func (l *responseLease) start(pool chan struct{}) {
	l.pool = pool
	l.deadline = time.Now().Add(l.timeout)
	l.timer = time.NewTimer(l.timeout)
}

func (l *responseLease) release() {
	if l.pool != nil {
		<-l.pool
		l.pool = nil
		l.timer.Stop()
	}
}

func (l *responseLease) releaseAcknowledged(watches map[string]*watchState) {
	var oldest time.Time
	for _, watch := range watches {
		if len(watch.unacknowledged) > 0 {
			at := watch.unacknowledged[0].at
			if oldest.IsZero() || at.Before(oldest) {
				oldest = at
			}
		}
	}
	if oldest.IsZero() {
		l.release()
		return
	}
	deadline := oldest.Add(l.timeout)
	if !deadline.Equal(l.deadline) {
		l.deadline = deadline
		l.timer.Reset(time.Until(deadline))
	}
}

func (l *responseLease) expired() <-chan time.Time {
	if l.pool == nil {
		return nil
	}
	return l.timer.C
}

func (l *responseLease) timedOut() bool {
	return l.pool != nil && !time.Now().Before(l.deadline)
}

func responseAckTimeout() error {
	return status.Error(codes.DeadlineExceeded, "xDS response acknowledgement timeout")
}

func (f *flowController) requestResponsePool(watches map[string]*watchState) chan struct{} {
	for _, watch := range watches {
		if watch.receivedAcknowledgement {
			return f.requestSlots
		}
	}
	return f.initialSlots
}

type boundedSendStream struct {
	DeltaStream
	timeout time.Duration
}

func (s *boundedSendStream) Send(response *discoveryv3.DeltaDiscoveryResponse) error {
	done := make(chan error, 1)
	go func() { done <- s.DeltaStream.Send(response) }()
	timer := time.NewTimer(s.timeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-s.Context().Done():
		return status.FromContextError(s.Context().Err()).Err()
	case <-timer.C:
		// Returning from the RPC handler cancels the transport and unblocks Send.
		return status.Error(codes.DeadlineExceeded, "xDS response send timeout")
	}
}
