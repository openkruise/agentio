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
	"time"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentlog "github.com/openkruise/agentio/pkg/log"
	"github.com/openkruise/agentio/pkg/model"
	xdsstore "github.com/openkruise/agentio/pkg/xds/store"
)

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

func (s *Server) requestResponsePool(watches map[string]*watchState) chan struct{} {
	for _, watch := range watches {
		if watch.receivedAcknowledgement {
			return s.requestSlots
		}
	}
	return s.initialSlots
}

func (s *Server) handleClientRequest(
	stream DeltaStream,
	scope model.ClientScope,
	connLog *agentlog.Logger,
	watches map[string]*watchState,
	subscription xdsstore.Subscription,
	request *discoveryv3.DeltaDiscoveryRequest,
	lease *responseLease,
) error {
	watch := watches[request.GetTypeUrl()]
	pureACK := watch != nil && watch.started && request.GetResponseNonce() != "" &&
		len(request.GetResourceNamesSubscribe()) == 0 && len(request.GetResourceNamesUnsubscribe()) == 0 &&
		len(request.GetInitialResourceVersions()) == 0
	if !pureACK {
		if err := lease.acquire(s.requestResponsePool(watches)); err != nil {
			return err
		}
	}
	err := s.handleRequest(stream, scope, connLog, watches, subscription, request)
	lease.releaseAcknowledged(watches)
	return err
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
