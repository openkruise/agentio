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
	"errors"
	"io"
	"time"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentlog "github.com/openkruise/agentio/pkg/log"
	"github.com/openkruise/agentio/pkg/metrics"
	"github.com/openkruise/agentio/pkg/model"
	xdsstore "github.com/openkruise/agentio/pkg/xds/store"
)

// A session owns all mutable stream state. Only its event loop writes responses;
// certificate workers return completions to that loop.
type deltaSession struct {
	server       *Server
	stream       DeltaStream
	scope        model.ClientScope
	log          *agentlog.Logger
	requests     <-chan streamRequest
	subscription xdsstore.Subscription
	watches      map[string]*watchState
	lease        *responseLease
	connection   *pushConnection
	inputClosed  bool
}

func newDeltaSession(
	server *Server,
	stream DeltaStream,
	scope model.ClientScope,
	connLog *agentlog.Logger,
	requests <-chan streamRequest,
) *deltaSession {
	return &deltaSession{
		server:       server,
		stream:       stream,
		scope:        scope,
		log:          connLog,
		requests:     requests,
		subscription: server.resources.Subscribe(stream.Context(), scope),
		watches:      make(map[string]*watchState),
		lease:        server.flow.newLease(stream.Context()),
		connection:   newPushConnection(stream.Context()),
	}
}

func (d *deltaSession) run(first *discoveryv3.DeltaDiscoveryRequest, releaseAdmission func()) error {
	defer d.lease.release()
	defer func() {
		if watch := d.watches[model.SecretType]; watch != nil && watch.sds != nil {
			watch.sds.cancel()
		}
	}()
	defer d.server.pushScheduler.cancel(d.connection)
	if err := d.handleRequest(first); err != nil {
		return err
	}
	releaseAdmission()
	for {
		if d.lease.timedOut() {
			return responseAckTimeout()
		}
		if stop, err := d.pollRequest(); stop || err != nil {
			return err
		}
		certificates, pending := d.pendingWork()
		if d.inputClosed && !pending {
			return nil
		}
		select {
		case <-d.stream.Context().Done():
			return d.stream.Context().Err()
		case <-d.lease.expired():
			return responseAckTimeout()
		case incoming := <-d.requests:
			stop, err := d.handleIncoming(incoming)
			if stop || err != nil {
				return err
			}
		case completion := <-certificates:
			if err := d.handleCertificate(completion); err != nil {
				return err
			}
		case update := <-d.subscription.Updates():
			d.enqueueUpdate(update)
		case push := <-d.connection.pushes:
			if err := d.handlePush(push); err != nil {
				return err
			}
		}
	}
}

func (d *deltaSession) enqueueUpdate(update xdsstore.Update) {
	// Bound per-stream merges before they copy a cluster-wide Address batch.
	if d.scope.Class == model.ClientDedicatedZTunnel {
		update = update.ForWorkload(d.scope.WorkloadUID, d.server.resources.Snapshot())
	}
	for typeURL, watch := range d.watches {
		if watch.started && update.Affects(typeURL) {
			d.server.pushScheduler.Enqueue(d.connection, update)
			return
		}
	}
}

// Poll before background work so ACKs and subscription changes keep moving.
func (d *deltaSession) pollRequest() (bool, error) {
	select {
	case <-d.stream.Context().Done():
		return true, d.stream.Context().Err()
	case <-d.lease.expired():
		return true, responseAckTimeout()
	case incoming := <-d.requests:
		return d.handleIncoming(incoming)
	default:
		return false, nil
	}
}

func (d *deltaSession) handleIncoming(incoming streamRequest) (bool, error) {
	if incoming.err != nil {
		if errors.Is(incoming.err, io.EOF) {
			d.inputClosed = true
			d.requests = nil
			return false, nil
		}
		return true, incoming.err
	}
	if incoming.request == nil {
		return true, status.Error(codes.InvalidArgument, "empty DeltaDiscoveryRequest")
	}
	return false, d.handleRequest(incoming.request)
}

func (d *deltaSession) handleRequest(request *discoveryv3.DeltaDiscoveryRequest) error {
	watch := d.watches[request.GetTypeUrl()]
	pureACK := watch != nil && watch.started && request.GetResponseNonce() != "" &&
		len(request.GetResourceNamesSubscribe()) == 0 && len(request.GetResourceNamesUnsubscribe()) == 0 &&
		len(request.GetInitialResourceVersions()) == 0
	if !pureACK {
		if err := d.lease.acquire(d.server.flow.requestResponsePool(d.watches)); err != nil {
			return err
		}
	}
	err := d.server.handleRequest(d.stream, d.scope, d.log, d.watches, d.subscription, request)
	d.lease.releaseAcknowledged(d.watches)
	return err
}

func (d *deltaSession) handleCertificate(completion sdsCompletion) error {
	if err := d.lease.acquire(d.server.flow.requestResponsePool(d.watches)); err != nil {
		return err
	}
	if err := d.server.sendSDSCompletions(d.stream, d.log, d.watches[model.SecretType], completion); err != nil {
		return err
	}
	d.lease.releaseAcknowledged(d.watches)
	return nil
}

func (d *deltaSession) pendingWork() (<-chan sdsCompletion, bool) {
	var ready <-chan sdsCompletion
	pending := false
	if watch := d.watches[model.SecretType]; watch != nil && watch.sds != nil {
		ready = watch.sds.ready
		pending = len(watch.sds.jobs) > 0
	}
	return ready, pending || hasPendingConfigs(d.watches)
}

func (d *deltaSession) handlePush(push *scheduledPush) error {
	defer d.server.pushScheduler.Done(push)
	// Waiting for response capacity must keep processing requests and SDS results.
	for d.lease.pool == nil {
		certificates, pending := d.pendingWork()
		if d.inputClosed && !pending {
			return nil
		}
		select {
		case <-d.stream.Context().Done():
			return d.stream.Context().Err()
		case incoming := <-d.requests:
			stop, err := d.handleIncoming(incoming)
			if stop || err != nil {
				return err
			}
		case completion := <-certificates:
			if err := d.handleCertificate(completion); err != nil {
				return err
			}
		case d.server.flow.pushSlots <- struct{}{}:
			d.lease.start(d.server.flow.pushSlots)
		}
	}
	if d.lease.timedOut() {
		return responseAckTimeout()
	}
	err := d.server.pushUpdate(d.stream, d.scope, d.log, d.watches, push.Update)
	d.lease.releaseAcknowledged(d.watches)
	if err != nil {
		return err
	}
	metrics.Default.RecordXDSConvergence(time.Since(push.Started))
	return nil
}
