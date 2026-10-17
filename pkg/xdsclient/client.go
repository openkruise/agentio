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

// Package xdsclient implements reusable Delta ADS watches and on-demand lookups.
// The subscription and publication ordering follows ztunnel/src/xds/client.rs.
// Unlike Istio adsc, it accepts explicit wire type URLs (including aliases) and
// concurrent demand callers. Transport credentials belong to the caller.
package xdsclient

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"math"
	"sync"
	"sync/atomic"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/prometheus/client_golang/prometheus"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"k8s.io/apimachinery/pkg/util/wait"

	agentlog "github.com/openkruise/agentio/pkg/log"
)

var log = agentlog.New("xdsclient")

// ErrNotFound indicates an explicitly removed resource.
var ErrNotFound = errors.New("xDS resource removed or unavailable")

// Watch with Wildcard=false starts with no resources; Demand adds named watches.
// Validate is called before publishing the entire response. It must not mutate value.
type Watch struct {
	TypeURL  string
	Wildcard bool
	Validate func(value *anypb.Any) error
	// Transform runs once per interested resource, after wire validation. Only
	// its result is cached. Nil keeps the complete Any. The result must be
	// immutable after publication; callbacks must not call back into Client.
	Transform func(value *anypb.Any) (any, error)
	// OnDelete decides whether an explicit subscription survives a deletion.
	// Nil retains it. Called for deleted subscribed names and vanished aliases,
	// after validation, under the client lock; it must not call back into Client.
	// Releasing an explicit name does not cancel a wildcard subscription.
	OnDelete func(name string) DeleteAction
}

// Config defines the node identity and initial watches. Node must be non-nil;
// its ID may be empty. Watches may be empty. Server-specific identity
// requirements belong to the consumer.
type Config struct {
	// MetricsRegisterer enables built-in metrics when non-nil. Use a registerer
	// with distinct constant labels when sharing a registry across clients.
	MetricsRegisterer prometheus.Registerer
	Node              *core.Node
	Watches           []Watch
}

// Resource contains a published value. Value is read-only, including any nested
// maps, slices or protobuf messages. Without Transform, Value is an *anypb.Any.
// Each update replaces the Resource rather than mutating a published value.
type Resource struct {
	Value any
}

// Snapshot owns its maps and shares immutable Resources across types.
// Connected reports whether the ADS stream is open. Synced reports whether a
// type has accepted a response on that stream, not whether every name is ready.
// Disconnection retains Resources but resets Synced; NACK preserves both.
// Consumers decide whether retained, unsynchronized values are usable.
type Snapshot struct {
	Connected bool
	Resources map[string]map[string]*Resource
	Synced    map[string]bool
	Changed   <-chan struct{}
}
type typeState struct {
	watch           Watch
	names           map[string]*subscription
	pending         map[string]struct{}
	sharedAliases   map[string]map[string]struct{}
	removed         map[string]bool
	aliases         map[string]string
	resourceAliases map[string][]string
	resources       map[string]*Resource
	synced          bool
}

// Client maintains synchronized Delta ADS resources and named subscriptions.
type Client struct {
	ads       discovery.AggregatedDiscoveryServiceClient
	cfg       Config
	mu        sync.Mutex
	types     map[string]*typeState
	changed   chan struct{}
	wake      chan struct{}
	running   atomic.Bool
	connected bool
	metrics   *clientMetrics
}

// New creates a client; call Run to start receiving resources.
func New(conn grpc.ClientConnInterface, cfg Config) (*Client, error) {
	if conn == nil || cfg.Node == nil {
		return nil, errors.New("xDS connection and node are required")
	}
	cfg.Node = proto.Clone(cfg.Node).(*core.Node)
	c := &Client{
		ads:     discovery.NewAggregatedDiscoveryServiceClient(conn),
		cfg:     cfg,
		types:   map[string]*typeState{},
		changed: make(chan struct{}),
		wake:    make(chan struct{}, 1),
	}
	for _, w := range cfg.Watches {
		if w.TypeURL == "" || c.types[w.TypeURL] != nil {
			return nil, fmt.Errorf("invalid or duplicate watch %q", w.TypeURL)
		}
		c.types[w.TypeURL] = &typeState{
			watch:           w,
			names:           map[string]*subscription{},
			pending:         map[string]struct{}{},
			sharedAliases:   map[string]map[string]struct{}{},
			removed:         map[string]bool{},
			aliases:         map[string]string{},
			resourceAliases: map[string][]string{},
			resources:       map[string]*Resource{},
		}
	}
	if cfg.MetricsRegisterer != nil {
		c.metrics = newClientMetrics(c)
		if err := cfg.MetricsRegisterer.Register(c.metrics); err != nil {
			return nil, fmt.Errorf("register xDS client metrics: %w", err)
		}
	}
	return c, nil
}

func (c *Client) notifyLocked() {
	close(c.changed)
	c.changed = make(chan struct{})
}

// Observe returns readiness and the signal closed by the next cache update.
// Readiness means each type has accepted a response on the current stream.
// Individual names may still be missing; Demand waits for those independently.
// Both are captured under the same lock, without copying resource payloads.
func (c *Client) Observe(types ...string) (<-chan struct{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, typ := range types {
		st := c.types[typ]
		if st == nil || !st.synced {
			return c.changed, false
		}
	}
	return c.changed, true
}

// Snapshot copies the publication maps; resource values are shared and read-only.
func (c *Client) Snapshot() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := Snapshot{
		Connected: c.connected,
		Resources: map[string]map[string]*Resource{},
		Synced:    map[string]bool{},
		Changed:   c.changed,
	}
	for typ, st := range c.types {
		s.Synced[typ] = st.synced
		s.Resources[typ] = maps.Clone(st.resources)
	}
	return s
}

func (c *Client) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.connected = false
	for _, st := range c.types {
		st.synced = false
	}
	c.notifyLocked()
}

// Run owns the stream until cancellation, reconnecting with bounded backoff.
// Only one Run may be active. The caller retains ownership of the gRPC connection.
func (c *Client) Run(ctx context.Context) error {
	if !c.running.CompareAndSwap(false, true) {
		return errors.New("xDS client already running")
	}
	defer c.running.Store(false)
	defer c.reset()
	initialBackoff := wait.Backoff{
		Duration: 100 * time.Millisecond,
		Factor:   2,
		Jitter:   0.2,
		Cap:      5 * time.Second,
		// Steps bounds growth, not reconnect attempts. Growth stops at Cap.
		Steps: math.MaxInt,
	}
	backoff := initialBackoff
	for ctx.Err() == nil {
		started := time.Now()
		received, err := c.runStream(ctx)
		c.reset()
		if ctx.Err() != nil {
			break
		}
		if received && time.Since(started) > time.Second {
			backoff = initialBackoff
		}
		delay := backoff.Step()
		log.Warn("xDS stream disconnected", "error", err, "retry", delay)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
	return nil
}

// The receive loop must keep draining responses while Send is flow-controlled.
// Only the writer calls Send. ACK state is bounded by resource type: a newer
// applied response supersedes the older nonce, without dropping any resource delta.
func (c *Client) runStream(parent context.Context) (bool, error) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	stream, err := c.ads.DeltaAggregatedResources(ctx, grpc.MaxCallRecvMsgSize(math.MaxInt32))
	if err != nil {
		return false, err
	}
	sent := map[string]map[string]*subscription{}
	initial := c.initialRequests(sent)
	var ackMu sync.Mutex
	acks := map[string]*discovery.DeltaDiscoveryRequest{}
	writerDone := make(chan error, 1)
	go func() {
		send := func() error {
			for _, req := range initial {
				if err := stream.Send(req); err != nil {
					return err
				}
			}
			for {
				select {
				case <-ctx.Done():
					return nil
				case <-c.wake:
				}
				ackMu.Lock()
				batch := acks
				acks = map[string]*discovery.DeltaDiscoveryRequest{}
				ackMu.Unlock()
				for _, req := range c.pendingRequests(sent) {
					if ack := batch[req.TypeUrl]; ack != nil {
						req.ResponseNonce = ack.ResponseNonce
						req.ErrorDetail = ack.ErrorDetail
					}
					batch[req.TypeUrl] = req
				}
				for _, req := range batch {
					if err := stream.Send(req); err != nil {
						return err
					}
				}
			}
		}
		writerDone <- send()
		cancel()
	}()
	c.mu.Lock()
	c.connected = true
	c.notifyLocked()
	c.mu.Unlock()
	received := false
	for {
		r, err := stream.Recv()
		if err != nil {
			cancel()
			sendErr := <-writerDone
			if sendErr != nil && status.Code(sendErr) != codes.Canceled {
				return received, sendErr
			}
			return received, err
		}
		ack := &discovery.DeltaDiscoveryRequest{TypeUrl: r.TypeUrl, ResponseNonce: r.Nonce}
		if err := c.apply(r); err != nil {
			ack.ErrorDetail = &rpcstatus.Status{Code: int32(codes.InvalidArgument), Message: err.Error()}
			log.Warn("xDS response rejected", "type", r.TypeUrl, "error", ack.ErrorDetail.Message)
		} else {
			received = true
		}
		ackMu.Lock()
		acks[r.TypeUrl] = ack
		ackMu.Unlock()
		c.wakeSubscriptions()
	}
}

func (c *Client) apply(r *discovery.DeltaDiscoveryResponse) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.types[r.TypeUrl]
	if st == nil {
		return fmt.Errorf("unregistered response type %q", r.TypeUrl)
	}
	if err := validateResponse(r, st.watch); err != nil {
		return err
	}
	// Ignore late updates for released interests. Transform the interested
	// batch before any cache or subscription mutation.
	selected := make([]*discovery.Resource, 0, len(r.Resources))
	for _, res := range r.Resources {
		if st.interested(res.Name, res.Aliases) {
			selected = append(selected, res)
		}
	}
	values, err := transformResources(selected, st.watch)
	if err != nil {
		return err
	}
	var removedAliases []string
	if !st.synced {
		// This stream does not resume resource versions. Replace retained data
		// on its first accepted response, then accumulate only fresh deltas.
		// Remember aliases of explicitly removed canonical resources before
		// discarding the old index. A fresh resource may reassign those aliases.
		for _, name := range r.RemovedResources {
			for _, alias := range st.resourceAliases[name] {
				if st.aliases[alias] == name {
					removedAliases = append(removedAliases, alias)
				}
			}
		}
		st.resources = map[string]*Resource{}
		st.removed = map[string]bool{}
		st.aliases = map[string]string{}
		st.sharedAliases = map[string]map[string]struct{}{}
		st.resourceAliases = map[string][]string{}
	}
	// Update only aliases touched by this delta. Shared host-network aliases
	// retain their owners so deleting one resource can make an alias unique again.
	touched := make(map[string]struct{}, len(removedAliases))
	for _, alias := range removedAliases {
		touched[alias] = struct{}{}
	}
	for _, res := range r.Resources {
		for _, alias := range st.resourceAliases[res.Name] {
			touched[alias] = struct{}{}
		}
		st.removeResource(res.Name)
		if !st.interested(res.Name, res.Aliases) {
			continue
		}
		st.resources[res.Name] = values[res.Name]
		st.addResourceAliases(res.Name, res.Aliases)
		for _, alias := range res.Aliases {
			delete(st.removed, alias)
		}
		delete(st.removed, res.Name)
	}
	for _, name := range r.RemovedResources {
		for _, alias := range st.resourceAliases[name] {
			touched[alias] = struct{}{}
		}
		st.removeResource(name)
	}
	for alias := range touched {
		if _, exists := st.aliases[alias]; !exists {
			c.deletedSubscription(st, alias)
		}
	}
	for _, name := range r.RemovedResources {
		c.deletedSubscription(st, name)
	}

	st.synced = true
	c.notifyLocked()
	return nil
}

func validateResponse(r *discovery.DeltaDiscoveryResponse, watch Watch) error {
	seen := map[string]bool{}
	for _, res := range r.Resources {
		if res == nil || res.Name == "" || res.Resource == nil || res.Resource.TypeUrl != r.TypeUrl || res.Ttl != nil {
			return errors.New("invalid resource or unsupported TTL")
		}
		if seen[res.Name] {
			return fmt.Errorf("duplicate resource %q", res.Name)
		}
		for _, alias := range res.Aliases {
			if alias == "" || alias == "*" {
				return fmt.Errorf("invalid alias %q", alias)
			}
		}
		seen[res.Name] = true
		if watch.Validate != nil {
			if err := watch.Validate(res.Resource); err != nil {
				return err
			}
		}
	}
	for _, name := range r.RemovedResources {
		if name == "" || seen[name] {
			return errors.New("invalid or conflicting removed resource")
		}
		seen[name] = true
	}
	return nil
}
