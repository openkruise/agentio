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

package xdsclient

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
)

// DeleteAction controls the lifetime of a named subscription after deletion.
type DeleteAction uint8

const (
	// KeepSubscription continues watching for the resource to reappear.
	KeepSubscription DeleteAction = iota
	// ReleaseSubscription ends this demand; a future Demand subscribes again.
	ReleaseSubscription
)

// Each subscription is a generation. Waiters keep their generation even after
// the name has been released and reused, so they cannot miss its deletion.
type subscription struct {
	err        error
	done       chan struct{}
	owners     int
	persistent bool
}

// ErrReleased means a locally owned subscription was released, not that the
// control plane deleted the resource.
var ErrReleased = errors.New("xDS subscription released")

// Subscription owns one interest in a named resource. Updates remain visible
// until Release or server-driven subscription deletion. Values stay immutable.
type Subscription struct {
	client     *Client
	typ        string
	name       string
	generation *subscription
	released   bool // guarded by client.mu
}

// Acquire creates an independently releasable interest. It does not wait for
// discovery. Callers must Release even if Demand is canceled or fails.
func (c *Client) Acquire(typ, name string) (*Subscription, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, sub, err := c.subscribeLocked(typ, name)
	if err != nil {
		return nil, err
	}
	sub.owners++
	return &Subscription{client: c, typ: typ, name: name, generation: sub}, nil
}

// Done closes when this subscription generation ends (local final release or
// OnDelete=ReleaseSubscription). It is not closed by ordinary resource updates.
func (s *Subscription) Done() <-chan struct{} { return s.generation.done }

// Demand waits for the current resource within this subscription generation.
func (s *Subscription) Demand(ctx context.Context) (*Resource, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.client.mu.Lock()
	return s.client.waitLocked(ctx, s.client.types[s.typ], s.name, s.generation, s)
}

// Release relinquishes only this owner's interest. Plain Client.Demand and
// other handles remain subscribed. Old handles cannot release a newer generation.
func (s *Subscription) Release() {
	c := s.client
	c.mu.Lock()
	defer c.mu.Unlock()
	if s.released {
		return
	}
	s.released = true
	sub := s.generation
	sub.owners--
	st := c.types[s.typ]
	if st.names[s.name] == sub && sub.owners == 0 && !sub.persistent {
		sub.err = ErrReleased
		close(sub.done)
		delete(st.names, s.name)
		st.pending[s.name] = struct{}{}
		delete(st.removed, s.name)
		st.releaseResource(s.name)
		c.wakeSubscriptions()
	}
	c.notifyLocked()
}

func (c *Client) subscribeLocked(typ, name string) (*typeState, *subscription, error) {
	if name == "" || name == "*" {
		return nil, nil, errors.New("demand requires an exact resource name")
	}
	st := c.types[typ]
	if st == nil {
		return nil, nil, fmt.Errorf("unregistered type %q", typ)
	}
	sub := st.names[name]
	if sub == nil {
		sub = &subscription{done: make(chan struct{})}
		st.names[name] = sub
		st.pending[name] = struct{}{}
		delete(st.removed, name)
		c.wakeSubscriptions()
	}
	return st, sub, nil
}

func (st *typeState) interested(name string, aliases []string) bool {
	if st.watch.Wildcard || st.names[name] != nil {
		return true
	}
	for _, alias := range aliases {
		if st.names[alias] != nil {
			return true
		}
	}
	return false
}

func (st *typeState) releaseResource(name string) {
	if st.watch.Wildcard {
		return
	}
	canonical, alias := st.aliases[name]
	if !alias {
		canonical = name
	}
	if alias && canonical == "" {
		for candidate := range st.sharedAliases[name] {
			if !st.interested(candidate, st.resourceAliases[candidate]) {
				st.removeResource(candidate)
			}
		}
	} else if !st.interested(canonical, st.resourceAliases[canonical]) {
		st.removeResource(canonical)
	}
}

func (st *typeState) addResourceAliases(name string, aliases []string) {
	st.resourceAliases[name] = append([]string(nil), aliases...)
	for _, alias := range aliases {
		owner, found := st.aliases[alias]
		switch {
		case !found:
			st.aliases[alias] = name
		case owner == "":
			st.sharedAliases[alias][name] = struct{}{}
		case owner != name:
			st.sharedAliases[alias] = map[string]struct{}{owner: {}, name: {}}
			st.aliases[alias] = ""
		}
	}
}

func (st *typeState) removeResource(name string) {
	aliases := st.resourceAliases[name]
	delete(st.resources, name)
	delete(st.resourceAliases, name)
	for _, alias := range aliases {
		if owners := st.sharedAliases[alias]; owners != nil {
			delete(owners, name)
			if len(owners) == 1 {
				for owner := range owners {
					st.aliases[alias] = owner
				}
				delete(st.sharedAliases, alias)
			}
		} else if st.aliases[alias] == name {
			delete(st.aliases, alias)
		}
	}
}

func (c *Client) wakeSubscriptions() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// deletedSubscription is called while applying a validated response under mu.
func (c *Client) deletedSubscription(st *typeState, name string) {
	sub := st.names[name]
	if sub == nil {
		return
	}
	if st.watch.OnDelete == nil || st.watch.OnDelete(name) == KeepSubscription {
		st.removed[name] = true
		return
	}
	sub.err = ErrNotFound
	close(sub.done)
	delete(st.names, name)
	st.pending[name] = struct{}{}
	delete(st.removed, name)
	c.wakeSubscriptions()
}

// Demand returns a read-only resource, waiting for publication or removal. Successful
// subscriptions remain watched so later policy changes are observed. All
// concurrent waiters are notified; cancellation does not cancel other waiters.
// A released deletion ends existing waiters with ErrNotFound; a later call
// creates a new subscription, even before the old unsubscribe has been sent.
func (c *Client) Demand(ctx context.Context, typ, name string) (*Resource, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	st, sub, err := c.subscribeLocked(typ, name)
	if err != nil {
		c.mu.Unlock()
		return nil, err
	}
	sub.persistent = true
	return c.waitLocked(ctx, st, name, sub, nil)
}

// waitLocked consumes the lock and always returns with it released.
func (c *Client) waitLocked(
	ctx context.Context,
	st *typeState,
	name string,
	sub *subscription,
	owner *Subscription,
) (_ *Resource, err error) {
	var started time.Time
	for {
		if sub.err != nil {
			c.mu.Unlock()
			return nil, sub.err
		}
		if owner != nil && owner.released {
			c.mu.Unlock()
			return nil, ErrReleased
		}
		if st.synced {
			canonical := name
			if target, alias := st.aliases[name]; alias {
				if target == "" {
					c.mu.Unlock()
					return nil, fmt.Errorf("ambiguous resource alias %q", name)
				}
				canonical = target
			}
			if value := st.resources[canonical]; value != nil {
				result := value
				c.mu.Unlock()
				return result, nil
			}
			if st.removed[name] {
				c.mu.Unlock()
				return nil, ErrNotFound
			}
		}
		if c.metrics != nil && started.IsZero() {
			started = time.Now()
			waiters := c.metrics.waiters.WithLabelValues(st.watch.TypeURL)
			waiters.Inc()
			defer func() {
				waiters.Dec()
				c.metrics.waitDuration.WithLabelValues(st.watch.TypeURL, demandResult(err)).
					Observe(time.Since(started).Seconds())
			}()
		}
		changed := c.changed
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-changed:
		}
		c.mu.Lock()
	}
}

func (c *Client) initialRequests(sent map[string]map[string]*subscription) []*discovery.DeltaDiscoveryRequest {
	c.mu.Lock()
	initial := make([]*discovery.DeltaDiscoveryRequest, 0, len(c.types))
	for typ, st := range c.types {
		req := &discovery.DeltaDiscoveryRequest{Node: c.cfg.Node, TypeUrl: typ}
		sent[typ] = map[string]*subscription{}
		st.pending = map[string]struct{}{}
		for name, sub := range st.names {
			req.ResourceNamesSubscribe = append(req.ResourceNamesSubscribe, name)
			sent[typ][name] = sub
		}
		sort.Strings(req.ResourceNamesSubscribe)
		if st.watch.Wildcard {
			req.ResourceNamesSubscribe = append(req.ResourceNamesSubscribe, "*")
		} else if len(req.ResourceNamesSubscribe) == 0 {
			// The same subscribe/unsubscribe handshake used by ztunnel prevents an
			// empty initial request from becoming an implicit wildcard subscription.
			req.ResourceNamesSubscribe = []string{"*"}
			req.ResourceNamesUnsubscribe = []string{"*"}
		}
		initial = append(initial, req)
	}
	c.mu.Unlock()
	sort.Slice(initial, func(i, j int) bool { return initial[i].TypeUrl < initial[j].TypeUrl })
	return initial
}

func (c *Client) pendingRequests(sent map[string]map[string]*subscription) []*discovery.DeltaDiscoveryRequest {
	c.mu.Lock()
	requests := []*discovery.DeltaDiscoveryRequest{}
	for typ, st := range c.types {
		req := &discovery.DeltaDiscoveryRequest{TypeUrl: typ}
		for name := range st.pending {
			sub := st.names[name]
			// A new generation must resubscribe even if the previous generation's
			// unsubscribe has not yet been sent.
			if sub != nil && sent[typ][name] != sub {
				req.ResourceNamesSubscribe = append(req.ResourceNamesSubscribe, name)
				sent[typ][name] = sub
			} else if sub == nil && sent[typ][name] != nil {
				req.ResourceNamesUnsubscribe = append(req.ResourceNamesUnsubscribe, name)
				delete(sent[typ], name)
			}
		}
		st.pending = map[string]struct{}{}
		if len(req.ResourceNamesSubscribe)+len(req.ResourceNamesUnsubscribe) > 0 {
			sort.Strings(req.ResourceNamesSubscribe)
			sort.Strings(req.ResourceNamesUnsubscribe)
			requests = append(requests, req)
		}
	}
	c.mu.Unlock()

	return requests
}
