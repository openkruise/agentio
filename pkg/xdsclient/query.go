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
	"bytes"
	"context"
	"errors"
	"time"

	"google.golang.org/protobuf/types/known/anypb"
)

// Query fetches one exact name. An empty canonical name and nil value mean authoritative absence.
type Query func(context.Context, string) (canonical string, value *anypb.Any, ttl time.Duration, err error)

type queryEntry struct {
	canonical string
	expires   time.Time
	flight    *queryFlight
}

type queryFlight struct {
	done  chan struct{}
	value *Resource
	err   error
}

// Aliases may hold the same compiled resource. Keep its wire bytes so unchanged
// TTL refreshes can skip policy compilation and admission publication.
type queryPublication struct {
	owners   int
	body     *anypb.Any
	rejected bool
}

// queryLocked consumes the client lock. Lease owners share the read but keep independent deadlines.
func (c *Client) queryLocked(
	ctx context.Context,
	st *typeState,
	name string,
	sub *subscription,
	owner *Subscription,
) (*Resource, error) {
	if sub.err != nil || (owner != nil && owner.released) {
		c.mu.Unlock()
		return nil, ErrReleased
	}
	if sub.query == nil {
		sub.query = new(queryEntry)
	}
	entry := sub.query
	if time.Now().Before(entry.expires) {
		v := st.resources[entry.canonical]
		c.mu.Unlock()
		if v == nil {
			return nil, ErrNotFound
		}
		return v, nil
	}
	f := entry.flight
	if f == nil {
		f = &queryFlight{done: make(chan struct{})}
		entry.flight = f
		go c.fetch(context.WithoutCancel(ctx), st, name, sub, f)
	}
	for {
		if sub.changed == nil {
			sub.changed = make(chan struct{})
		}
		changed := sub.changed
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-changed:
		case <-f.done:
		}
		c.mu.Lock()
		if sub.err != nil || (owner != nil && owner.released) {
			c.mu.Unlock()
			return nil, ErrReleased
		}
		select {
		case <-f.done:
			c.mu.Unlock()
			return f.value, f.err
		default:
		}
	}
}

func (c *Client) fetch(ctx context.Context, st *typeState, name string, sub *subscription, f *queryFlight) {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	canonical, body, ttl, err := st.watch.Query(ctx, name)

	c.mu.Lock()
	defer c.mu.Unlock()
	defer close(f.done)
	defer func() { sub.query.flight = nil }()
	if st.names[name] != sub {
		f.err = ErrReleased
		return
	}
	if err != nil {
		f.err = err
		return
	}
	if ttl < 0 || (canonical == "") != (body == nil) || (body != nil && body.TypeUrl != st.watch.TypeURL) {
		f.err = errors.New("invalid resource query response")
		return
	}
	if body == nil {
		f.err = ErrNotFound
	} else {
		f.value, f.err = c.publishQueryLocked(st, name, sub, canonical, body)
		if f.err != nil {
			return
		}
	}
	if canonical != sub.query.canonical {
		st.releaseQuery(sub)
		if canonical != "" {
			st.queried[canonical].owners++
			sub.query.canonical = canonical
		}
		c.notifyLocked()
	}
	sub.query.expires = time.Now().Add(ttl)
}

func (c *Client) publishQueryLocked(
	st *typeState,
	name string,
	sub *subscription,
	canonical string,
	body *anypb.Any,
) (*Resource, error) {
	prior := st.resources[canonical]
	if p := st.queried[canonical]; p != nil && bytes.Equal(p.body.Value, body.Value) {
		if p.rejected {
			p.rejected = false
			st.changed(canonical, nil)
			c.notifyLocked()
		}
		return prior, nil
	}

	c.mu.Unlock()
	value, err := decodeQuery(st.watch, body)
	c.mu.Lock()
	if st.names[name] != sub {
		return nil, ErrReleased
	}
	if err != nil {
		if p := st.queried[canonical]; p != nil {
			p.rejected = true
		}
		st.rejectResource(canonical, []string{name}, err)
		return nil, err
	}
	if current := st.resources[canonical]; current != nil && current != prior {
		// A concurrent alias already published a fresh value during compilation.
		return current, nil
	}

	current := &Resource{Value: value}
	st.resources[canonical] = current
	p := st.queried[canonical]
	if p == nil {
		p = new(queryPublication)
		st.queried[canonical] = p
	}
	p.body = body
	p.rejected = false
	st.changed(canonical, nil)
	c.notifyLocked()
	return current, nil
}

func decodeQuery(w Watch, body *anypb.Any) (any, error) {
	if w.Validate != nil {
		if err := w.Validate(body); err != nil {
			return nil, err
		}
	}
	if w.Transform != nil {
		return w.Transform(body)
	}
	return body, nil
}

func (st *typeState) releaseQuery(sub *subscription) {
	if sub.query == nil || sub.query.canonical == "" {
		return
	}
	name := sub.query.canonical
	sub.query.canonical = ""
	p := st.queried[name]
	p.owners--
	if p.owners == 0 {
		delete(st.queried, name)
		delete(st.resources, name)
		st.changed(name, nil)
	}
}
