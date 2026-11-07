// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package httpclient

import (
	"container/list"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

// CalloutOptions controls one provider's outbound connections.
type CalloutOptions struct {
	Options
	TLS                  *tls.Config
	Protocol             string
	MaxConcurrentStreams int
}

// NewCallout retains net/http's HTTP/1 handling while allocating HTTP/2 streams
// explicitly. Each member owns at most one connection.
func NewCallout(opts CalloutOptions) *http.Client {
	p := &calloutPool{opts: opts}
	return &http.Client{
		Transport:     p,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

type calloutPool struct {
	mu      sync.Mutex
	opts    CalloutOptions
	members []*calloutConn
	waiters list.List
	retired bool
}

type calloutConn struct {
	pool      *calloutPool
	transport *http.Transport
	h2        *http2.ClientConn
	active    int
	ready     bool
	timer     *time.Timer
}

// signal wakes only the oldest waiter; arriving calls cannot jump the queue.
func (p *calloutPool) signal() {
	if first := p.waiters.Front(); first != nil {
		select {
		case first.Value.(chan struct{}) <- struct{}{}:
		default:
		}
	}
}

func (p *calloutPool) acquire(ctx context.Context) (*calloutConn, error) {
	p.mu.Lock()
	wake := make(chan struct{}, 1)
	waiter := p.waiters.PushBack(wake)
	defer func() {
		p.waiters.Remove(waiter)
		p.signal()
		p.mu.Unlock()
	}()
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		first := p.waiters.Front() == waiter
		if first {
			if c := p.available(); c != nil {
				return c, nil
			}
		}
		p.mu.Unlock()
		// Peer SETTINGS/GOAWAY can change capacity independently of a request ending.
		var timer *time.Timer
		var tick <-chan time.Time
		if first {
			timer = time.NewTimer(10 * time.Millisecond)
			tick = timer.C
		}
		select {
		case <-ctx.Done():
		case <-wake:
		case <-tick:
		}
		if timer != nil {
			timer.Stop()
		}
		p.mu.Lock()
	}
}

// available reserves capacity under mu for the oldest waiting call.
func (p *calloutPool) available() *calloutConn {
	connecting := false
	for i := 0; i < len(p.members); {
		c := p.members[i]
		limit := 1
		if c.h2 != nil {
			state := c.h2.State()
			if state.Closed || state.Closing {
				if c.active == 0 {
					p.remove(c)
					continue
				}
				i++
				continue
			}
			limit = min(p.opts.MaxConcurrentStreams, int(state.MaxConcurrentStreams))
		}
		if !c.ready {
			connecting = true
			i++
			continue
		}
		if c.active < limit {
			c.active++
			if c.timer != nil {
				c.timer.Stop()
				c.timer = nil
			}
			return c
		}
		i++
	}
	// Finish one handshake before expanding the pool so a cold burst can share
	// the negotiated streams instead of opening one connection per request.
	if !connecting && len(p.members) < p.opts.MaxConnsPerHost {
		c := p.newConn()
		c.active = 1
		p.members = append(p.members, c)
		return c
	}
	return nil
}

func (p *calloutPool) newConn() *calloutConn {
	c := &calloutConn{pool: p}
	opts := p.opts.Options
	opts.MaxConnsPerHost = 1
	opts.MaxIdleConns = 1
	opts.MaxIdleConnsPerHost = 1
	t := New(opts).Transport.(*http.Transport)
	t.TLSClientConfig = new(tls.Config)
	if p.opts.TLS != nil {
		t.TLSClientConfig = p.opts.TLS.Clone()
	}
	if p.opts.Protocol == "HTTP1" {
		t.TLSClientConfig.NextProtos = []string{"http/1.1"}
	} else {
		t.TLSClientConfig.NextProtos = []string{"h2", "http/1.1"}
	}
	t.Protocols = new(http.Protocols)
	t.Protocols.SetHTTP1(p.opts.Protocol != "HTTP2")
	t.Protocols.SetHTTP2(p.opts.Protocol != "HTTP1")
	t.ForceAttemptHTTP2 = false
	t.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	if p.opts.Protocol != "HTTP1" {
		t.TLSNextProto["h2"] = func(_ string, conn *tls.Conn) http.RoundTripper {
			return &calloutH2{owner: c, conn: conn}
		}
	}
	if p.opts.Protocol == "HTTP2" {
		t.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			ctx, cancel := context.WithTimeout(ctx, p.opts.TLSHandshakeTimeout)
			defer cancel()
			conn, err := t.DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			cfg := new(tls.Config)
			if p.opts.TLS != nil {
				cfg = p.opts.TLS.Clone()
			}
			if cfg.ServerName == "" {
				cfg.ServerName, _, err = net.SplitHostPort(address)
				if err != nil {
					conn.Close() //nolint:errcheck // Preserve the connection failure; this socket is being discarded.
					return nil, err
				}
			}
			cfg.NextProtos = []string{"h2"}
			secure := tls.Client(conn, cfg)
			if err = secure.HandshakeContext(ctx); err != nil {
				conn.Close() //nolint:errcheck // Preserve the connection failure; this socket is being discarded.
				return nil, err
			}
			if secure.ConnectionState().NegotiatedProtocol != "h2" {
				secure.Close() //nolint:errcheck // Discard a connection with the wrong negotiated protocol.
				return nil, fmt.Errorf("HTTP2 requires ALPN h2")
			}
			return secure, nil
		}
	}
	c.transport = t
	return c
}

// calloutH2 synchronizes the first request with peer SETTINGS using a PING ack.
// The peer's first frame must be SETTINGS; by the time the ack is read, the
// library has applied those settings. No speculative request needs retrying.
type calloutH2 struct {
	owner *calloutConn
	conn  net.Conn
	once  sync.Once
	cc    *http2.ClientConn
	err   error
}

func (h *calloutH2) RoundTrip(req *http.Request) (*http.Response, error) {
	h.once.Do(func() {
		t := &http2.Transport{AllowHTTP: true, StrictMaxConcurrentStreams: true}
		h.cc, h.err = t.NewClientConn(h.conn)
		if h.err == nil {
			h.err = h.cc.Ping(req.Context())
		}
		if h.err != nil {
			h.conn.Close() //nolint:errcheck // Preserve the connection failure; this socket is being discarded.
			return
		}
		p := h.owner.pool
		p.mu.Lock()
		h.owner.h2 = h.cc
		h.owner.ready = true
		p.signal()
		p.mu.Unlock()
	})
	if h.err != nil {
		return nil, h.err
	}
	// A released application slot can precede HTTP/2 stream cleanup; let RoundTrip wait.
	return h.cc.RoundTrip(req)
}

func (p *calloutPool) RoundTrip(req *http.Request) (*http.Response, error) {
	c, err := p.acquire(req.Context())
	if err != nil {
		if req.Body != nil {
			req.Body.Close() //nolint:errcheck // Return the transport error after releasing the request body.
		}
		return nil, err
	}
	var resp *http.Response
	if req.URL.Scheme == "http" && p.opts.Protocol == "HTTP2" {
		p.mu.Lock()
		cc := c.h2
		p.mu.Unlock()
		if cc == nil {
			address := req.URL.Host
			if req.URL.Port() == "" {
				address = net.JoinHostPort(req.URL.Hostname(), "80")
			}
			var conn net.Conn
			conn, err = c.transport.DialContext(req.Context(), "tcp", address)
			if err == nil {
				resp, err = (&calloutH2{owner: c, conn: conn}).RoundTrip(req)
			}
		} else {
			resp, err = cc.RoundTrip(req)
		}
	} else {
		trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
			// HTTP/2 readiness is published only after SETTINGS synchronization.
			if tc, ok := info.Conn.(*tls.Conn); ok && tc.ConnectionState().NegotiatedProtocol == "h2" {
				return
			}
			p.mu.Lock()
			c.ready = true
			p.signal()
			p.mu.Unlock()
		}}
		traced := req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
		resp, err = c.transport.RoundTrip(traced)
	}
	if err != nil {
		if req.Body != nil {
			req.Body.Close() //nolint:errcheck // Return the transport error after releasing the request body.
		}
		p.release(c, true)
		return nil, err
	}
	resp.Body = &calloutBody{ReadCloser: resp.Body, done: func() { p.release(c, false) }}
	return resp, nil
}

type calloutBody struct {
	io.ReadCloser
	once sync.Once
	done func()
}

func (b *calloutBody) Read(v []byte) (int, error) {
	n, err := b.ReadCloser.Read(v)
	if err != nil {
		b.once.Do(b.done)
	}
	return n, err
}
func (b *calloutBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.done)
	return err
}

func (p *calloutPool) release(c *calloutConn, failed bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	c.active--
	if c.active == 0 {
		idle := 0
		for _, other := range p.members {
			if other.active == 0 {
				idle++
			}
		}
		if failed || p.retired || idle > p.opts.MaxIdleConnsPerHost {
			p.remove(c)
		} else {
			var idleTimer *time.Timer
			idleTimer = time.AfterFunc(p.opts.IdleConnTimeout, func() {
				p.mu.Lock()
				defer p.mu.Unlock()
				if c.active == 0 && c.timer == idleTimer {
					p.remove(c)
					p.signal()
				}
			})
			c.timer = idleTimer
		}
	}
	p.signal()
}

// remove requires mu and no active callers. Closing both transports also
// releases HTTP/2 sockets handed off through TLSNextProto.
func (p *calloutPool) remove(c *calloutConn) {
	for i, member := range p.members {
		if member == c {
			p.members = append(p.members[:i], p.members[i+1:]...)
			if c.timer != nil {
				c.timer.Stop()
				c.timer = nil
			}
			c.transport.CloseIdleConnections()
			if c.h2 != nil {
				c.h2.Close() //nolint:errcheck // No requests remain on this retired or idle connection.
			}
			return
		}
	}
}
func (p *calloutPool) CloseIdleConnections() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := 0; i < len(p.members); {
		c := p.members[i]
		if c.active == 0 {
			p.remove(c)
		} else {
			i++
		}
	}
	p.signal()
}

// Retire lets callers that already selected this provider finish, then closes
// their connections immediately instead of keeping an obsolete pool warm.
func (p *calloutPool) Retire() {
	p.mu.Lock()
	p.retired = true
	p.mu.Unlock()
	p.CloseIdleConnections()
}
