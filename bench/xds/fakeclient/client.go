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

// Package fakeclient provides a deliberately caller-driven Delta ADS client for
// simulations. Each Open owns a TCP/gRPC connection and one stream. It has no
// resource cache, automatic ACK, background receive loop, or stream reconnect;
// scenarios decide what to send, validate, delay, ACK, NACK, and when to reconnect.
package fakeclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Config is independent of any resource schema or Kubernetes identity convention.
// Node, TLSConfig and Headers must not be mutated while Open is using them.
type Config struct {
	Target      string // host:port; uses passthrough resolution, including normal DNS dialing
	Node        *core.Node
	TLSConfig   *tls.Config
	Plaintext   bool // explicit opt-in for a plaintext test server
	Headers     metadata.MD
	Token       func(context.Context) (string, error)           // optional; invoked on each Open
	DialContext func(context.Context, string) (net.Conn, error) // optional instrumentation
}

// Client supports one concurrent receiver and serialized sends. Open/Recv/Send
// are bounded by the context supplied to Open. Transport establishment may be
// lazy; receiving a response establishes that the server accepted the stream.
type Client struct {
	conn      *grpc.ClientConn
	stream    discovery.AggregatedDiscoveryService_DeltaAggregatedResourcesClient
	cancel    context.CancelFunc
	node      *core.Node
	sentNode  bool
	sendMu    sync.Mutex
	closeOnce sync.Once
}

// Open creates an independent ADS connection and stream bounded by ctx.
func Open(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.Target == "" || cfg.Node == nil || cfg.Node.Id == "" {
		return nil, errors.New("target and node.id are required")
	}
	if (cfg.TLSConfig == nil && !cfg.Plaintext) || (cfg.TLSConfig != nil && cfg.Plaintext) {
		return nil, errors.New("provide TLSConfig or explicitly select Plaintext")
	}
	transport := insecure.NewCredentials()
	if cfg.TLSConfig != nil {
		transport = credentials.NewTLS(cfg.TLSConfig.Clone())
	}
	headers := cfg.Headers.Copy()
	if headers == nil {
		headers = metadata.MD{}
	}
	if cfg.Token != nil {
		token, err := cfg.Token(ctx)
		if err != nil {
			return nil, fmt.Errorf("read token: %w", err)
		}
		token = strings.TrimSpace(token)
		if token == "" {
			return nil, errors.New("empty bearer token")
		}
		headers.Set("authorization", "Bearer "+token)
	}
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(transport),
		// Match ztunnel so silent transport failures also trigger scenario reconnects.
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	}
	if cfg.DialContext != nil {
		opts = append(opts, grpc.WithContextDialer(cfg.DialContext))
	}
	conn, err := grpc.NewClient("passthrough:///"+cfg.Target, opts...)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(metadata.NewOutgoingContext(ctx, headers))
	stream, err := discovery.NewAggregatedDiscoveryServiceClient(conn).DeltaAggregatedResources(ctx)
	if err != nil {
		cancel()
		return nil, errors.Join(err, conn.Close())
	}
	return &Client{conn: conn, stream: stream, cancel: cancel, node: proto.Clone(cfg.Node).(*core.Node)}, nil
}

// Send supports arbitrary type URLs, initial_resource_versions, subscribe and
// unsubscribe sets, and custom ACK/NACK requests. It does not mutate request.
// The configured Node is included in the first request unless explicitly set.
func (c *Client) Send(request *discovery.DeltaDiscoveryRequest) error {
	if request == nil {
		return errors.New("nil discovery request")
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	r := proto.Clone(request).(*discovery.DeltaDiscoveryRequest)
	if !c.sentNode && r.Node == nil {
		r.Node = c.node
	}
	if err := c.stream.Send(r); err != nil {
		return err
	}
	c.sentNode = true
	return nil
}

// Recv reads the next response without acknowledging it.
func (c *Client) Recv() (*discovery.DeltaDiscoveryResponse, error) { return c.stream.Recv() }

// Subscribe with no names leaves interpretation to the server, as in Delta xDS.
// Pass "*" for an explicit wildcard. Subsequent calls can add named subscriptions.
func (c *Client) Subscribe(typeURL string, names ...string) error {
	return c.Send(&discovery.DeltaDiscoveryRequest{TypeUrl: typeURL, ResourceNamesSubscribe: names})
}

// Unsubscribe removes the named subscriptions from the stream.
func (c *Client) Unsubscribe(typeURL string, names ...string) error {
	return c.Send(&discovery.DeltaDiscoveryRequest{TypeUrl: typeURL, ResourceNamesUnsubscribe: names})
}

// ACK acknowledges a response without changing subscriptions.
func (c *Client) ACK(response *discovery.DeltaDiscoveryResponse) error {
	if response == nil {
		return errors.New("nil response")
	}
	return c.Send(&discovery.DeltaDiscoveryRequest{TypeUrl: response.TypeUrl, ResponseNonce: response.Nonce})
}

// NACK rejects a response with the supplied reason.
func (c *Client) NACK(response *discovery.DeltaDiscoveryResponse, reason string) error {
	if response == nil {
		return errors.New("nil response")
	}
	return c.Send(
		&discovery.DeltaDiscoveryRequest{
			TypeUrl:       response.TypeUrl,
			ResponseNonce: response.Nonce,
			ErrorDetail:   status.New(codes.InvalidArgument, reason).Proto(),
		},
	)
}

// Close cancels the stream and closes its connection once.
func (c *Client) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.cancel()
		err = c.conn.Close()
	})
	return err
}

// FileToken reads on every Open so new streams observe projected-token rotation.
func FileToken(path string) func(context.Context) (string, error) {
	return func(context.Context) (string, error) {
		b, err := os.ReadFile(path)
		return string(b), err
	}
}

// TLSFromCA configures server verification using a PEM CA bundle.
func TLSFromCA(path, serverName string) (*tls.Config, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("CA file contains no certificates")
	}
	return &tls.Config{RootCAs: pool, ServerName: serverName, MinVersion: tls.VersionTLS12}, nil
}
