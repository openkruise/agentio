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

package gatewayagent

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	agentiolog "github.com/openkruise/agentio/pkg/log"
)

var xdsLog = agentiolog.New("gateway-xds")

// xdsProxy is a transparent, one-upstream-stream-per-Envoy-stream relay.
// Envoy owns subscriptions, versions, ACK/NACK and reconnect backoff. Do not ACK
// resources here, filter response types, or replay cached messages with old nonces.
type xdsProxy struct {
	discovery.UnimplementedAggregatedDiscoveryServiceServer
	config           Config
	nextConnectionID atomic.Uint64
}

func startXDS(c Config) (func(), <-chan error, error) {
	listener, err := listenSocket(c.XDSSocket)
	if err != nil {
		return nil, nil, err
	}
	server := grpc.NewServer(grpc.MaxRecvMsgSize(64 * 1024 * 1024))
	discovery.RegisterAggregatedDiscoveryServiceServer(server, &xdsProxy{config: c})
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	xdsLog.Info("gateway ADS server listening", "socket", c.XDSSocket, "address", c.Proxy.DiscoveryAddress)
	return func() {
		server.Stop()
		closeResource(listener)
	}, done, nil
}

func (p *xdsProxy) connect(ctx context.Context) (context.Context, *grpc.ClientConn, error) {
	return connectControlPlane(
		ctx,
		p.config.Proxy.DiscoveryAddress,
		p.config.XDSServerName,
		cmp.Or(p.config.XDSRootCertFile, p.config.RootCertFile),
		p.config.TokenFile,
		p.config.ClusterID,
		p.config.XDSHeaders,
		grpc.WithKeepaliveParams(
			keepalive.ClientParameters{Time: p.config.KeepaliveInterval, Timeout: p.config.KeepaliveTimeout},
		),
	)
}

func connectControlPlane(
	ctx context.Context,
	address, serverName, rootFile, tokenFile, clusterID string,
	headers map[string]string,
	options ...grpc.DialOption,
) (context.Context, *grpc.ClientConn, error) {
	// Read both files for every new stream. Projected tokens and CA bundles may
	// have rotated since the preceding ADS connection.
	root, err := os.ReadFile(rootFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read ADS trust bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(root) {
		return nil, nil, fmt.Errorf("ADS trust bundle contains no certificates")
	}
	token, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read ADS token: %w", err)
	}
	if strings.TrimSpace(string(token)) == "" {
		return nil, nil, fmt.Errorf("ADS token is empty")
	}
	options = append(options,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			RootCAs:    pool,
			ServerName: serverName,
			MinVersion: tls.VersionTLS12,
		})),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(64*1024*1024)),
	)
	conn, err := grpc.NewClient(address, options...)
	if err != nil {
		return nil, nil, err
	}
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs(
		"authorization", "Bearer "+strings.TrimSpace(string(token)),
		"clusterid", clusterID,
	))
	for key, value := range headers {
		ctx = metadata.AppendToOutgoingContext(ctx, key, value)
	}
	return ctx, conn, nil
}

func (p *xdsProxy) DeltaAggregatedResources(
	down discovery.AggregatedDiscoveryService_DeltaAggregatedResourcesServer,
) (result error) {
	received, finished := p.observeSession(down.Context())
	stage := "connect"
	defer func() { finished(result, stage) }()
	ctx, cancel := context.WithCancel(down.Context())
	defer cancel()
	ctx, conn, err := p.connect(ctx)
	if err != nil {
		return err
	}
	defer closeResource(conn)
	stage = "open_stream"
	up, err := discovery.NewAggregatedDiscoveryServiceClient(conn).DeltaAggregatedResources(ctx)
	if err != nil {
		return err
	}
	stage = "relay"
	return relay(ctx, down.Recv, up.Send, up.Recv, func(response *discovery.DeltaDiscoveryResponse) error {
		received()
		return down.Send(response)
	})
}

func (p *xdsProxy) StreamAggregatedResources(
	down discovery.AggregatedDiscoveryService_StreamAggregatedResourcesServer,
) (result error) {
	received, finished := p.observeSession(down.Context())
	stage := "connect"
	defer func() { finished(result, stage) }()
	ctx, cancel := context.WithCancel(down.Context())
	defer cancel()
	ctx, conn, err := p.connect(ctx)
	if err != nil {
		return err
	}
	defer closeResource(conn)
	stage = "open_stream"
	up, err := discovery.NewAggregatedDiscoveryServiceClient(conn).StreamAggregatedResources(ctx)
	if err != nil {
		return err
	}
	stage = "relay"
	return relay(ctx, down.Recv, up.Send, up.Recv, func(response *discovery.DiscoveryResponse) error {
		received()
		return down.Send(response)
	})
}

// Observe actual responses rather than gRPC client creation, which is asynchronous.
func (p *xdsProxy) observeSession(ctx context.Context) (func(), func(error, string)) {
	started := time.Now()
	received, finished := observeADS(ctx, p.config.metrics)
	logger := xdsLog.With("address", p.config.Proxy.DiscoveryAddress, "connection_id", p.nextConnectionID.Add(1))
	var first sync.Once
	return func() {
			received()
			first.Do(func() {
				logger.Info("gateway ADS received first control-plane response", "duration", time.Since(started))
			})
		}, func(err error, stage string) {
			finished()
			fields := []any{
				"stage", stage, "code", status.Code(err).String(), "error", err, "duration", time.Since(started),
			}
			if ctx.Err() != nil || expectedADSClosure(err) {
				logger.Debug("gateway ADS stream closed", fields...)
			} else {
				logger.Warn("gateway ADS stream failed", fields...)
			}
		}
}

// Like Istio's GRPCErrorType, recognize normal transport shutdowns even when
// gRPC reports them as RPC errors. This only controls logging, not relay errors.
func expectedADSClosure(err error) bool {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
		return true
	}
	s := status.Convert(err)
	if s.Code() == codes.Canceled {
		return true
	}
	// gRPC combines the read error (often EOF) with a preceding GOAWAY.
	// Preserve non-NO_ERROR GOAWAYs before considering generic close messages.
	if _, goaway, ok := strings.Cut(s.Message(), "received prior goaway: code: "); ok {
		code, _, _ := strings.Cut(goaway, ",")
		return code == "NO_ERROR"
	}
	if s.Code() == codes.Unavailable {
		for _, message := range []string{"client disconnected", "error reading from server: EOF", "transport is closing"} {
			if strings.Contains(s.Message(), message) {
				return true
			}
		}
	}
	// Unlike Istio, keep DeadlineExceeded visible: ADS has no normal deadline.
	return strings.Contains(err.Error(), "stream terminated by RST_STREAM with error code: NO_ERROR")
}

// Returning terminates the downstream handler and cancels the upstream RPC,
// unblocking both receive loops. Each direction has exactly one writer and no
// unbounded queue; gRPC flow control provides backpressure.
func relay[Request, Response any](ctx context.Context,
	recvDown func() (Request, error), sendUp func(Request) error,
	recvUp func() (Response, error), sendDown func(Response) error,
) error {
	done := make(chan error, 2)
	go func() { done <- copyMessages(recvDown, sendUp) }()
	go func() { done <- copyMessages(recvUp, sendDown) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func copyMessages[T any](recv func() (T, error), send func(T) error) error {
	for {
		message, err := recv()
		if err != nil {
			return err
		}
		if err := send(message); err != nil {
			return err
		}
	}
}
