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
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"

	agentiolog "github.com/openkruise/agentio/pkg/log"
)

var xdsLog = agentiolog.New("gateway-xds")

// xdsProxy is a transparent, one-upstream-stream-per-Envoy-stream relay.
// Envoy owns subscriptions, versions, ACK/NACK and reconnect backoff. Do not ACK
// resources here, filter response types, or replay cached messages with old nonces.
type xdsProxy struct {
	discovery.UnimplementedAggregatedDiscoveryServiceServer
	config Config
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
		envStringFallback(p.config.XDSRootCertFile, p.config.RootCertFile),
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
) error {
	received, finished := observeADS(down.Context(), p.config.metrics)
	defer finished()
	ctx, cancel := context.WithCancel(down.Context())
	defer cancel()
	ctx, conn, err := p.connect(ctx)
	if err != nil {
		return err
	}
	defer closeResource(conn)
	up, err := discovery.NewAggregatedDiscoveryServiceClient(conn).DeltaAggregatedResources(ctx)
	if err != nil {
		return err
	}
	return relay(ctx, down.Recv, up.Send, up.Recv, func(response *discovery.DeltaDiscoveryResponse) error {
		received()
		return down.Send(response)
	})
}

func (p *xdsProxy) StreamAggregatedResources(
	down discovery.AggregatedDiscoveryService_StreamAggregatedResourcesServer,
) error {
	received, finished := observeADS(down.Context(), p.config.metrics)
	defer finished()
	ctx, cancel := context.WithCancel(down.Context())
	defer cancel()
	ctx, conn, err := p.connect(ctx)
	if err != nil {
		return err
	}
	defer closeResource(conn)
	up, err := discovery.NewAggregatedDiscoveryServiceClient(conn).StreamAggregatedResources(ctx)
	if err != nil {
		return err
	}
	return relay(ctx, down.Recv, up.Send, up.Recv, func(response *discovery.DiscoveryResponse) error {
		received()
		return down.Send(response)
	})
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
		xdsLog.Debug("gateway ADS stream closed", "error", err)
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

func envStringFallback(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}
