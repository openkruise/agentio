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

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	servicev3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type processorConfig struct {
	requestHeaders  map[string]string
	responseHeaders map[string]string
}

func configFromEnvironment(getenv func(string) string) processorConfig {
	return processorConfig{
		requestHeaders:  parseHeaderPairs(getenv("REQUEST_HEADERS_TO_ADD")),
		responseHeaders: parseHeaderPairs(getenv("RESPONSE_HEADERS_TO_ADD")),
	}
}

func parseHeaderPairs(value string) map[string]string {
	result := make(map[string]string)
	for _, pair := range strings.Split(value, ",") {
		key, headerValue, found := strings.Cut(strings.TrimSpace(pair), "=")
		key = strings.ToLower(strings.TrimSpace(key))
		if !found || key == "" {
			continue
		}
		result[key] = strings.TrimSpace(headerValue)
	}
	return result
}

type processor struct {
	servicev3.UnimplementedExternalProcessorServer
	config processorConfig
}

func (p processor) Process(stream servicev3.ExternalProcessor_ProcessServer) error {
	for {
		request, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return status.Errorf(codes.Unknown, "receive processing request: %v", err)
		}
		if err := stream.Send(p.responseFor(request)); err != nil {
			return err
		}
	}
}

func (p processor) responseFor(request *servicev3.ProcessingRequest) *servicev3.ProcessingResponse {
	switch request.Request.(type) {
	case *servicev3.ProcessingRequest_RequestHeaders:
		return &servicev3.ProcessingResponse{Response: &servicev3.ProcessingResponse_RequestHeaders{
			RequestHeaders: headerResponse(p.config.requestHeaders),
		}}
	case *servicev3.ProcessingRequest_ResponseHeaders:
		return &servicev3.ProcessingResponse{Response: &servicev3.ProcessingResponse_ResponseHeaders{
			ResponseHeaders: headerResponse(p.config.responseHeaders),
		}}
	case *servicev3.ProcessingRequest_RequestBody:
		return &servicev3.ProcessingResponse{Response: &servicev3.ProcessingResponse_RequestBody{
			RequestBody: &servicev3.BodyResponse{Response: &servicev3.CommonResponse{}},
		}}
	case *servicev3.ProcessingRequest_ResponseBody:
		return &servicev3.ProcessingResponse{Response: &servicev3.ProcessingResponse_ResponseBody{
			ResponseBody: &servicev3.BodyResponse{Response: &servicev3.CommonResponse{}},
		}}
	case *servicev3.ProcessingRequest_RequestTrailers:
		return &servicev3.ProcessingResponse{Response: &servicev3.ProcessingResponse_RequestTrailers{
			RequestTrailers: &servicev3.TrailersResponse{HeaderMutation: &servicev3.HeaderMutation{}},
		}}
	case *servicev3.ProcessingRequest_ResponseTrailers:
		return &servicev3.ProcessingResponse{Response: &servicev3.ProcessingResponse_ResponseTrailers{
			ResponseTrailers: &servicev3.TrailersResponse{HeaderMutation: &servicev3.HeaderMutation{}},
		}}
	default:
		return &servicev3.ProcessingResponse{}
	}
}

func headerResponse(headers map[string]string) *servicev3.HeadersResponse {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	mutations := make([]*corev3.HeaderValueOption, 0, len(keys))
	for _, key := range keys {
		mutations = append(mutations, &corev3.HeaderValueOption{Header: &corev3.HeaderValue{
			Key:      key,
			RawValue: []byte(headers[key]),
		}})
	}
	return &servicev3.HeadersResponse{Response: &servicev3.CommonResponse{
		HeaderMutation: &servicev3.HeaderMutation{SetHeaders: mutations},
	}}
}

func main() {
	port := flag.Int("port", 9002, "gRPC port")
	credentialPort := flag.Int(
		"credential-provider-port",
		0,
		"serve the credential-provider HTTP fixture instead of ext-proc",
	)
	calloutPort := flag.Int("http-callout-port", 0, "serve the HTTPCallout fixture instead of ext-proc")
	oauth2Port := flag.Int(
		"oauth2-port",
		0,
		"serve OAuth2 credential/control HTTP and resource HTTPS on consecutive ports",
	)
	oauth2Cert := flag.String("oauth2-cert", "", "OAuth2 resource server certificate file")
	oauth2Key := flag.String("oauth2-key", "", "OAuth2 resource server private key file")
	flag.Parse()
	if *oauth2Port != 0 {
		log.Fatalf("serve OAuth2 fixture: %v", serveOAuth2Fixture(*oauth2Port, *oauth2Cert, *oauth2Key))
	}
	if *calloutPort != 0 {
		server := &http.Server{
			Addr:              fmt.Sprintf(":%d", *calloutPort),
			Handler:           newCalloutFixture(),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      65 * time.Second,
			IdleTimeout:       90 * time.Second,
		}
		log.Fatalf("serve HTTPCallout: %v", server.ListenAndServe())
	}
	if *credentialPort != 0 {
		log.Fatalf("serve credential provider: %v", serveCredentialProvider(*credentialPort))
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	server := grpc.NewServer(grpc.MaxConcurrentStreams(1000))
	servicev3.RegisterExternalProcessorServer(server, processor{config: configFromEnvironment(os.Getenv)})
	serveError := make(chan error, 1)
	go func() { serveError <- server.Serve(listener) }()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	select {
	case err := <-serveError:
		if err != nil {
			log.Fatalf("serve ext-proc: %v", err)
		}
	case <-ctx.Done():
		stopped := make(chan struct{})
		go func() {
			server.GracefulStop()
			close(stopped)
		}()
		select {
		case <-stopped:
		case <-time.After(10 * time.Second):
			server.Stop()
		}
	}
}
