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

// Send header-only ext_proc requests through a deployed EPE's WDS binding path.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extproc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/openkruise/agentio/bench/load"
)

func main() {
	address := flag.String(
		"address",
		"agentio-epe.agentio-perf:9002",
		"Plaintext EPE ext_proc endpoint in an isolated test cluster",
	)
	namespace := flag.String("namespace", "epe-demand-workloads", "Fixture Pod namespace")
	cluster := flag.String("cluster-id", "Kubernetes", "Workload registry cluster ID")
	path := flag.String("path", "/block", "HTTP request path")
	want := flag.Int("status", 453, "Expected immediate HTTP status; zero expects normal header processing")
	requests := flag.Int("requests", 10000, "Total requests")
	identities := flag.Int("identities", 128, "Number of fixture Pods named workload-%05d")
	offset := flag.Int("offset", 0, "First fixture Pod number")
	concurrency := flag.Int("concurrency", 16, "Concurrent ext_proc streams")
	connections := flag.Int("connections", 1, "Shared gRPC connections")
	rate := flag.Int("rate", 0, "Requests per second; zero uses closed-loop concurrency")
	duration := flag.Duration("duration", 5*time.Minute, "Maximum run duration")
	flag.Parse()
	if err := run(*address, *namespace, *cluster, *path, *want, *connections, load.Config{
		Requests:    *requests,
		Identities:  *identities,
		Offset:      *offset,
		Concurrency: *concurrency,
		Rate:        *rate,
		Duration:    *duration,
	}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(address, namespace, cluster, path string, want, connections int, config load.Config) (resultErr error) {
	if connections < 1 {
		return fmt.Errorf("connections must be positive")
	}
	clients := make([]extproc.ExternalProcessorClient, connections)
	for i := range clients {
		conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return err
		}
		defer func() { resultErr = errors.Join(resultErr, conn.Close()) }()
		clients[i] = extproc.NewExternalProcessorClient(conn)
	}
	var next atomic.Uint64
	var mu sync.Mutex
	responses := map[string]int{}
	responseBins := map[int]map[string]int{}
	var started time.Time
	config.Started = func() { started = time.Now() }
	record := func(outcome string) {
		mu.Lock()
		second := int(time.Since(started).Seconds())
		if responseBins[second] == nil {
			responseBins[second] = map[string]int{}
		}
		responseBins[second][outcome]++
		responses[outcome]++
		mu.Unlock()
	}
	result, runErr := load.Run(context.Background(), config, func(ctx context.Context, index int) error {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		stream, err := clients[(next.Add(1)-1)%uint64(connections)].Process(ctx)
		if err != nil {
			record("grpc_" + status.Code(err).String())
			return err
		}
		name := fmt.Sprintf("workload-%05d", index)
		request := &extproc.ProcessingRequest{
			Attributes: map[string]*structpb.Struct{"envoy.filters.http.ext_proc": {Fields: map[string]*structpb.Value{
				"filter_state['agentio.workload.uid']": structpb.NewStringValue(
					cluster + "//Pod/" + namespace + "/" + name,
				),
			}}},
			Request: &extproc.ProcessingRequest_RequestHeaders{RequestHeaders: &extproc.HttpHeaders{
				EndOfStream: true,
				Headers: &core.HeaderMap{Headers: []*core.HeaderValue{
					{Key: ":method", RawValue: []byte("GET")},
					{Key: ":scheme", RawValue: []byte("http")},
					{Key: ":authority", RawValue: []byte("203.0.113.7:8080")},
					{Key: ":path", RawValue: []byte(path)},
				}},
			}},
		}
		if err := stream.Send(request); err != nil {
			record("send_" + status.Code(err).String())
			return err
		}
		response, err := stream.Recv()
		if err != nil {
			record("grpc_" + status.Code(err).String())
			return err
		}
		if err := stream.CloseSend(); err != nil {
			record("close_" + status.Code(err).String())
			return err
		}
		if immediate := response.GetImmediateResponse(); immediate != nil {
			record("http_" + strconv.Itoa(int(immediate.GetStatus().GetCode())))
		} else if response.GetRequestHeaders() != nil {
			record("headers")
		} else {
			record("unexpected_response")
		}
		if want == 0 && response.GetRequestHeaders() != nil {
			return nil
		}
		if immediate := response.GetImmediateResponse(); want != 0 && immediate != nil &&
			int(immediate.GetStatus().GetCode()) == want {
			return nil
		}
		return fmt.Errorf("unexpected response for %s: %s", name, response)
	})
	if err := json.NewEncoder(os.Stdout).Encode(struct {
		load.Result
		Connections  int                    `json:"connections"`
		Responses    map[string]int         `json:"responses"`
		ResponseBins map[int]map[string]int `json:"response_bins"`
	}{result, connections, responses, responseBins}); err != nil {
		return err
	}
	if runErr != nil {
		return runErr
	}
	if result.Errors != 0 {
		return fmt.Errorf("%d requests failed: %s", result.Errors, result.FirstError)
	}
	return nil
}
