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

// gateway-fixture isolates Envoy HTTP, ext_proc transport and the real EPE engine.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	extpb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/go-logr/logr"
	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"google.golang.org/grpc"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/openkruise/agentio/bench/load"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/extproc"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/headermutation"
	"github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
)

type fixedProfiles []*securityprofile.Profile

func (p fixedProfiles) ResolveProfiles(context.Context, subject.Subject) ([]*securityprofile.Profile, error) {
	return p, nil
}

func makeEPE(n int) (*extproc.Server, error) {
	regs, err := filter.Build(headermutation.Definition())
	if err != nil {
		return nil, err
	}
	profiles := make(fixedProfiles, n)
	for i := range profiles {
		obj := &v1alpha1.SecurityProfile{
			ObjectMeta: metav1.ObjectMeta{Name: "p" + strconv.Itoa(i), Namespace: "bench", ResourceVersion: "1"},
		}
		obj.Spec.Rules = []v1alpha1.SecurityRule{
			{
				Name:  "header",
				Match: []v1alpha1.RuleMatch{{Domains: []string{"*"}}},
				Actions: v1alpha1.SecurityRuleActions{
					HeaderManipulation: &v1alpha1.HeaderManipulationAction{
						Set: []v1alpha1.HeaderValue{{Name: "x-policy", Value: "applied"}},
					},
				},
			},
		}
		profiles[i], err = securityprofile.NewProfile(obj, &obj.Spec)
		if err != nil {
			return nil, err
		}
		if err = profiles[i].Project(regs); err != nil {
			return nil, err
		}
	}
	return extproc.NewServer(
		extproc.ServerDeps{
			Registrations:               regs,
			Resolve:                     securityprofile.NewResolver(profiles, regs, nil, nil),
			FailClosedOnMissingIdentity: true,
		},
	), nil
}

type passProcessor struct {
	extpb.UnimplementedExternalProcessorServer
	delay time.Duration
}

func (p passProcessor) Process(stream extpb.ExternalProcessor_ProcessServer) error {
	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if p.delay > 0 {
			timer := time.NewTimer(p.delay)
			select {
			case <-stream.Context().Done():
				timer.Stop()
				return stream.Context().Err()
			case <-timer.C:
			}
		}
		resp := &extpb.ProcessingResponse{}
		switch req.Request.(type) {
		case *extpb.ProcessingRequest_RequestHeaders:
			resp.Response = &extpb.ProcessingResponse_RequestHeaders{RequestHeaders: &extpb.HeadersResponse{}}
		case *extpb.ProcessingRequest_ResponseHeaders:
			resp.Response = &extpb.ProcessingResponse_ResponseHeaders{ResponseHeaders: &extpb.HeadersResponse{}}
		case *extpb.ProcessingRequest_RequestBody:
			resp.Response = &extpb.ProcessingResponse_RequestBody{RequestBody: &extpb.BodyResponse{}}
		case *extpb.ProcessingRequest_ResponseBody:
			resp.Response = &extpb.ProcessingResponse_ResponseBody{ResponseBody: &extpb.BodyResponse{}}
		default:
			return fmt.Errorf("unexpected ext_proc message %T", req.Request)
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
	}
}

func origin(w http.ResponseWriter, r *http.Request) {
	if _, err := io.Copy(io.Discard, r.Body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("X-Policy", r.Header.Get("X-Policy"))
	w.Header().Set("Content-Type", "text/plain")
	if _, err := io.WriteString(w, "ok\n"); err != nil {
		ctrllog.Log.Error(err, "write origin response")
	}
}

func run(args []string) error {
	f := flag.NewFlagSet("gateway-fixture", flag.ContinueOnError)
	mode := f.String("mode", "origin", "origin, noop, epe, load")
	address := f.String("listen", "127.0.0.1:19201", "HTTP or gRPC listen address")
	n := f.Int("profiles", 0, "matching profiles, each with one header mutation")
	delay := f.Duration("delay", 0, "noop: processing delay per message")
	authority := f.String("authority", "", "override HTTP Host independently of the gateway URL")
	url := f.String("url", "http://127.0.0.1:19200/", "load target")
	requests := f.Int("requests", 100000, "load request count")
	concurrency := f.Int("concurrency", 64, "load workers")
	rate := f.Int("rate", 0, "load rate; zero is closed-loop")
	body := f.Int("body-bytes", 0, "load POST request bytes")
	wantPolicy := f.Bool("expect-policy", false, "validate real EPE header mutation at origin")
	if err := f.Parse(args); err != nil {
		return err
	}
	if *n < 0 || *body < 0 {
		return fmt.Errorf("profiles and body-bytes must be nonnegative")
	}
	switch *mode {
	case "origin":
		return http.ListenAndServe(*address, http.HandlerFunc(origin))
	case "noop", "epe":
		server := grpc.NewServer()
		if *mode == "epe" {
			processor, err := makeEPE(*n)
			if err != nil {
				return err
			}
			extpb.RegisterExternalProcessorServer(server, processor)
		} else {
			extpb.RegisterExternalProcessorServer(server, passProcessor{delay: *delay})
		}
		listener, err := net.Listen("tcp", *address)
		if err != nil {
			return err
		}
		return server.Serve(listener)
	case "load":
		return runLoad(*url, *requests, *concurrency, *rate, *body, *wantPolicy, *authority)
	default:
		return fmt.Errorf("unknown mode %q", *mode)
	}
}

func runLoad(url string, requests, concurrency, rate, bodyBytes int, wantPolicy bool, authority string) error {
	transport := &http.Transport{
		MaxIdleConns:        concurrency,
		MaxIdleConnsPerHost: concurrency,
		MaxConnsPerHost:     concurrency,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	result, err := load.Run(
		context.Background(),
		load.Config{
			Requests:    requests,
			Identities:  concurrency,
			Concurrency: concurrency,
			Rate:        rate,
			Duration:    2 * time.Minute,
		},
		func(ctx context.Context, _ int) error {
			method := http.MethodGet
			var body io.Reader
			if bodyBytes > 0 {
				method = http.MethodPost
				body = io.LimitReader(zeroReader{}, int64(bodyBytes))
			}
			req, err := http.NewRequestWithContext(ctx, method, url, body)
			if err != nil {
				return err
			}
			if authority != "" {
				req.Host = authority
			}
			if bodyBytes > 0 {
				req.ContentLength = int64(bodyBytes)
			}
			resp, err := client.Do(req)
			if err != nil {
				return err
			}
			_, readErr := io.Copy(io.Discard, resp.Body)
			closeErr := resp.Body.Close()
			if resp.StatusCode != http.StatusOK || wantPolicy && resp.Header.Get("X-Policy") != "applied" {
				return fmt.Errorf("status=%d policy=%q", resp.StatusCode, resp.Header.Get("X-Policy"))
			}
			return errors.Join(readErr, closeErr)
		},
	)
	if encodeErr := json.NewEncoder(os.Stdout).Encode(result); encodeErr != nil {
		return encodeErr
	}
	if result.Errors > 0 {
		return fmt.Errorf("%d requests failed: %s", result.Errors, result.FirstError)
	}
	return err
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func main() {
	ctrllog.SetLogger(logr.FromSlogHandler(slog.Default().Handler()))
	if err := run(os.Args[1:]); err != nil {
		ctrllog.Log.Error(err, "gateway fixture failed")
		os.Exit(1)
	}
}
