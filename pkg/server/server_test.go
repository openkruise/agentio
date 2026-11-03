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

package server

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"istio.io/istio/pkg/test"

	"github.com/openkruise/agentio/pkg/features"
	agentlog "github.com/openkruise/agentio/pkg/log"
	"github.com/openkruise/agentio/pkg/server/debug"
)

func TestStartupLogUsesEffectiveSettingsWithoutDumpingOptions(t *testing.T) {
	var output bytes.Buffer
	previousLogger := slog.Default()
	previousLevel := agentlog.OutputLevel()
	slog.SetDefault(slog.New(slog.NewTextHandler(&output, nil)))
	agentlog.ConfigureOutputLevel(slog.LevelInfo)
	t.Cleanup(func() {
		slog.SetDefault(previousLogger)
		agentlog.ConfigureOutputLevel(previousLevel)
	})
	test.SetForTest(t, &features.KubernetesAPIQPS, 123.0)
	test.SetForTest(t, &features.KubernetesAPIBurst, 246)
	test.SetForTest(t, &features.RequestRateLimit, 77.0)
	test.SetForTest(t, &features.PushDebounceAfter, 321*time.Millisecond)
	options := DefaultOptions()
	options.Kubeconfig = "private-kubeconfig-path-must-not-be-logged"
	logStartup(options)
	for _, field := range []string{"kubernetes_api_qps=123", "kubernetes_api_burst=246",
		"xds_request_rate_limit=77", "push_debounce=321ms", "revision=", "go_memory_limit_bytes="} {
		if !strings.Contains(output.String(), field) {
			t.Fatalf("startup summary lacks %q: %s", field, output.String())
		}
	}
	if strings.Contains(output.String(), options.Kubeconfig) {
		t.Fatalf("startup summary dumped private process options: %s", output.String())
	}
}

func TestWithRunContextCancelsChildWhenRunReturns(t *testing.T) {
	want := errors.New("initialization failed")
	var child context.Context
	err := withRunContext(context.Background(), func(ctx context.Context) error {
		child = ctx
		return want
	})
	if !errors.Is(err, want) {
		t.Fatalf("withRunContext() error = %v, want %v", err, want)
	}
	select {
	case <-child.Done():
	case <-time.After(time.Second):
		t.Fatal("child context remained active after run returned")
	}
}

func TestRunRejectsInvalidOptions(t *testing.T) {
	options := DefaultOptions()
	options.MonitoringAddress = ""

	if err := Run(context.Background(), options); err == nil {
		t.Fatal("Run() accepted invalid options")
	}
}

func TestRunStopsWhenContextIsCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, DefaultOptions())
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run() did not stop after context cancellation")
	}
}

func TestShutdownHTTPBoundsActiveRequests(t *testing.T) {
	for _, graceful := range []bool{true, false} {
		name := "forced"
		if graceful {
			name = "graceful"
		}
		t.Run(name, func(t *testing.T) {
			entered := make(chan struct{})
			release := make(chan struct{}, 1)
			handlerDone := make(chan bool, 1)
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				close(entered)
				select {
				case <-release:
					response.WriteHeader(http.StatusNoContent)
				case <-request.Context().Done():
				}
				handlerDone <- request.Context().Err() != nil
			}))
			defer server.Close()
			defer close(release)
			shutdownStarted := make(chan struct{})
			server.Config.RegisterOnShutdown(func() { close(shutdownStarted) })
			clientDone := make(chan error, 1)
			go func() {
				response, err := server.Client().Get(server.URL)
				if err == nil {
					err = response.Body.Close()
					if response.StatusCode != http.StatusNoContent {
						err = errors.New("unexpected response status")
					}
				}
				clientDone <- err
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("HTTP request did not enter handler")
			}
			shutdownDone := make(chan struct{})
			go func() {
				shutdownHTTP(server.Config, 100*time.Millisecond)
				close(shutdownDone)
			}()
			if graceful {
				select {
				case <-shutdownStarted:
					release <- struct{}{}
				case <-time.After(time.Second):
					t.Fatal("HTTP shutdown did not start")
				}
			}
			select {
			case <-shutdownDone:
			case <-time.After(time.Second):
				t.Fatal("HTTP shutdown exceeded its grace period")
			}
			select {
			case canceled := <-handlerDone:
				if canceled == graceful {
					t.Fatalf("request context canceled = %v, want %v", canceled, !graceful)
				}
			case <-time.After(time.Second):
				t.Fatal("HTTP handler did not finish after shutdown")
			}
			select {
			case err := <-clientDone:
				if (err == nil) != graceful {
					t.Fatalf("HTTP client error = %v, graceful = %v", err, graceful)
				}
			case <-time.After(time.Second):
				t.Fatal("HTTP client did not finish after shutdown")
			}
		})
	}
}

func TestGRPCServerKeepaliveUsesConfiguredMaxConnectionAge(t *testing.T) {
	test.SetForTest(t, &features.MaxServerConnectionAge, 47*time.Minute)
	parameters := grpcServerKeepaliveParameters()
	if parameters.MaxConnectionAge != 47*time.Minute {
		t.Fatalf("MaxConnectionAge = %v, want 47m", parameters.MaxConnectionAge)
	}
}

func TestNewMonitoringHandlerRegistersConfigDebugHandlerWhenProvided(t *testing.T) {
	debugHandler := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("X-Debug-Handler", "reached")
		response.WriteHeader(http.StatusNoContent)
	})
	handler := newMonitoringHandler(func() bool { return true }, debugHandler)

	for _, path := range []string{debug.Path, debug.LoggingPath, debug.LoggingPath + "/krt"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNoContent || response.Header().Get("X-Debug-Handler") != "reached" {
			t.Fatalf("%s debug response = %d headers=%v, want sentinel handler", path, response.Code, response.Header())
		}
	}
	for _, path := range []string{"/healthz", "/ready", "/metrics"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusOK {
			t.Fatalf("%s response status = %d, want 200", path, response.Code)
		}
	}
}

func TestNewMonitoringHandlerOmitsConfigDebugHandlerWhenDisabled(t *testing.T) {
	handler := newMonitoringHandler(func() bool { return false }, nil)

	debugResponse := httptest.NewRecorder()
	handler.ServeHTTP(debugResponse, httptest.NewRequest(http.MethodGet, debug.Path, nil))
	if debugResponse.Code != http.StatusNotFound {
		t.Fatalf("disabled debug response status = %d, want 404", debugResponse.Code)
	}
	loggingResponse := httptest.NewRecorder()
	handler.ServeHTTP(loggingResponse, httptest.NewRequest(http.MethodGet, debug.LoggingPath+"/krt", nil))
	if loggingResponse.Code != http.StatusNotFound {
		t.Fatalf("disabled logging debug response status = %d, want 404", loggingResponse.Code)
	}
	healthResponse := httptest.NewRecorder()
	handler.ServeHTTP(healthResponse, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if healthResponse.Code != http.StatusOK {
		t.Fatalf("health response status = %d, want 200", healthResponse.Code)
	}
	readyResponse := httptest.NewRecorder()
	handler.ServeHTTP(readyResponse, httptest.NewRequest(http.MethodGet, "/ready", nil))
	if readyResponse.Code != http.StatusServiceUnavailable {
		t.Fatalf("ready response status = %d, want 503", readyResponse.Code)
	}
}
