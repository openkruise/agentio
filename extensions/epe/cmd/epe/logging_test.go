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

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap/zapcore"
	"k8s.io/klog/v2"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlzap "sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/openkruise/agentio/extensions/epe/pkg/admin"
	auditlog "github.com/openkruise/agentio/extensions/epe/pkg/audit/log"
	"github.com/openkruise/agentio/extensions/epe/pkg/logging"
	agentlog "github.com/openkruise/agentio/pkg/log"
)

// TestInitLoggingBridgesBothStacksOntoZap covers the seam between the two
// logging stacks in this process. Shared agentio packages linked into the EPE
// binary log through pkg/log, which resolves slog.Default() per record, while
// EPE itself logs through controller-runtime's zap. Without the bridge the
// pkg/log records reach Go's built-in handler and print as text inside the JSON
// stream, ignoring the level flags.
//
// Everything is asserted from a single initLogging call because
// ctrllog.SetLogger is one-shot: controller-runtime fulfils the root
// delegating sink once and clears its promise, so a second SetLogger is a
// silent no-op. Subtests share one buffer and reset it between cases.
func TestInitLoggingBridgesBothStacksOntoZap(t *testing.T) {
	previousSlog := slog.Default()
	previousFlags := flag.CommandLine
	t.Cleanup(func() {
		klog.ClearLogger()
		slog.SetDefault(previousSlog)
		flag.CommandLine = previousFlags
	})
	// The controller-runtime root logger cannot be restored for the same
	// one-shot reason, so it is left pointing at this buffer. Nothing else in
	// this package logs after the test binary finishes.

	var out bytes.Buffer
	opts := ctrlzap.Options{Development: false, DestWriter: &out}
	flag.CommandLine = flag.NewFlagSet(t.Name(), flag.ContinueOnError)
	opts.BindFlags(flag.CommandLine)
	// Start with the binary defaults, including its actual -v default. Runtime
	// changes must still admit debug and trace through the same core.
	if err := flag.CommandLine.Parse(nil); err != nil {
		t.Fatal(err)
	}
	level := initLogging(&opts)

	records := func(t *testing.T) []map[string]any {
		t.Helper()

		var parsed []map[string]any
		for _, line := range strings.Split(out.String(), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var record map[string]any
			if err := json.Unmarshal([]byte(line), &record); err != nil {
				t.Fatalf("log line is not JSON, so it bypassed the zap encoder: %q (%v)", line, err)
			}
			parsed = append(parsed, record)
		}
		return parsed
	}

	t.Run("defaults preserve info and suppress debug across stacks", func(t *testing.T) {
		out.Reset()
		if level.Level() != zapcore.InfoLevel {
			t.Fatalf("default level = %v, want info", level.Level())
		}
		ctrllog.Log.V(logging.DEFAULT).Info("EPE default")
		ctrllog.Log.V(logging.DEBUG).Info("hidden EPE debug")
		ctrllog.Log.V(logging.TRACE).Info("hidden EPE trace")
		slog.Info("slog default")
		slog.Debug("hidden slog debug")
		klog.InfoS("klog default")
		klog.V(1).InfoS("hidden klog debug")
		got := records(t)
		if len(got) != 3 {
			t.Fatalf("default records = %v, want only three info records", got)
		}
		for i, message := range []string{"EPE default", "slog default", "klog default"} {
			if got[i]["msg"] != message || got[i]["level"] != "info" {
				t.Errorf("default record = %v, want %q at info", got[i], message)
			}
		}
	})

	t.Run("access records are not sampled", func(t *testing.T) {
		out.Reset()
		auditLogger := auditlog.NewBufferedLogger(ctrllog.Log.WithName("audit"), 4096)
		for i := range 200 {
			auditLogger.Submit(auditlog.Entry{RequestID: fmt.Sprintf("request-%d", i), Outcome: "passthrough"})
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel() // Drain the queued records synchronously.
		if err := auditLogger.Start(ctx); err != nil {
			t.Fatal(err)
		}
		got := records(t)
		if len(got) != 200 {
			t.Fatalf("emitted %d access records, want 200", len(got))
		}
		for i, record := range got {
			if record["requestID"] != fmt.Sprintf("request-%d", i) {
				t.Errorf("unexpected access record: %v", record)
			}
		}
	})

	t.Run("shared package logs reach the zap encoder", func(t *testing.T) {
		out.Reset()
		agentlog.New("krt").Info("collection synced", "collection", "workloads")

		got := records(t)
		if len(got) != 1 {
			t.Fatalf("expected exactly one record, got %d: %v", len(got), got)
		}
		record := got[0]
		for key, want := range map[string]any{
			"msg":        "collection synced",
			"component":  "krt",
			"collection": "workloads",
			"level":      "info",
		} {
			if record[key] != want {
				t.Errorf("%s = %v, want %v", key, record[key], want)
			}
		}
		// pkg/log records the caller PC and zapslog turns it into a zap caller,
		// so the line still names its origin rather than the bridge.
		if caller, _ := record["caller"].(string); !strings.Contains(caller, "logging_test.go") {
			t.Errorf("caller = %v, want it to name logging_test.go", record["caller"])
		}
	})

	t.Run("controller-runtime logs stay on the same stream", func(t *testing.T) {
		out.Reset()
		ctrllog.Log.WithName("ext-proc").Info("handling request headers", "requestID", "abc")

		got := records(t)
		if len(got) != 1 {
			t.Fatalf("expected exactly one record, got %d: %v", len(got), got)
		}
		if got[0]["logger"] != "ext-proc" {
			t.Errorf("logger = %v, want %q", got[0]["logger"], "ext-proc")
		}
		if got[0]["requestID"] != "abc" {
			t.Errorf("requestID = %v, want %q", got[0]["requestID"], "abc")
		}
	})

	t.Run("debug stays gated in this process", func(t *testing.T) {
		out.Reset()
		logger := agentlog.New("krt")
		if !logger.Enabled(t.Context(), slog.LevelInfo) {
			t.Error("info records must reach the handler")
		}
		// pkg/log filters by its own scope level before any handler sees the
		// record, and nothing here raises it, so debug stays off however
		// verbose -v is. That is deliberate: pkg/krt emits debug lines per
		// event on the recompute path.
		if logger.Enabled(t.Context(), slog.LevelDebug) {
			t.Error("debug records must stay gated in the EPE process")
		}

		logger.Debug("handled event", "resource", "key")
		logger.Info("watch started")

		got := records(t)
		if len(got) != 1 {
			t.Fatalf("expected only the info record, got %d: %v", len(got), got)
		}
		if got[0]["msg"] != "watch started" {
			t.Errorf("msg = %v, want %q", got[0]["msg"], "watch started")
		}
	})

	t.Run("admin updates existing loggers across the bridges", func(t *testing.T) {
		server := httptest.NewServer(admin.NewHandler(admin.Options{EnableDebug: true, LogLevel: &level}))
		defer server.Close()
		existing := ctrllog.Log.WithName("ext-proc").WithValues("requestID", "already-created")
		existingSlog := slog.Default().With("source", "already-created")
		shared := agentlog.New("krt")
		update := func(name string) {
			t.Helper()
			request, err := http.NewRequest(http.MethodPut, server.URL+"/debug/logging/default",
				strings.NewReader(`{"output_level":"`+name+`"}`))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", "application/json")
			response, err := server.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := response.Body.Close(); err != nil {
					t.Error(err)
				}
			}()
			if response.StatusCode != http.StatusAccepted {
				t.Fatalf("PUT output_level %q: status=%d, want 202", name, response.StatusCode)
			}
		}

		out.Reset()
		existing.V(logging.DEBUG).Info("hidden before update")
		update("debug")
		existing.V(logging.DEBUG).Info("debug enabled")
		existing.V(logging.TRACE).Info("trace still hidden")
		got := records(t)
		if len(got) != 1 || got[0]["msg"] != "debug enabled" || got[0]["requestID"] != "already-created" ||
			got[0]["level"] != "debug" {
			t.Fatalf("debug update records = %v", got)
		}

		out.Reset()
		update("2")
		existing.V(logging.TRACE).Info("trace enabled")
		if got := records(t); len(got) != 1 || got[0]["msg"] != "trace enabled" {
			t.Fatalf("trace update records = %v", got)
		}

		out.Reset()
		update("error")
		existing.Info("hidden logr")
		existingSlog.Info("hidden slog")
		klog.InfoS("hidden klog")
		shared.Info("hidden shared package")
		existing.Error(io.EOF, "visible error")
		got = records(t)
		if len(got) != 1 || got[0]["msg"] != "visible error" {
			t.Fatalf("error update records = %v", got)
		}
		if _, found := got[0]["stacktrace"]; found {
			t.Fatal("changing level enabled error stacktraces")
		}

		out.Reset()
		update("info")
		existing.V(logging.DEFAULT).Info("restored EPE default")
		existing.V(logging.DEBUG).Info("debug hidden after info reset")
		existing.Info("restored logr")
		existingSlog.Info("restored slog")
		existingSlog.Debug("hidden slog debug after info reset")
		klog.InfoS("restored klog")
		klog.V(1).InfoS("hidden klog debug after info reset")
		shared.Info("restored shared package")
		got = records(t)
		if len(got) != 5 {
			t.Fatalf("restored logger records = %v", got)
		}
		for _, record := range got {
			if record["level"] != "info" {
				t.Errorf("restored record = %v, want info", record)
			}
		}

		out.Reset()
		update("none")
		existing.Error(io.EOF, "hidden logr error")
		existingSlog.Error("hidden slog error")
		klog.ErrorS(io.EOF, "hidden klog error")
		shared.Error("hidden shared error")
		if got := records(t); len(got) != 0 {
			t.Fatalf("none should suppress every record: %v", got)
		}

		out.Reset()
		update("1")
		existingSlog.Debug("slog debug enabled")
		existing.V(logging.DEBUG).Info("EPE debug enabled")
		existing.V(logging.TRACE).Info("EPE trace still hidden")
		if got := records(
			t,
		); len(got) != 2 || got[0]["msg"] != "slog debug enabled" ||
			got[1]["msg"] != "EPE debug enabled" {
			t.Fatalf("verbosity 1 records = %v", got)
		}
	})
}

func TestNewLogLevelHonorsStartupFlags(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want zapcore.Level
	}{
		{name: "default", want: zapcore.InfoLevel},
		{name: "debug verbosity", args: []string{"-v=1"}, want: zapcore.DebugLevel},
		{name: "trace verbosity", args: []string{"-v=2"}, want: -2},
		{name: "info overrides verbosity", args: []string{"-v=5", "--zap-log-level=info"}, want: zapcore.InfoLevel},
		{name: "numeric zap level", args: []string{"--zap-log-level=3", "-v=5"}, want: -3},
		{name: "named zap level", args: []string{"--zap-log-level=debug"}, want: zapcore.DebugLevel},
		{name: "development preserves verbosity", args: []string{"--zap-devel"}, want: zapcore.InfoLevel},
	} {
		t.Run(tc.name, func(t *testing.T) {
			previousFlags, previousVerbosity := flag.CommandLine, *logVerbosity
			t.Cleanup(func() {
				flag.CommandLine = previousFlags
				*logVerbosity = previousVerbosity
			})
			flag.CommandLine = flag.NewFlagSet(t.Name(), flag.ContinueOnError)
			flag.IntVar(logVerbosity, "v", 0, "log verbosity")
			opts := ctrlzap.Options{}
			opts.BindFlags(flag.CommandLine)
			if err := flag.CommandLine.Parse(tc.args); err != nil {
				t.Fatal(err)
			}
			if got := newLogLevel(&opts).Level(); got != tc.want {
				t.Fatalf("startup level = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestInitLoggingPreservesEncoderFlags(t *testing.T) {
	previousSlog, previousFlags := slog.Default(), flag.CommandLine
	t.Cleanup(func() {
		klog.ClearLogger()
		slog.SetDefault(previousSlog)
		flag.CommandLine = previousFlags
	})
	for _, tc := range []struct {
		name string
		args []string
		json bool
	}{
		{name: "production", json: true},
		{name: "explicit JSON", args: []string{"--zap-encoder=json", "--zap-time-encoding=epoch", "--zap-log-level=info"}, json: true},
		{name: "console", args: []string{"--zap-encoder=console"}},
		{name: "development", args: []string{"--zap-devel"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			opts := ctrlzap.Options{DestWriter: &out}
			flag.CommandLine = flag.NewFlagSet(t.Name(), flag.ContinueOnError)
			opts.BindFlags(flag.CommandLine)
			if err := flag.CommandLine.Parse(tc.args); err != nil {
				t.Fatal(err)
			}
			initLogging(&opts)
			slog.Info("encoder check")
			slog.Debug("hidden debug")
			if strings.Contains(out.String(), "hidden debug") {
				t.Fatal("encoder flags changed default verbosity")
			}
			if !tc.json {
				if !strings.Contains(out.String(), "INFO") || !strings.Contains(out.String(), "encoder check") {
					t.Fatalf("console output = %q", out.String())
				}
				return
			}
			var record map[string]any
			if err := json.Unmarshal(out.Bytes(), &record); err != nil {
				t.Fatal(err)
			}
			if record["msg"] != "encoder check" || record["level"] != "info" {
				t.Fatalf("JSON record = %v", record)
			}
			if tc.name == "explicit JSON" {
				if _, ok := record["ts"].(float64); !ok {
					t.Fatalf("epoch timestamp = %v", record["ts"])
				}
			} else if _, ok := record["ts"].(string); !ok {
				t.Fatalf("default timestamp = %v", record["ts"])
			}
		})
	}
}
