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
	"bytes"
	"encoding/json"
	stdlog "log"
	"log/slog"
	"strings"
	"testing"

	"k8s.io/klog/v2"

	agentiolog "github.com/openkruise/agentio/pkg/log"
)

func TestNewLoggerObservesRuntimeLevelUpdates(t *testing.T) {
	previous := agentiolog.OutputLevel()
	t.Cleanup(func() { agentiolog.SetOutputLevel(previous) })

	var output bytes.Buffer
	logger, err := agentiolog.NewLogger(&output, "info", "text")
	if err != nil {
		t.Fatal(err)
	}
	logger.Debug("hidden")
	if err := agentiolog.SetOutputLevelName("debug"); err != nil {
		t.Fatal(err)
	}
	logger.Debug("visible")
	if strings.Contains(output.String(), "hidden") || !strings.Contains(output.String(), "visible") {
		t.Fatalf("runtime level update output = %q", output.String())
	}
}

func TestNewLoggerAppliesLevelAndJSONFormat(t *testing.T) {
	var output bytes.Buffer
	logger, err := agentiolog.NewLogger(&output, "info", "json")
	if err != nil {
		t.Fatalf("agentiolog.NewLogger() returned error: %v", err)
	}

	logger.Debug("hidden")
	logger.Info("control plane ready", "component", "xds")

	var entry map[string]any
	if err := json.Unmarshal(output.Bytes(), &entry); err != nil {
		t.Fatalf("decode JSON log: %v\n%s", err, output.String())
	}
	if entry["level"] != "INFO" || entry["msg"] != "control plane ready" || entry["component"] != "xds" {
		t.Fatalf("log entry = %#v, want structured INFO entry", entry)
	}
	if strings.Contains(output.String(), "hidden") {
		t.Fatalf("info logger emitted debug entry: %s", output.String())
	}
}

func TestNewLoggerAppliesTextFormat(t *testing.T) {
	var output bytes.Buffer
	logger, err := agentiolog.NewLogger(&output, "debug", "text")
	if err != nil {
		t.Fatalf("agentiolog.NewLogger() returned error: %v", err)
	}

	logger.Debug("watch started", "resource", "pods")

	for _, want := range []string{"level=DEBUG", `msg="watch started"`, "resource=pods"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("text log %q does not contain %q", output.String(), want)
		}
	}
}

func TestNewLoggerRejectsInvalidConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name   string
		level  string
		format string
	}{
		{name: "level", level: "verbose", format: "text"},
		{name: "format", level: "info", format: "console"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := agentiolog.NewLogger(&bytes.Buffer{}, tc.level, tc.format); err == nil {
				t.Fatalf("agentiolog.NewLogger(%q, %q) accepted invalid configuration", tc.level, tc.format)
			}
		})
	}
}

func TestInstallLoggerRoutesStandardLogAndKlog(t *testing.T) {
	var output bytes.Buffer
	logger, err := agentiolog.NewLogger(&output, "info", "json")
	if err != nil {
		t.Fatalf("agentiolog.NewLogger() returned error: %v", err)
	}
	previous := slog.Default()
	installLogger(logger)
	t.Cleanup(func() {
		klog.ClearLogger()
		slog.SetDefault(previous)
	})

	stdlog.Print("standard dependency log")
	klog.InfoS("kubernetes dependency log", "resource", "pods")

	entries := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(entries) != 2 {
		t.Fatalf("routed log entries = %d, want 2:\n%s", len(entries), output.String())
	}
	for index, wantMessage := range []string{"standard dependency log", "kubernetes dependency log"} {
		var entry map[string]any
		if err := json.Unmarshal([]byte(entries[index]), &entry); err != nil {
			t.Fatalf("decode routed log %d: %v\n%s", index, err, entries[index])
		}
		if entry["msg"] != wantMessage {
			t.Fatalf("routed log %d message = %v, want %q", index, entry["msg"], wantMessage)
		}
	}
}

func TestSharedLoggerPreservesComponentWarningLevel(t *testing.T) {
	previous, level := slog.Default(), agentiolog.OutputLevel()
	t.Cleanup(func() {
		slog.SetDefault(previous)
		agentiolog.ConfigureOutputLevel(level)
	})
	var output bytes.Buffer
	logger, err := agentiolog.NewLogger(&output, "info", "json")
	if err != nil {
		t.Fatal(err)
	}
	slog.SetDefault(logger)
	agentiolog.New("xdsclient").Warn("xDS stream disconnected", "retry", "100ms")
	var entry map[string]any
	if err := json.Unmarshal(output.Bytes(), &entry); err != nil {
		t.Fatal(err)
	}
	if entry["level"] != "WARN" || entry["msg"] != "xDS stream disconnected" || entry["component"] != "xdsclient" {
		t.Fatalf("warning was rewrapped: %s", &output)
	}
}
