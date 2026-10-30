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
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestSuitesPreserveCasesAndRepeats(t *testing.T) {
	for suite, want := range map[string]int{"bandwidth": 57, "capacity": 33, "overhead": 90, "isolation": 9, "pilot": 12, "buckets": 3, "fairness": 21} {
		c := config{Suite: suite, Repeats: 3}
		cases := schedule(c)
		if len(cases) != want || !reflect.DeepEqual(cases, schedule(c)) {
			t.Fatalf("%s: unexpected schedule", suite)
		}
		seen := map[scenario]bool{}
		for _, s := range cases {
			if seen[s] {
				t.Fatalf("duplicate %+v", s)
			}
			seen[s] = true
		}
	}
}

func TestOverheadModes(t *testing.T) {
	for _, mode := range []string{"baseline", "disabled", "concurrency", "high", "distinct-high", "combined"} {
		data, err := envoyConfig(
			config{Suite: "overhead", BasePort: 19000, ConnectTimeout: time.Second},
			scenario{Mode: mode, Streams: 1024},
		)
		if err != nil {
			t.Fatal(err)
		}
		var b map[string]any
		if err := json.Unmarshal(data, &b); err != nil {
			t.Fatal(err)
		}
		l := object(object(b["static_resources"])["listeners"].([]any)[0])
		hcm := object(object(object(l["filter_chains"].([]any)[0])["filters"].([]any)[0])["typed_config"])
		seen := map[string]bool{}
		for _, f := range hcm["http_filters"].([]any) {
			filter := object(f)
			name := filter["name"].(string)
			if name != "agentio.bandwidth" && name != "agentio.connect_concurrency" {
				continue
			}
			seen[name] = true
			p := object(object(object(object(filter["typed_config"])["value"])["filter_config"])["value"])
			if mode == "disabled" && p["enabled"] != false {
				t.Fatal("resident filter was not disabled")
			}
			if name == "agentio.bandwidth" && mode != "disabled" {
				d := object(p["descriptors"].([]any)[0])
				if object(d["bandwidth_limit"])["download_bytes_per_second"] != "1099511627776" {
					t.Fatal("overhead measurement is bandwidth constrained")
				}
			}
		}
		if seen["agentio.bandwidth"] != (mode != "baseline" && mode != "concurrency") ||
			seen["agentio.connect_concurrency"] != (mode == "disabled" || mode == "concurrency" || mode == "combined") {
			t.Fatalf("%s: unexpected filters %v", mode, seen)
		}
	}
}

func TestBucketDiscoveryKeepsPolicyAndUsesFileSource(t *testing.T) {
	data, err := envoyConfig(
		config{Suite: "buckets", BasePort: 19000, ConnectTimeout: time.Second},
		scenario{Mode: "high", Streams: 32},
	)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ecds.json")
	data, err = discoverBandwidth(data, path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte("config_discovery")) || bytes.Contains(data, []byte("budget_name")) {
		t.Fatal("policy is not supplied through ECDS")
	}
	resource, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(resource, []byte("bandwidth_limit")) ||
		!bytes.Contains(resource, []byte("TypedExtensionConfig")) {
		t.Fatal("ECDS resource lost the bandwidth policy")
	}
}

func TestConfigVariantsAndIndependentConcurrency(t *testing.T) {
	c := config{
		ConnectTimeout: time.Second,
		SharedRate:     32 * 1048576,
		Suite:          "capacity",
		BasePort:       19000,
		Module:         "/modules/test.so",
	}
	for _, mode := range []string{"baseline", "bypass", "high", "shared", "distinct", "isolation"} {
		for _, limit := range []int{0, 1024} {
			c.ConcurrencyLimit = limit
			data, err := envoyConfig(c, scenario{Mode: mode, Streams: 32})
			if err != nil {
				t.Fatal(err)
			}
			var b map[string]any
			if err := json.Unmarshal(data, &b); err != nil {
				t.Fatal(err)
			}
			listener := object(object(b["static_resources"])["listeners"].([]any)[0])
			if listener["connection_balance_config"] == nil {
				t.Fatal("capacity suite lacks exact balance")
			}
			hcm := object(object(object(listener["filter_chains"].([]any)[0])["filters"].([]any)[0])["typed_config"])
			filters := hcm["http_filters"].([]any)
			bandwidth, concurrency := false, false
			for _, f := range filters {
				filter := object(f)
				switch filter["name"] {
				case "agentio.bandwidth":
					bandwidth = true
					module := object(object(filter["typed_config"])["value"])
					if object(object(object(module["dynamic_module_config"])["module"])["local"])["filename"] != c.Module {
						t.Fatal("wrong module")
					}
					descriptors := object(object(module["filter_config"])["value"])["descriptors"].([]any)
					rate := object(object(descriptors[0])["bandwidth_limit"])["download_bytes_per_second"]
					if mode == "distinct" && rate != "1048576" {
						t.Fatalf("distinct rate=%v", rate)
					}
					if mode == "isolation" && len(descriptors) != 2 {
						t.Fatal("missing fast sandbox")
					}
				case "agentio.connect_concurrency":
					concurrency = true
				}
			}
			if bandwidth != (mode != "baseline") || concurrency != (limit > 0) {
				t.Fatalf("mode=%s cap=%d filters=%v", mode, limit, filters)
			}
		}
	}
}

func TestInputsAndCPUParsing(t *testing.T) {
	if _, err := parseConfig(
		[]string{"-output=x", "-suite=buckets", "-base-port=65528", "-repeats=3"},
		io.Discard,
	); err == nil {
		t.Fatal("bucket repeats exceed the port range")
	}
	for _, args := range [][]string{{}, {"-output=x", "-suite=unknown"}, {"-output=x", "-repeats=0"}, {"-output=x", "-base-port=65534"}, {"-output=x", "-concurrency-limit=-1"}} {
		if _, err := parseConfig(args, io.Discard); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	cpus, err := parseCPUs("0-2,7,9-10")
	if err != nil || !reflect.DeepEqual(cpus, []int{0, 1, 2, 7, 9, 10}) {
		t.Fatalf("%v %v", cpus, err)
	}
	if _, err := parseCPUs("3-1"); err == nil {
		t.Fatal("reversed range accepted")
	}
}

func TestBucketFixtureSeparatesResidentDebtAndProbeTraffic(t *testing.T) {
	data, err := envoyConfig(
		config{ConnectTimeout: time.Second, Suite: "buckets", BasePort: 19000, ResidentBuckets: 100000},
		scenario{Mode: "high"},
	)
	if err != nil {
		t.Fatal(err)
	}
	var b map[string]any
	if err := json.Unmarshal(data, &b); err != nil {
		t.Fatal(err)
	}
	resources := object(b["static_resources"])
	listener := object(resources["listeners"].([]any)[0])
	hcm := object(object(object(listener["filter_chains"].([]any)[0])["filters"].([]any)[0])["typed_config"])
	if object(hcm["http2_protocol_options"])["max_concurrent_streams"] != float64(200000) {
		t.Fatal("fixture stream ceiling")
	}
	module := object(object(object(hcm["http_filters"].([]any)[1])["typed_config"])["value"])
	policy := object(object(module["filter_config"])["value"])
	if policy["max_dynamic_buckets"] != float64(101024) {
		t.Fatal("insufficient probe headroom")
	}
	descriptors := policy["descriptors"].([]any)
	for i, tenant := range []string{"perf", "resident"} {
		if object(object(descriptors[i])["entries"].([]any)[0])["value"] != tenant {
			t.Fatal("probe and resident budgets overlap")
		}
	}
	if object(object(descriptors[1])["bandwidth_limit"])["upload_bytes_per_second"] != "1" {
		t.Fatal("seed byte/time conversion changed")
	}
}

func TestAnalyzePreservesHistoricalJSONLAndRejectsErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rows.jsonl")
	data := "{\"event\":\"environment\"}\n"
	data += "{\"event\":\"result\",\"mode\":\"high\",\"streams\":1,\"direction\":\"D\",\"errors\":0,\"mib_per_s\":10}\n"
	data += strings.ReplaceAll(strings.Split(data, "\n")[1], "\":10", "\":20") + "\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := analyze(path, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "15.00 [10.00, 20.00]") {
		t.Fatal(out.String())
	}
	if err := os.WriteFile(path, []byte(strings.ReplaceAll(data, "\"errors\":0", "\"errors\":1")), 0600); err != nil {
		t.Fatal(err)
	}
	if err := analyze(path, io.Discard); err == nil {
		t.Fatal("failed measurements accepted")
	}
}
