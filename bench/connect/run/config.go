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
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"slices"
	"strconv"
	"time"

	"github.com/openkruise/agentio/bench/connect/fixture"
)

type config struct {
	ConnectTimeout   time.Duration
	SharedRate       int64
	ProgressInterval time.Duration
	Suite            string
	Repeats          int
	Duration         time.Duration
	Warmup           time.Duration
	Envoy            string
	Load             string
	Module           string
	Output           string
	BasePort         int
	ConcurrencyLimit int
	ResidentBuckets  int
	ResidentMode     string
	DebtBytes        int
	RecoveryWait     time.Duration
	ProbeRequests    int
	Reload           bool
}

type scenario struct {
	Mode      string
	Streams   int
	Direction string
	Repeat    int
}

//nolint:gocyclo // CLI validation enumerates independent input constraints.
func parseConfig(args []string, w io.Writer) (config, error) {
	c := config{}
	f := flag.NewFlagSet("connect-bench run", flag.ContinueOnError)
	f.SetOutput(w)
	f.StringVar(&c.Suite, "suite", "bandwidth", "bandwidth, capacity, overhead, isolation, pilot, buckets, fairness")
	f.Int64Var(
		&c.SharedRate,
		"bytes-per-second",
		32*1048576,
		"shared byte rate (distinct mode divides it across streams)",
	)
	f.DurationVar(
		&c.ConnectTimeout,
		"upstream-connect-timeout",
		time.Second,
		"Envoy TCP upstream connect timeout; increase for SYN loss tests",
	)
	f.DurationVar(&c.ProgressInterval, "progress-interval", 0, "per-stream progress sampling; 0 disables it")
	f.IntVar(&c.Repeats, "repeats", 3, "repetitions per case")
	f.DurationVar(&c.Duration, "duration", 6*time.Second, "measurement window")
	f.DurationVar(&c.Warmup, "warmup", 2*time.Second, "warmup window")
	f.StringVar(&c.Envoy, "envoy", "envoy", "Envoy executable")
	f.StringVar(&c.Load, "load", "connect-load", "Go origin/load executable")
	f.StringVar(&c.Module, "module", "/usr/local/lib/libenvoy_agentio_network_limits.so", "dynamic module path")
	f.StringVar(&c.Output, "output", "", "empty output directory for JSONL, configs and logs")
	f.IntVar(&c.BasePort, "base-port", 17900, "four consecutive loopback ports")
	f.IntVar(&c.ConcurrencyLimit, "concurrency-limit", 0, "optional per-sandbox active-stream cap; 0 omits the filter")
	f.IntVar(&c.ResidentBuckets, "resident-buckets", 10000, "background distinct buckets for the buckets suite")
	f.StringVar(&c.ResidentMode, "resident-mode", "debt", "active or debt background buckets")
	f.IntVar(&c.DebtBytes, "debt-bytes", 1024, "seed bytes at 1 byte/s for debt buckets")
	f.DurationVar(&c.RecoveryWait, "recovery-wait", 0, "quiet observation after releasing background streams")
	f.IntVar(&c.ProbeRequests, "probe-requests", 5000, "CONNECT open/close probes after bucket population")
	f.BoolVar(&c.Reload, "reload", false, "bucket suite: change rate and grouping during throughput measurement")
	if err := f.Parse(args); err != nil {
		return c, err
	}
	if f.NArg() != 0 ||
		c.Output == "" ||
		c.Repeats <= 0 ||
		c.SharedRate <= 0 || c.ConnectTimeout <= 0 ||
		c.ProgressInterval < 0 ||
		c.Duration <= 0 ||
		c.Warmup < 0 ||
		c.BasePort < 1 ||
		c.BasePort > 65532 ||
		c.ConcurrencyLimit < 0 ||
		uint64(c.ConcurrencyLimit) > 1<<32-1 ||
		!slices.Contains(
			[]string{"bandwidth", "capacity", "overhead", "isolation", "pilot", "buckets", "fairness"},
			c.Suite,
		) ||
		c.ResidentBuckets < 0 ||
		!slices.Contains([]string{"active", "debt"}, c.ResidentMode) ||
		c.DebtBytes < 4 ||
		c.DebtBytes > 16384 ||
		c.RecoveryWait < 0 ||
		c.ProbeRequests <= 0 ||
		(c.Reload && c.Suite != "buckets") ||
		((c.Suite == "buckets" || c.Suite == "overhead") && c.ConcurrencyLimit != 0) {
		return c, fmt.Errorf("invalid suite, output, counts, duration, port or concurrency limit")
	}
	if c.Suite == "buckets" && c.Repeats > (65536-c.BasePort)/4 {
		return c, fmt.Errorf("bucket repeats need four distinct ports per case starting at base-port")
	}
	return c, nil
}

func schedule(c config) []scenario {
	var cases []scenario
	if c.Suite == "overhead" {
		for _, mode := range []string{"baseline", "disabled", "concurrency", "high", "distinct-high", "combined"} {
			for _, n := range []int{1, 32, 256, 1024} {
				cases = append(cases, scenario{Mode: mode, Streams: n, Direction: "D"})
			}
			cases = append(cases, scenario{Mode: mode, Streams: 32, Direction: "U"})
		}
	} else if c.Suite == "fairness" {
		for _, direction := range []string{"U", "D"} {
			for _, n := range []int{1, 8, 32} {
				cases = append(cases, scenario{Mode: "shared", Streams: n, Direction: direction})
			}
		}
		cases = append(cases, scenario{Mode: "isolation", Streams: 33, Direction: "D"})
	} else if c.Suite == "buckets" {
		cases = append(cases, scenario{Mode: "high", Streams: 32, Direction: "D"})
	} else if c.Suite == "isolation" {
		for _, n := range []int{1, 33, 257} {
			cases = append(cases, scenario{Mode: "isolation", Streams: n, Direction: "D"})
		}
	} else {
		streams := []int{1, 32, 256}
		modes := []string{"baseline", "bypass", "high", "shared", "distinct"}
		if c.Suite == "pilot" {
			streams = []int{32}
			modes = []string{"baseline", "high", "shared", "distinct"}
		}
		if c.Suite == "capacity" {
			modes = []string{"baseline", "bypass", "high"}
		}
		for _, n := range streams {
			for _, mode := range modes {
				cases = append(cases, scenario{Mode: mode, Streams: n, Direction: "D"})
			}
		}
		if c.Suite != "pilot" {
			for _, mode := range modes {
				if mode != "bypass" {
					cases = append(cases, scenario{Mode: mode, Streams: 32, Direction: "U"})
				}
			}
		}
	}
	var result []scenario
	for repeat := 1; repeat <= c.Repeats; repeat++ {
		for _, s := range cases {
			s.Repeat = repeat
			result = append(result, s)
		}
	}
	rand.New(rand.NewSource(29)).Shuffle(len(result), func(i, j int) { result[i], result[j] = result[j], result[i] })
	return result
}

func object(value any) map[string]any { return value.(map[string]any) }

//nolint:funlen // Keep mode overrides together with their shared identity and module placement.
func envoyConfig(c config, s scenario) ([]byte, error) {
	var b map[string]any
	if err := json.Unmarshal(fixture.Bootstrap, &b); err != nil {
		return nil, err
	}
	object(object(object(b["admin"])["address"])["socket_address"])["port_value"] = c.BasePort + 1
	resources := object(b["static_resources"])
	listener := object(resources["listeners"].([]any)[0])
	object(object(listener["address"])["socket_address"])["port_value"] = c.BasePort + 2
	if c.Suite == "capacity" || c.Suite == "overhead" || c.Suite == "isolation" || c.Suite == "buckets" ||
		c.Suite == "fairness" {
		listener["connection_balance_config"] = map[string]any{"exact_balance": map[string]any{}}
	}
	for _, cluster := range resources["clusters"].([]any) {
		object(cluster)["connect_timeout"] = strconv.FormatFloat(c.ConnectTimeout.Seconds(), 'f', -1, 64) + "s"
		if c.Suite == "buckets" || c.Suite == "overhead" {
			object(cluster)["circuit_breakers"] = map[string]any{"thresholds": []any{map[string]any{
				"max_connections": 200000,
				"max_requests":    200000,
			}}}
		}
		endpoint := object(object(object(cluster)["load_assignment"])["endpoints"].([]any)[0])["lb_endpoints"].([]any)[0]
		object(object(object(object(endpoint)["endpoint"])["address"])["socket_address"])["port_value"] = c.BasePort
	}
	hcm := object(object(object(listener["filter_chains"].([]any)[0])["filters"].([]any)[0])["typed_config"])
	if c.Suite == "buckets" {
		object(hcm["http2_protocol_options"])["max_concurrent_streams"] = 200000
	}
	filters := hcm["http_filters"].([]any)
	module := object(object(object(filters[1])["typed_config"])["value"])
	object(object(object(module["dynamic_module_config"])["module"])["local"])["filename"] = c.Module
	policy := object(object(module["filter_config"])["value"])
	descriptors := policy["descriptors"].([]any)[:1]
	rate := c.SharedRate
	if s.Mode == "high" || s.Mode == "bypass" || s.Mode == "distinct-high" || s.Mode == "combined" {
		rate = 1 << 40
	}
	if s.Mode == "distinct" {
		rate /= int64(s.Streams)
	}
	object(descriptors[0])["bandwidth_limit"] = map[string]any{
		"upload_bytes_per_second":   fmt.Sprint(rate),
		"download_bytes_per_second": fmt.Sprint(rate),
	}
	if s.Mode == "isolation" {
		descriptors = append(descriptors, map[string]any{
			"entries": []any{
				map[string]any{"key": "tenant", "value": "perf"},
				map[string]any{"key": "sandbox", "value": "fast"},
			},
			"bandwidth_limit": map[string]any{"download_bytes_per_second": fmt.Sprint(int64(1) << 40)},
		})
	}
	if s.Mode == "bypass" {
		object(object(descriptors[0])["entries"].([]any)[0])["value"] = "unmatched"
	}
	policy["descriptors"] = descriptors
	if s.Mode == "disabled" {
		policy["enabled"] = false
	}
	policy["max_dynamic_buckets"] = 10000
	if c.Suite == "buckets" {
		object(object(descriptors[0])["entries"].([]any)[0])["value"] = "perf"
		policy["descriptors"] = append(descriptors, map[string]any{
			"entries": []any{
				map[string]any{"key": "tenant", "value": "resident"},
				map[string]any{"key": "sandbox"},
			},
			"bandwidth_limit": map[string]any{"upload_bytes_per_second": "1"},
		})
		policy["max_dynamic_buckets"] = c.ResidentBuckets + 1024
	}
	if s.Mode == "baseline" || s.Mode == "concurrency" {
		filters = []any{filters[0], filters[2]}
	}
	limit := c.ConcurrencyLimit
	if c.Suite == "overhead" && (s.Mode == "disabled" || s.Mode == "concurrency" || s.Mode == "combined") {
		limit = 100000
	}
	if limit > 0 {
		// Clone the module envelope, keeping admission state independent from shaping.
		data, err := json.Marshal(module)
		if err != nil {
			return nil, err
		}
		var admission map[string]any
		if err := json.Unmarshal(data, &admission); err != nil {
			return nil, err
		}
		admission["filter_name"] = "envoy_agentio_connect_concurrency"
		object(admission["filter_config"])["value"] = map[string]any{
			"enabled":             s.Mode != "disabled",
			"budget_name":         "bench-concurrency",
			"rate_limits":         policy["rate_limits"],
			"max_dynamic_buckets": 10000,
			"descriptors": []any{
				map[string]any{
					"entries":                []any{map[string]any{"key": "tenant"}, map[string]any{"key": "sandbox"}},
					"max_concurrent_streams": limit,
				},
			},
		}
		filter := map[string]any{
			"name": "agentio.connect_concurrency",
			"typed_config": map[string]any{
				"@type":    "type.googleapis.com/udpa.type.v1.TypedStruct",
				"type_url": "type.googleapis.com/envoy.extensions.filters.http.dynamic_modules.v3.DynamicModuleFilter",
				"value":    admission,
			}}
		filters = append([]any{filters[0], filter}, filters[1:]...)
	}
	hcm["http_filters"] = filters
	return json.MarshalIndent(b, "", "  ")
}
