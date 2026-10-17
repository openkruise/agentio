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

import "testing"

func TestCPDeltaMarksLostReplica(t *testing.T) {
	before := cpSnapshot{
		Time: 1,
		ADS: map[string]cpSample{
			"0": {
				CPU:     10,
				Alloc:   1048576,
				Mallocs: 10,
				GC:      1,
				Pause:   1000000,
				Cgroup:  map[string]uint64{"throttled_usec": 100},
			},
			"1": {CPU: 20},
		},
	}
	after := cpSnapshot{
		Time: 3,
		ADS: map[string]cpSample{
			"0": {
				CPU:     13,
				Alloc:   3145728,
				Mallocs: 15,
				GC:      3,
				Pause:   4000000,
				Cgroup:  map[string]uint64{"throttled_usec": 200},
			},
		},
	}
	got := cpDelta(before, after)
	if got["cpu_seconds"] != float64(3) || got["allocated_mib"] != float64(2) || got["gc_pause_ms"] != float64(3) {
		t.Fatalf("wrong counters: %+v", got)
	}
	missing := got["missing_control_planes"].([]string)
	if len(missing) != 1 || missing[0] != "1" {
		t.Fatalf("lost replica must mark the interval incomplete: %+v", got)
	}
}
