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
	"io"
	"testing"
)

func TestConfig(t *testing.T) {
	base := []string{
		"--kubeconfig",
		"/tmp/test",
		"--output",
		"/tmp/results",
		"--bench-image",
		"bench:test",
		"--variant",
		"candidate=porter:test",
	}
	c, err := parseConfig(
		append(
			base,
			"--variant-env",
			"candidate:AGENTIO_LOG_LEVEL=info,discovery=debug",
			"--variant-command",
			"candidate=/porter",
			"--suites",
			"mixed,lifecycle,controlplane",
			"--control-plane-image", "cp:baseline",
			"--keep-namespace",
		),
		io.Discard,
	)
	if err != nil {
		t.Fatal(err)
	}
	if c.Workloads != 100000 || c.Variants[0].Command != "/porter" ||
		c.Variants[0].Env["AGENTIO_LOG_LEVEL"] != "info,discovery=debug" ||
		len(c.Suites) != 3 || c.ControlPlaneImage != "cp:baseline" || !c.KeepNamespace {
		t.Fatalf("unexpected config: %+v", c)
	}
	for name, extra := range map[string][]string{
		"below minimum":      {"--workloads", "49999"},
		"duplicate variant":  {"--variant", "candidate=other:test"},
		"unknown env target": {"--variant-env", "other:KEY=value"},
		"duplicate suite":    {"--suites", "mixed,mixed"},
		"single CP failover": {"--suites", "failover", "--control-planes", "1"},
		"unpartitioned rate": {"--hot-rate", "10001"},
	} {
		t.Run(name, func(t *testing.T) {
			args := append(append([]string{}, base...), extra...)
			if _, err := parseConfig(args, io.Discard); err == nil {
				t.Fatal("expected invalid configuration")
			}
		})
	}
}
