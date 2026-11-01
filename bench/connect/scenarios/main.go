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
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/openkruise/agentio/bench/connect/fixture"
	"github.com/openkruise/agentio/bench/scenario"
)

func main() {
	image := flag.String("image", "", "candidate gateway image")
	module := flag.String("module", "", "optional candidate .so overriding the image module")
	binary := flag.String("test-binary", "", "prebuilt Linux Go test binary (otherwise built automatically)")
	profile := flag.String("profile", "smoke", "smoke, scale, or soak")
	only := flag.String("case", "", "run only this case from the profile")
	output := flag.String("output", "", "new artifact directory outside the repository")
	flag.Parse()
	err := run(*image, *module, *binary, *profile, *only, *output)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(image, module, binary, profile, only, output string) error {
	if image == "" || output == "" {
		return fmt.Errorf("-image and -output are required")
	}
	cases := fixture.Scenarios(profile)
	if len(cases) == 0 {
		return fmt.Errorf("unknown profile %q", profile)
	}
	if binary == "" {
		// Preserve the executable referenced by suite.json for exact replay.
		dir, err := filepath.Abs(output + "-inputs")
		if err != nil {
			return err
		}
		if err = os.Mkdir(dir, 0755); err != nil {
			return err
		}
		binary = filepath.Join(dir, "network-limits.test")
		arch, err := exec.Command("docker", "image", "inspect", "--format", "{{.Architecture}}", image).Output()
		if err != nil {
			return err
		}
		cmd := exec.Command("go", "test", "-c", "-o", binary, "./extensions/envoy/network-limits/tests")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+strings.TrimSpace(string(arch)))
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err = cmd.Run(); err != nil {
			return err
		}
	}
	binary, err := filepath.Abs(binary)
	if err != nil {
		return err
	}
	suite := scenario.Suite{Name: "network-limits-" + profile}
	for _, c := range cases {
		if only != "" && c.Name != only {
			continue
		}
		raw, err := json.Marshal(c)
		if err != nil {
			return err
		}
		timeout := time.Duration(c.Seconds)*time.Second + 3*time.Minute
		item := scenario.Case{
			SuccessMarker: "SCENARIO_COMPLETED",
			Name:          c.Name,
			Image:         image,
			Timeout:       (timeout + 30*time.Second).String(),
			Memory:        "12g",
			Command: []string{
				"/tests/network-limits.test",
				"-test.v",
				"-test.run=^TestEnvoyNetworkScenario$",
				"-test.timeout=" + timeout.String(),
			},
			Mounts: []scenario.Mount{{Source: binary, Target: "/tests/network-limits.test"}},
			Env: map[string]string{
				"AGENTIO_TEST_ENVOY_BINARY": "/usr/local/bin/envoy",
				"AGENTIO_TEST_ARTIFACTS":    "{artifacts}",
				"AGENTIO_NETWORK_SCENARIO":  string(raw),
			},
		}
		if module != "" {
			absolute, err := filepath.Abs(module)
			if err != nil {
				return err
			}
			item.Mounts = append(item.Mounts, scenario.Mount{Source: absolute, Target: "/tests/network-limits.so"})
			item.Env["AGENTIO_TEST_NETWORK_LIMITS_MODULE"] = "/tests/network-limits.so"
		}
		suite.Cases = append(suite.Cases, item)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	_, err = scenario.Run(ctx, suite, output, os.Stdout)
	return err
}
