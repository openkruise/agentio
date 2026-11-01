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
	"os/signal"
	"syscall"

	"github.com/openkruise/agentio/bench/scenario"
)

func main() {
	plan := flag.String("suite", "", "suite JSON to execute or replay")
	output := flag.String("output", "", "new directory outside the repository for artifacts")
	only := flag.String("case", "", "run only this case from the saved suite")
	flag.Parse()
	if err := run(*plan, *output, *only); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(plan, output, only string) error {
	if output == "" {
		return fmt.Errorf("-output is required")
	}
	data, err := os.ReadFile(plan)
	if err != nil {
		return err
	}
	var suite scenario.Suite
	if err = json.Unmarshal(data, &suite); err != nil {
		return err
	}
	if only != "" {
		var selected []scenario.Case
		for _, c := range suite.Cases {
			if c.Name == only {
				selected = append(selected, c)
			}
		}
		suite.Cases = selected
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	_, err = scenario.Run(ctx, suite, output, os.Stdout)
	return err
}
