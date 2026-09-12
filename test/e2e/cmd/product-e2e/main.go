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
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/openkruise/agentio/test/e2e"
	"github.com/openkruise/agentio/test/e2e/command"
	"github.com/openkruise/agentio/test/e2e/product"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := execute(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type options struct {
	action, root, group, format, out string
	timeout                          time.Duration
	selection                        product.Selection
}

func parseOptions(args []string, stderr io.Writer) (options, error) {
	if len(args) == 0 || args[0] != "plan" && args[0] != "run" {
		return options{}, errors.New("usage: product-e2e plan|run [-suites names] [-profile sidecar|ambient] [-backend auto|iptables] [-tests regexp] [-group id] [-force]")
	}
	opts := options{action: args[0]}
	fs := flag.NewFlagSet(opts.action, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&opts.root, "root", ".", "test/e2e module directory")
	suites := fs.String("suites", os.Getenv("AGENTIO_E2E_SUITES"), "comma- or space-separated suite names (default: required product suites)")
	fs.StringVar(&opts.selection.Profile, "profile", os.Getenv("AGENTIO_E2E_PROFILE"), "select one profile")
	fs.StringVar(&opts.selection.Backend, "backend", os.Getenv("AGENTIO_E2E_FIREWALL_BACKEND"), "select one backend")
	fs.StringVar(&opts.group, "group", os.Getenv("AGENTIO_E2E_GROUP"), "select one generated environment group")
	fs.StringVar(&opts.selection.Tests, "tests", "", "regular expression selecting top-level Go tests")
	fs.BoolVar(&opts.selection.Force, "force", false, "ignore required coverage; requires explicit suites, profile and backend")
	fs.StringVar(&opts.format, "format", "text", "plan output: text or json")
	fs.StringVar(&opts.out, "out", "", "write the selected plan as JSON")
	fs.DurationVar(&opts.timeout, "timeout", 30*time.Minute, "timeout per suite")
	if err := fs.Parse(args[1:]); err != nil {
		return options{}, err
	}
	if fs.NArg() != 0 || opts.format != "text" && opts.format != "json" || opts.timeout <= 0 {
		return options{}, errors.New("unexpected positional arguments, invalid format or nonpositive timeout")
	}
	for _, name := range strings.FieldsFunc(*suites, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' }) {
		opts.selection.Suites = append(opts.selection.Suites, strings.TrimPrefix(name, "./suites/"))
	}
	if len(opts.selection.Suites) == 1 && opts.selection.Suites[0] == "..." {
		opts.selection.Suites = nil
	}
	return opts, nil
}

func execute(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	opts, err := parseOptions(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return err
	}
	commands := command.Runner{}
	inventory, err := product.Discover(ctx, opts.root, commands)
	if err != nil {
		return err
	}
	plan, err := product.Build(product.Catalog(), inventory, opts.selection)
	if err != nil {
		return err
	}
	plan, err = selectGroup(plan, opts.group)
	if err != nil {
		return err
	}
	if opts.action == "run" {
		config, err := runConfig(plan)
		if err != nil {
			return err
		}
		if opts.out == "" {
			directory := config.Artifacts.Dir
			if !filepath.IsAbs(directory) {
				directory = filepath.Join(opts.root, directory)
			}
			opts.out = filepath.Join(directory, fmt.Sprintf("product-%d", time.Now().UnixNano()), "plan.json")
		}
	}
	if opts.out != "" {
		if err := writePlan(opts.out, plan); err != nil {
			return err
		}
	}
	if err := printPlan(stdout, opts.format, plan); err != nil {
		return err
	}
	if opts.action == "plan" {
		return nil
	}
	return (product.Runner{Commands: commands, Root: opts.root, Env: os.Environ(), Output: stdout, Timeout: opts.timeout}).Run(ctx, plan)
}

func selectGroup(plan product.Plan, id string) (product.Plan, error) {
	if id == "" {
		return plan, nil
	}
	for _, group := range plan.Include {
		if group.ID == id {
			return product.Plan{Include: []product.Group{group}}, nil
		}
	}
	return product.Plan{}, fmt.Errorf("group %q has no tests in the selected plan", id)
}

func runConfig(plan product.Plan) (e2e.Config, error) {
	// Respect the framework's YAML/environment precedence before allowing
	// multiple combinations to use the caller's cluster configuration.
	defaults := e2e.DefaultConfig()
	defaults.Artifacts.Dir = "artifacts"
	config, err := e2e.ResolveConfig(e2e.RegisterFlags(flag.NewFlagSet("framework", flag.ContinueOnError)), defaults)
	if err != nil {
		return e2e.Config{}, err
	}
	if len(plan.Include) > 1 && (config.Cluster.Mode == e2e.ClusterModeExisting || config.Cluster.Reuse || os.Getenv("AGENTIO_E2E_REUSE") == "true") {
		return e2e.Config{}, errors.New("select one group when borrowing a cluster or Agentio installation")
	}
	return config, nil
}

func writePlan(path string, plan product.Plan) error {
	data, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0644)
}

func printPlan(output io.Writer, format string, plan product.Plan) error {
	if format == "json" {
		return json.NewEncoder(output).Encode(plan)
	}
	for _, group := range plan.Include {
		if _, err := fmt.Fprintf(output, "%s (fixtures: %s)\n", group.ID, strings.Join(group.Fixtures, ", ")); err != nil {
			return err
		}
		for _, invocation := range group.Invocations {
			if _, err := fmt.Fprintf(output, "  %s: %d tests\n", invocation.Suite, len(invocation.Tests)); err != nil {
				return err
			}
		}
	}
	return nil
}
