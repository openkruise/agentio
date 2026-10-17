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
	"flag"
	"fmt"
	"io"
	"math"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/validation"
)

type variant struct {
	Name    string            `json:"name"`
	Image   string            `json:"image"`
	Command string            `json:"command"`
	Env     map[string]string `json:"env"`
}

type config struct {
	Kubeconfig        string
	Context           string
	Namespace         string
	KeepNamespace     bool
	Output            string
	BenchImage        string
	ControlPlaneImage string
	PullPolicy        string
	Suites            []string
	Variants          []variant
	Workloads         int
	Gateways          int
	ControlPlanes     int
	CPCPU             int
	PorterCPU         int
	LoadCPU           int
	CPMemory          string
	PorterMemory      string
	Trials            int
	PrepareSeconds    int
	HotRequests       int
	ReconnectRequests int
	HotRate           int
	ColdRate          int
	MixedSeconds      int
	AdmissionRate     float64
}

type stringsFlag []string

func (s *stringsFlag) String() string {
	return strings.Join(*s, ",")
}

func (s *stringsFlag) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func parseConfig(args []string, output io.Writer) (config, error) {
	var c config
	var variants, commands, envs stringsFlag
	var suites string
	f := flag.NewFlagSet("porter-bench run", flag.ContinueOnError)
	f.SetOutput(output)
	f.StringVar(&c.Kubeconfig, "kubeconfig", "", "explicit kubeconfig")
	f.StringVar(&c.Context, "context", "", "kubeconfig context")
	f.StringVar(
		&c.Namespace,
		"namespace",
		"porter-perf-"+time.Now().Format("20060102150405"),
		"new disposable namespace",
	)
	f.StringVar(&c.Output, "output", "", "empty artifact directory")
	f.BoolVar(
		&c.KeepNamespace,
		"keep-namespace",
		false,
		"retain test namespace after success or failure for inspection",
	)
	f.StringVar(&c.BenchImage, "bench-image", "", "Go helper image")
	f.StringVar(
		&c.ControlPlaneImage,
		"control-plane-image",
		"",
		"independent ADS server image; defaults to bench-image",
	)
	f.StringVar(&c.PullPolicy, "image-pull-policy", "Never", "Never, IfNotPresent, Always")
	f.StringVar(&suites, "suites", "reconnect", "comma-separated reconnect,mixed,lifecycle,failover")
	f.Var(&variants, "variant", "NAME=IMAGE (repeatable)")
	f.Var(&commands, "variant-command", "NAME=/path/to/porter (repeatable)")
	f.Var(&envs, "variant-env", "NAME:KEY=VALUE (repeatable)")
	for _, item := range []struct {
		name   string
		target *int
		value  int
	}{
		{"workloads", &c.Workloads, 100000}, {"gateways", &c.Gateways, 4}, {"control-planes", &c.ControlPlanes, 2},
		{"cp-cpu", &c.CPCPU, 6}, {"porter-cpu", &c.PorterCPU, 3}, {"load-cpu", &c.LoadCPU, 3},
		{"trials", &c.Trials, 3}, {"prepare-seconds", &c.PrepareSeconds, 10},
		{"hot-requests", &c.HotRequests, 2000000}, {"reconnect-requests", &c.ReconnectRequests, 300000},
		{"hot-rate", &c.HotRate, 10000}, {"cold-rate", &c.ColdRate, 1000}, {"mixed-seconds", &c.MixedSeconds, 60},
	} {
		f.IntVar(item.target, item.name, item.value, "positive "+item.name)
	}
	f.StringVar(&c.CPMemory, "cp-memory", "6Gi", "control-plane memory limit")
	f.StringVar(&c.PorterMemory, "porter-memory", "3Gi", "Porter memory limit")
	f.Float64Var(&c.AdmissionRate, "admission-rate", 0, "0 retains automatic stream admission limit")
	if err := f.Parse(args); err != nil {
		return c, err
	}
	if f.NArg() != 0 {
		return c, fmt.Errorf("unexpected arguments: %v", f.Args())
	}
	if err := c.validate(); err != nil {
		return c, err
	}
	if len(variants) == 0 {
		return c, fmt.Errorf("at least one variant is required")
	}
	for suite := range strings.SplitSeq(suites, ",") {
		if !slices.Contains([]string{"reconnect", "mixed", "lifecycle", "failover", "controlplane"}, suite) ||
			slices.Contains(c.Suites, suite) {
			return c, fmt.Errorf("unknown or duplicate suite %q", suite)
		}
		if suite == "failover" && c.ControlPlanes < 2 {
			return c, fmt.Errorf("failover needs at least two control planes")
		}
		c.Suites = append(c.Suites, suite)
	}
	if err := c.parseVariants(variants, commands, envs); err != nil {
		return c, err
	}
	return c, nil
}

func (c config) validate() error {
	if c.Kubeconfig == "" || c.Output == "" || c.BenchImage == "" {
		return fmt.Errorf("kubeconfig, output, bench-image and at least one variant are required")
	}
	if errs := validation.IsDNS1123Label(c.Namespace); len(errs) > 0 {
		return fmt.Errorf("invalid namespace: %v", errs)
	}
	for _, n := range []int{c.Gateways, c.ControlPlanes, c.CPCPU, c.PorterCPU, c.LoadCPU, c.Trials, c.PrepareSeconds, c.HotRequests, c.ReconnectRequests, c.HotRate, c.ColdRate, c.MixedSeconds} {
		if n <= 0 {
			return fmt.Errorf("counts, rates, CPUs and preparation time must be positive")
		}
	}
	if c.Workloads < 50000 || c.Workloads%500 != 0 || c.Workloads%c.Gateways != 0 || c.Workloads/c.Gateways <= 1000 {
		return fmt.Errorf("workloads must be >=50000, divisible by 500 and gateways, with >1000 per gateway")
	}
	for _, n := range []int{c.HotRequests, c.ReconnectRequests, c.HotRate, c.ColdRate} {
		if n%c.Gateways != 0 {
			return fmt.Errorf("counts and rates must divide evenly across gateways")
		}
	}
	if math.IsNaN(c.AdmissionRate) || math.IsInf(c.AdmissionRate, 0) || c.AdmissionRate < 0 {
		return fmt.Errorf("admission rate must be finite and non-negative")
	}
	for _, memory := range []string{c.CPMemory, c.PorterMemory} {
		q, err := resource.ParseQuantity(memory)
		if err != nil || q.Sign() <= 0 {
			return fmt.Errorf("invalid memory limit %q", memory)
		}
	}
	if !slices.Contains([]string{"Never", "IfNotPresent", "Always"}, c.PullPolicy) {
		return fmt.Errorf("invalid image pull policy")
	}
	return nil
}

func (c *config) parseVariants(variants, commands, envs []string) error {
	names := map[string]int{}
	for _, item := range variants {
		name, image, ok := strings.Cut(item, "=")
		_, duplicate := names[name]
		if !ok || image == "" || duplicate || !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(name) {
			return fmt.Errorf("invalid or duplicate variant %q", item)
		}
		names[name] = len(c.Variants)
		c.Variants = append(
			c.Variants,
			variant{Name: name, Image: image, Command: "/usr/local/bin/agentio-porter", Env: map[string]string{}},
		)
	}
	for _, item := range commands {
		name, command, ok := strings.Cut(item, "=")
		index, known := names[name]
		if !ok || !known || !filepath.IsAbs(command) {
			return fmt.Errorf("invalid variant command %q", item)
		}
		c.Variants[index].Command = command
	}
	for _, item := range envs {
		name, pair, ok := strings.Cut(item, ":")
		key, value, equals := strings.Cut(pair, "=")
		index, known := names[name]
		if !ok || !equals || !known || !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString(key) {
			return fmt.Errorf("invalid variant env %q", item)
		}
		c.Variants[index].Env[key] = value
	}
	return nil
}
