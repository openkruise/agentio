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

package gatewayagent

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"strconv"
	"strings"
	"time"
)

// RuntimeOptions is the deployment-facing configuration. Identity and credential
// paths are deliberately supplied separately by the operator/Downward API.
// Duration values use Go duration strings, e.g. "30s".
type RuntimeOptions struct {
	AdvancedOptions
	Concurrency                 *int           `json:"concurrency,omitempty"`
	DrainDuration               string         `json:"drainDuration,omitempty"`
	TerminationDrainDuration    string         `json:"terminationDrainDuration,omitempty"`
	MinimumDrainDuration        string         `json:"minimumDrainDuration,omitempty"`
	ExitOnZeroActiveConnections bool           `json:"exitOnZeroActiveConnections"`
	StatsFlushInterval          string         `json:"statsFlushInterval,omitempty"`
	SecretTTL                   string         `json:"secretTTL,omitempty"`
	KeepaliveInterval           string         `json:"keepaliveInterval,omitempty"`
	KeepaliveTimeout            string         `json:"keepaliveTimeout,omitempty"`
	AgentLogLevel               string         `json:"agentLogLevel,omitempty"`
	EnvoyLogLevel               string         `json:"envoyLogLevel,omitempty"`
	EnvoyComponentLogLevel      string         `json:"envoyComponentLogLevel,omitempty"`
	LogAsJSON                   bool           `json:"logAsJSON"`
	Metadata                    map[string]any `json:"metadata,omitempty"`
}

// LoadConfig applies defaults, deployment JSON, metadata environment variables,
// then explicit CLI flags. CPU-derived concurrency is only a fallback.
func LoadConfig(args []string, output io.Writer) (Config, error) {
	c := FromEnvironment()
	for _, arg := range args {
		if arg == "--legacy" || arg == "-legacy" {
			c.Legacy = true
		}
		if strings.HasPrefix(arg, "--legacy=") || strings.HasPrefix(arg, "-legacy=") {
			_, value, _ := strings.Cut(arg, "=")
			enabled, err := strconv.ParseBool(value)
			if err != nil {
				return c, err
			}
			c.Legacy = enabled
		}
	}
	if c.Legacy {
		c.legacyDefaults()
		c.Proxy.DrainDuration = 45 * time.Second
		c.Proxy.TerminationDrainDuration = 5 * time.Second
	}
	options, err := c.loadRuntimeOptions()
	if err != nil {
		return c, err
	}
	if err := c.applyFlags(args, output, options.Concurrency); err != nil {
		return c, err
	}
	c.applyCredentialPaths()
	if err := c.loadMetadata(); err != nil {
		return c, err
	}
	return c, c.validateRuntime()
}

func (c *Config) loadRuntimeOptions() (RuntimeOptions, error) {
	var options RuntimeOptions
	raw := os.Getenv("AGENTIO_GATEWAY_CONFIG")
	if c.Legacy {
		defaults, err := legacyAnnotationOptions()
		if err != nil {
			return options, err
		}
		if raw != "" {
			var explicit map[string]any
			if err := json.Unmarshal([]byte(raw), &explicit); err != nil {
				return options, err
			}
			maps.Copy(defaults, explicit)
		}
		encoded, err := json.Marshal(defaults)
		if err != nil {
			return options, err
		}
		raw = string(encoded)
	}
	if raw != "" {
		dec := json.NewDecoder(strings.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&options); err != nil {
			return options, fmt.Errorf("AGENTIO_GATEWAY_CONFIG: %w", err)
		}
		if err := dec.Decode(new(any)); err != io.EOF {
			return options, fmt.Errorf("AGENTIO_GATEWAY_CONFIG must contain one JSON object")
		}
	}
	c.AdvancedOptions = options.AdvancedOptions
	for _, setting := range []struct {
		name   string
		value  string
		target *time.Duration
	}{
		{"drainDuration", options.DrainDuration, &c.Proxy.DrainDuration},
		{"terminationDrainDuration", options.TerminationDrainDuration, &c.Proxy.TerminationDrainDuration},
		{"minimumDrainDuration", options.MinimumDrainDuration, &c.MinimumDrainDuration},
		{"statsFlushInterval", options.StatsFlushInterval, &c.StatsFlushInterval},
		{"secretTTL", options.SecretTTL, &c.SecretTTL},
		{"keepaliveInterval", options.KeepaliveInterval, &c.KeepaliveInterval},
		{"keepaliveTimeout", options.KeepaliveTimeout, &c.KeepaliveTimeout},
	} {
		if setting.value != "" {
			v, err := time.ParseDuration(setting.value)
			if err != nil {
				return options, fmt.Errorf("%s: %w", setting.name, err)
			}
			*setting.target = v
		}
	}
	if options.AgentLogLevel != "" {
		c.AgentLogLevel = options.AgentLogLevel
	}
	if options.EnvoyLogLevel != "" {
		c.LogLevel = options.EnvoyLogLevel
	}
	c.ComponentLogLevel = options.EnvoyComponentLogLevel
	c.LogAsJSON = options.LogAsJSON
	c.ExitOnZeroActiveConnections = options.ExitOnZeroActiveConnections
	c.Metadata = maps.Clone(options.Metadata)
	if c.Metadata == nil {
		c.Metadata = map[string]any{}
	}
	return options, nil
}

func (c *Config) loadMetadata() error {
	stringKeys := map[string]bool{}
	for _, env := range os.Environ() {
		name, value, _ := strings.Cut(env, "=")
		if key, ok := strings.CutPrefix(name, "AGENTIO_META_"); ok {
			if key == "" {
				return fmt.Errorf("empty metadata key")
			}
			c.Metadata[key], stringKeys[key] = value, true
		}
	}
	for _, env := range os.Environ() {
		name, value, _ := strings.Cut(env, "=")
		if key, ok := strings.CutPrefix(name, "AGENTIO_METAJSON_"); ok {
			if key == "" || stringKeys[key] {
				return fmt.Errorf("empty or duplicate metadata key %q", key)
			}
			var v any
			if err := json.Unmarshal([]byte(value), &v); err != nil {
				return fmt.Errorf("%s contains invalid JSON", name)
			}
			c.Metadata[key] = v
		}
	}
	for key := range c.Metadata {
		switch key {
		case "POD_NAME",
			"POD_NAMESPACE",
			"POD_UID",
			"NODE_NAME",
			"CLUSTER_ID",
			"SERVICE_ACCOUNT",
			"INSTANCE_IP",
			"TRUST_DOMAIN",
			"AGENTIO_VERSION",
			"AGENTIO_REVISION":
			return fmt.Errorf("metadata key %q is reserved", key)
		}
	}
	return nil
}

func (c *Config) applyFlags(args []string, output io.Writer, concurrency *int) error {
	flags := flag.NewFlagSet("gateway-agent", flag.ContinueOnError)
	flags.SetOutput(output)
	flags.BoolVar(&c.Legacy, "legacy", c.Legacy, "Use the pinned legacy gateway Envoy startup contract")
	flags.StringVar(&c.AgentLogLevel, "agent-log-level", c.AgentLogLevel, "Agent log level: debug, info, warn, error")
	flags.StringVar(&c.LogLevel, "envoy-log-level", c.LogLevel, "Envoy log level")
	flags.StringVar(
		&c.ComponentLogLevel,
		"envoy-component-log-level",
		c.ComponentLogLevel,
		"Envoy component log levels",
	)
	flags.BoolVar(&c.LogAsJSON, "log-as-json", c.LogAsJSON, "JSON logs for both agent and Envoy")
	flags.DurationVar(
		&c.Proxy.TerminationDrainDuration,
		"termination-drain-duration",
		c.Proxy.TerminationDrainDuration,
		"Maximum shutdown drain time",
	)
	flags.DurationVar(&c.Proxy.DrainDuration, "drain-duration", c.Proxy.DrainDuration, "Envoy listener drain time")
	flags.DurationVar(
		&c.MinimumDrainDuration,
		"minimum-drain-duration",
		c.MinimumDrainDuration,
		"Minimum wait before counting active connections",
	)
	flags.BoolVar(
		&c.ExitOnZeroActiveConnections,
		"exit-on-zero-active-connections",
		c.ExitOnZeroActiveConnections,
		"Exit when connections drain, within maximum drain time",
	)
	flags.DurationVar(
		&c.StatsFlushInterval,
		"stats-flush-interval",
		c.StatsFlushInterval,
		"Envoy statistics flush interval",
	)
	flags.DurationVar(&c.SecretTTL, "secret-ttl", c.SecretTTL, "Requested workload certificate lifetime")
	flags.DurationVar(
		&c.KeepaliveInterval,
		"keepalive-interval",
		c.KeepaliveInterval,
		"ADS gRPC keepalive interval (at least 30s, matching agentiod)",
	)
	flags.DurationVar(&c.KeepaliveTimeout, "keepalive-timeout", c.KeepaliveTimeout, "ADS gRPC keepalive timeout")
	flags.StringVar(
		&c.StatsEvictionInterval,
		"stats-eviction-interval",
		c.StatsEvictionInterval,
		"Unused worker statistics eviction interval (multiple of stats flush)",
	)
	skipDeprecated := boolOption(c.SkipDeprecatedLogs, true)
	flags.BoolVar(&skipDeprecated, "skip-deprecated-logs", skipDeprecated, "Suppress Envoy deprecation logs")
	policy := boolOption(c.PolicyStore, false)
	flags.BoolVar(&policy, "policy-store", policy, "Enable legacy SNI policy store and initial-sync readiness")
	workers := 0
	if concurrency != nil {
		workers = *concurrency
	}
	flags.IntVar(&workers, "concurrency", workers, "Envoy worker count; explicit zero uses Envoy default")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", flags.Args())
	}
	c.SkipDeprecatedLogs = &skipDeprecated
	c.PolicyStore = &policy
	explicitWorkers := concurrency != nil
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "concurrency" {
			explicitWorkers = true
		}
	})
	cpuLimit := os.Getenv("AGENTIO_CPU_LIMIT")
	if cpuLimit == "" && c.Legacy {
		cpuLimit = os.Getenv("ISTIO_CPU_LIMIT")
	}
	if !explicitWorkers && cpuLimit != "" {
		var err error
		workers, err = strconv.Atoi(cpuLimit)
		if err != nil || workers <= 0 {
			return fmt.Errorf("AGENTIO_CPU_LIMIT must be a positive integer (limits.cpu with divisor 1)")
		}
	}
	if workers < 0 || workers > 65535 {
		return fmt.Errorf("concurrency must be between 0 and 65535")
	}
	c.Proxy.Concurrency = int32(workers)
	if grace := os.Getenv("AGENTIO_TERMINATION_GRACE_PERIOD_SECONDS"); grace != "" {
		seconds, err := strconv.Atoi(grace)
		if err != nil || seconds < 1 {
			return fmt.Errorf("invalid Pod termination grace period")
		}
		// Leave time for child cleanup before Kubernetes SIGKILL.
		maximum := max(0, time.Duration(seconds)*time.Second-5*time.Second)
		c.Proxy.TerminationDrainDuration = min(c.Proxy.TerminationDrainDuration, maximum)
	}
	return nil
}

func (c Config) validateRuntime() error {
	if c.SecretTTL < time.Second || c.StatsFlushInterval <= 0 || c.Proxy.TerminationDrainDuration < 0 ||
		c.Proxy.DrainDuration < 0 ||
		c.MinimumDrainDuration < 0 ||
		c.Proxy.Concurrency < 0 {
		return fmt.Errorf("invalid certificate lifetime, statistics interval, drain duration or concurrency")
	}
	if c.ExitOnZeroActiveConnections && c.MinimumDrainDuration > c.Proxy.TerminationDrainDuration {
		return fmt.Errorf("minimum drain duration exceeds maximum termination drain duration")
	}
	if c.KeepaliveInterval < 30*time.Second || c.KeepaliveTimeout <= 0 {
		return fmt.Errorf(
			"keepalive interval must be at least 30s (agentiod enforcement policy) and timeout must be positive",
		)
	}
	switch c.AgentLogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("invalid agent log level %q", c.AgentLogLevel)
	}
	switch c.LogLevel {
	case "trace", "debug", "info", "warning", "warn", "error", "critical", "off":
	default:
		return fmt.Errorf("invalid Envoy log level %q", c.LogLevel)
	}
	return c.validateAdvanced()
}
