// Copyright Istio Authors
// Modifications Copyright 2026 The Kruise Authors
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

package proxyinit

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/spf13/pflag"

	agentlog "github.com/openkruise/agentio/pkg/log"
	"github.com/openkruise/agentio/pkg/proxyinit/config"
	"github.com/openkruise/agentio/pkg/proxyinit/iptables/constants"
)

// Command installs rules in the current network namespace before workload startup.
func Command(ctx context.Context, args []string, output, errors io.Writer) error {
	cfg, err := loadConfig(args, errors)
	if err != nil {
		return err
	}
	return Run(ctx, cfg)
}

//nolint:errcheck // Match Istio BindEnv: malformed environment values do not abort startup.
func loadConfig(args []string, output io.Writer) (*config.Config, error) {
	cfg := config.DefaultConfig()
	fs := pflag.NewFlagSet("proxy-init", pflag.ContinueOnError)
	fs.SetOutput(output)
	bindCmdlineFlags(cfg, fs)
	level := fs.String("log-output-level", "default:info", "Log level, optionally prefixed with default:")
	jsonLog := fs.Bool("log-as-json", false, "Emit JSON logs")
	fs.VisitAll(func(f *pflag.Flag) {
		if f.Name == constants.OutboundCapturePort {
			return // Upstream binds this option to the command line only.
		}
		if v, ok := os.LookupEnv("AGENTIO_" + strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))); ok {
			_ = fs.Set(f.Name, v)
		}
	})
	if value, ok := os.LookupEnv("INVALID_DROP"); ok {
		_ = fs.Set(constants.DropInvalid, value)
	}
	if len(args) > 0 && args[0] == "proxy-init" {
		args = args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() != 0 {
		return nil, fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	var logLevel slog.Level
	if err := logLevel.UnmarshalText([]byte(strings.TrimPrefix(*level, "default:"))); err != nil {
		return nil, err
	}
	agentlog.ConfigureOutputLevel(logLevel)
	opts := &slog.HandlerOptions{Level: logLevel}
	var handler slog.Handler = slog.NewTextHandler(output, opts)
	if *jsonLog {
		handler = slog.NewJSONHandler(output, opts)
	}
	slog.SetDefault(slog.New(handler))
	if err := cfg.FillConfigFromEnvironment(); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func bind[T string | bool | uint16 | time.Duration](fs *pflag.FlagSet, name, shorthand, usage string, value *T) {
	switch v := any(value).(type) {
	case *string:
		fs.StringVarP(v, name, shorthand, *v, usage)
	case *bool:
		fs.BoolVarP(v, name, shorthand, *v, usage)
	case *uint16:
		fs.Uint16VarP(v, name, shorthand, *v, usage)
	case *time.Duration:
		fs.DurationVarP(v, name, shorthand, *v, usage)
	}
}

//nolint:funlen // Keep flag declarations together for review.
func bindCmdlineFlags(cfg *config.Config, fs *pflag.FlagSet) {
	bind(fs, constants.OutboundCapturePort, "p", "Port to which outbound TCP traffic is redirected.", &cfg.ProxyPort)

	bind(fs, constants.InboundCapturePort, "z",
		"Port to which all inbound TCP traffic to the pod/VM should be redirected to.",
		&cfg.InboundCapturePort)

	bind(fs, constants.InboundTunnelPort, "e",
		"Specify the HBONE tunnel port for inbound tcp traffic.",
		&cfg.InboundTunnelPort)

	bind(
		fs,
		constants.ProxyUID,
		"u",
		"Specify the UID of the user for which the redirection is not applied. Typically, this is the UID of the proxy container.",
		&cfg.ProxyUID,
	)

	bind(fs, constants.ProxyGID, "g",
		"Specify the GID of the user for which the redirection is not applied (same default value as -u param).",
		&cfg.ProxyGID)

	bind(fs, constants.InterceptionMode, "m",
		"The mode used to redirect inbound connections to Envoy, \"REDIRECT\".",
		&cfg.InboundInterceptionMode)

	bind(fs, constants.IncludeInboundPorts, "b",
		"Comma separated list of inbound ports for which traffic is to be redirected to Envoy (optional). "+
			"The wildcard character \"*\" can be used to configure redirection for all ports. An empty list will disable.",
		&cfg.InboundPortsInclude)

	bind(fs, constants.ExcludeInboundPorts, "d",
		"Comma separated list of inbound ports to be excluded from redirection to Envoy (optional). "+
			"Only applies when all inbound traffic (i.e. \"*\") is being redirected.",
		&cfg.InboundPortsExclude)

	bind(fs, constants.ExcludeInterfaces, "c",
		"Comma separated list of NIC (optional). Neither inbound nor outbound traffic will be captured.",
		&cfg.ExcludeInterfaces)

	bind(fs, constants.IncludeOutboundIPRanges, "i",
		"Comma separated list of IP ranges in CIDR form to redirect to envoy (optional). "+
			"The wildcard character \"*\" can be used to redirect all outbound traffic. An empty list will disable all outbound.",
		&cfg.OutboundIPRangesInclude)

	bind(fs, constants.ExcludeOutboundIPRanges, "x",
		"Comma separated list of IP ranges in CIDR form to be excluded from redirection. "+
			"Only applies when all  outbound traffic (i.e. \"*\") is being redirected.",
		&cfg.OutboundIPRangesExclude)

	bind(fs, constants.IncludeOutboundPorts, "q",
		"Comma separated list of outbound ports to be explicitly included for redirection to Envoy.",
		&cfg.OutboundPortsInclude)

	bind(fs, constants.ExcludeOutboundPorts, "o",
		"Comma separated list of outbound ports to be excluded from redirection to Envoy.",
		&cfg.OutboundPortsExclude)

	bind(fs, constants.RerouteVirtualInterfaces, "k",
		"Comma separated list of virtual interfaces whose inbound traffic (from VM) will be treated as outbound.",
		&cfg.RerouteVirtualInterfaces)

	bind(fs, constants.DryRun, "n", "Do not call any external dependencies like iptables.",
		&cfg.DryRun)

	bind(fs, constants.IptablesProbePort, "", "Set listen port for failure detection.", &cfg.IptablesProbePort)

	bind(fs, constants.ProbeTimeout, "", "Failure detection timeout.", &cfg.ProbeTimeout)

	bind(fs, constants.SkipRuleApply, "", "Skip iptables apply.", &cfg.SkipRuleApply)

	bind(fs, constants.RunValidation, "", "Validate iptables.", &cfg.RunValidation)

	bind(fs, constants.RedirectDNS, "", "Enable capture of dns traffic by ztunnel.", &cfg.RedirectDNS)

	bind(fs, constants.DropInvalid, "", "Enable invalid drop in the iptables rules.", &cfg.DropInvalid)
	bind(
		fs,
		constants.RejectNonTCP,
		"",
		"Reject non-TCP outbound traffic except DNS and essential ICMPv6 control traffic; also capture all TCP/UDP port 53 traffic.",
		&cfg.RejectNonTCP,
	)

	bind(fs, constants.DualStack, "", "Enable ipv4/ipv6 redirects for dual-stack.", &cfg.DualStack)

	bind(
		fs,
		constants.CaptureAllDNS,
		"",
		"Instead of only capturing DNS traffic to DNS server IP, capture all DNS traffic at port 53. This setting is only effective when redirect dns is enabled.",
		&cfg.CaptureAllDNS,
	)

	bind(fs, constants.NetworkNamespace, "", "The network namespace that iptables rules should be applied to.",
		&cfg.NetworkNamespace)

	bind(fs, constants.CNIMode, "", "Whether to run as CNI plugin.", &cfg.HostFilesystemPodNetwork)

	bind(
		fs,
		constants.Reconcile,
		"",
		"Reconcile pre-existing and incompatible iptables rules instead of failing if drift is detected.",
		&cfg.Reconcile,
	)

	bind(fs, constants.CleanupOnly, "", "Perform a forced cleanup without creating new iptables chains or rules.",
		&cfg.CleanupOnly)

	// This flag is a safety measure in case the idempotency changes of #50328 backfire.
	// Allow bypassing of iptables idempotency handling, and attempts to apply iptables rules regardless of table state, which may cause unrecoverable failures.
	// Consider removing it after several releases with no reported issues.
	bind(fs, constants.ForceApply, "", "Apply iptables changes even if they appear to already be in place.",
		&cfg.ForceApply)

	// This mode is an alternative for iptables. It uses nftables rules for traffic redirection.
	bind(fs, constants.NativeNftables, "", "Use native nftables instead of iptables rules.",
		&cfg.NativeNftables)
	bind(
		fs,
		constants.NativeNftablesOutputPriority,
		"",
		"Native nftables NAT OUTPUT priority; use -101 to intercept before kube-proxy Service DNAT. Takes effect in a new network namespace.",
		&cfg.NativeNftablesOutputPriority,
	)

	// This allows the user to specify the iptables version to use.
	bind(fs, constants.ForceIptablesBinary, "", "Break glass option to choose which iptables binary to use.",
		&cfg.ForceIptablesBinary)
}
