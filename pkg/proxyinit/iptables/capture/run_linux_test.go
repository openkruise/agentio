//go:build linux && proxyinit_integration

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

package capture

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	// Create a new network namespace. This will have the 'lo' interface ready but nothing else.
	_ "github.com/howardjohn/unshare-go/netns"
	// Create a new user namespace. This will map the current UID/GID to 0.
	"github.com/howardjohn/unshare-go/userns"

	"github.com/stretchr/testify/require"

	"github.com/openkruise/agentio/pkg/proxyinit/iptables/constants"
	dep "github.com/openkruise/agentio/pkg/proxyinit/iptables/dependencies"
)

func TestIdempotentEquivalentRerun(t *testing.T) {
	setup(t)
	commonCases := getCommonTestCases()
	ext := &dep.RealDependencies{
		UsePodScopedXtablesLock: false,
		NetworkNamespace:        "",
	}
	scope := log
	for _, tt := range commonCases {
		t.Run(tt.name, func(t *testing.T) {
			cfg := constructTestConfig()
			tt.config(cfg)
			// Override UID and GID otherwise test will fail in the linux namespace from unshare-go lib
			cfg.ProxyUID = "0"
			cfg.ProxyGID = "0"
			if cfg.OwnerGroupsExclude != "" {
				cfg.OwnerGroupsInclude = "0"
			}
			if cfg.OwnerGroupsInclude != "" {
				cfg.OwnerGroupsInclude = "0"
			}

			defer func() {
				// Final Cleanup
				cfg.CleanupOnly = true
				cfg.Reconcile = false
				iptConfigurator, err := NewIptablesConfigurator(cfg, ext)
				if err != nil {
					t.Fatal("can't detect iptables")
				}
				require.NoError(t, iptConfigurator.Run())
				residueExists, deltaExists := VerifyIptablesState(
					scope,
					iptConfigurator.ext,
					iptConfigurator.ruleBuilder,
					&iptConfigurator.iptV,
					&iptConfigurator.ipt6V,
				)
				require.Equal(t, residueExists, false)
				require.Equal(t, deltaExists, true)
			}()

			// First Pass
			cfg.Reconcile = false
			iptConfigurator, err := NewIptablesConfigurator(cfg, ext)
			if err != nil {
				t.Fatal("can't detect iptables")
			}
			require.NoError(t, iptConfigurator.Run())
			residueExists, deltaExists := VerifyIptablesState(
				scope,
				iptConfigurator.ext,
				iptConfigurator.ruleBuilder,
				&iptConfigurator.iptV,
				&iptConfigurator.ipt6V,
			)
			require.Equal(t, residueExists, true)
			require.Equal(t, deltaExists, false)

			// Second Pass
			iptConfigurator, err = NewIptablesConfigurator(cfg, ext)
			if err != nil {
				t.Fatal("can't detect iptables")
			}
			require.NoError(t, iptConfigurator.Run())

			// Execution should fail if force-apply is used and chains exists
			cfg.ForceApply = true
			iptConfigurator, err = NewIptablesConfigurator(cfg, ext)
			if err != nil {
				t.Fatal("can't detect iptables")
			}
			require.Error(t, iptConfigurator.Run())
			cfg.ForceApply = false
		})
	}
}

func TestIPv6NotAvailable(t *testing.T) {
	setup(t)
	cfg := constructTestConfig()
	ext := &dep.DependenciesStub{
		ForceIPv6DetectionFail: true,
	}

	// Agentio shouldn't fail if we're working with IPv4 interfaces only, and ip6tables is unavailable.
	cfg.EnableIPv6 = false
	iptConfigurator, _ := NewIptablesConfigurator(cfg, ext)
	require.NoError(t, iptConfigurator.Run())

	cfg.EnableIPv6 = true
	_, err := NewIptablesConfigurator(cfg, ext)
	require.Error(t, err)
}

var initialized = &sync.Once{}

func setup(t *testing.T) {
	initialized.Do(func() {
		// Setup group namespace so iptables --gid-owner will work
		require.NoError(t, userns.WriteGroupMap(map[uint32]uint32{userns.OriginalGID(): 0}))
		// Agentio iptables expects to find a non-localhost IP in some interface
		require.NoError(t, exec.Command("ip", "addr", "add", "240.240.240.240/32", "dev", "lo").Run())
	})

	tempDir := t.TempDir()
	xtables := filepath.Join(tempDir, "xtables.lock")
	// Override lockfile directory so that we don't need to unshare the mount namespace
	t.Setenv("XTABLES_LOCKFILE", xtables)
}

func TestIdempotentUnequaledRerun(t *testing.T) {
	setup(t)
	commonCases := getCommonTestCases()
	ext := &dep.RealDependencies{
		UsePodScopedXtablesLock: false,
		NetworkNamespace:        "",
	}
	scope := log
	for _, tt := range commonCases {
		t.Run(tt.name, func(t *testing.T) {
			cfg := constructTestConfig()
			tt.config(cfg)
			// Override UID and GID otherwise test will fail in the linux namespace from unshare-go lib
			cfg.ProxyUID = "0"
			cfg.ProxyGID = "0"
			var stdout, stderr bytes.Buffer
			if cfg.OwnerGroupsExclude != "" {
				cfg.OwnerGroupsInclude = "0"
			}
			if cfg.OwnerGroupsInclude != "" {
				cfg.OwnerGroupsInclude = "0"
			}
			iptConfigurator, err := NewIptablesConfigurator(cfg, ext)

			defer func() {
				// Final Cleanup
				iptConfigurator.cfg.CleanupOnly = true
				iptConfigurator.cfg.Reconcile = false
				require.NoError(t, err)
				require.NoError(t, iptConfigurator.Run())
				residueExists, deltaExists := VerifyIptablesState(
					scope,
					iptConfigurator.ext,
					iptConfigurator.ruleBuilder,
					&iptConfigurator.iptV,
					&iptConfigurator.ipt6V,
				)
				require.Equal(t, residueExists, true) // residue found due to extra OUTPUT rule
				require.Equal(t, deltaExists, true)
				// Remove additional rule
				cmd := exec.Command(
					iptConfigurator.iptV.DetectedBinary,
					"-t",
					"nat",
					"-D",
					"OUTPUT",
					"-p",
					"tcp",
					"--dport",
					"123",
					"-j",
					"ACCEPT",
				)
				cmd.Stdout = &stdout
				cmd.Stderr = &stderr
				if err := cmd.Run(); err != nil {
					t.Errorf("iptables cmd (%s %s) failed: %s", cmd.Path, cmd.Args, stderr.String())
				}
				residueExists, deltaExists = VerifyIptablesState(
					scope,
					iptConfigurator.ext,
					iptConfigurator.ruleBuilder,
					&iptConfigurator.iptV,
					&iptConfigurator.ipt6V,
				)
				require.Equal(t, residueExists, false, "found unexpected residue on final pass")
				require.Equal(t, deltaExists, true, "found no delta on final pass")
			}()

			// First Pass
			require.NoError(t, err)
			require.NoError(t, iptConfigurator.Run())
			residueExists, deltaExists := VerifyIptablesState(
				scope,
				iptConfigurator.ext,
				iptConfigurator.ruleBuilder,
				&iptConfigurator.iptV,
				&iptConfigurator.ipt6V,
			)
			require.Equal(t, residueExists, true, "did not find residue on first pass")
			require.Equal(t, deltaExists, false, "found delta on first pass")

			// Diverge from installation
			cmd := exec.Command(
				iptConfigurator.iptV.DetectedBinary,
				"-t",
				"nat",
				"-A",
				"OUTPUT",
				"-p",
				"tcp",
				"--dport",
				"123",
				"-j",
				"ACCEPT",
			)
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err := cmd.Run(); err != nil {
				t.Errorf("iptables cmd (%s %s) failed: %s", cmd.Path, cmd.Args, stderr.String())
			}

			// Apply not required after tainting non-AGENTIO chains with extra rules
			residueExists, deltaExists = VerifyIptablesState(
				scope,
				iptConfigurator.ext,
				iptConfigurator.ruleBuilder,
				&iptConfigurator.iptV,
				&iptConfigurator.ipt6V,
			)
			require.Equal(t, residueExists, true, "did not find residue on second pass")
			require.Equal(t, deltaExists, false, "found delta on second pass")

			cmd = exec.Command(
				iptConfigurator.iptV.DetectedBinary,
				"-t",
				"nat",
				"-A",
				"AGENTIO_INBOUND",
				"-p",
				"tcp",
				"--dport",
				"123",
				"-j",
				"ACCEPT",
			)
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err := cmd.Run(); err != nil {
				t.Errorf("iptables cmd (%s %s) failed: %s", cmd.Path, cmd.Args, stderr.String())
			}

			// Apply required after tainting AGENTIO chains
			residueExists, deltaExists = VerifyIptablesState(
				scope,
				iptConfigurator.ext,
				iptConfigurator.ruleBuilder,
				&iptConfigurator.iptV,
				&iptConfigurator.ipt6V,
			)
			require.Equal(t, residueExists, true, "did not find residue on third pass")
			require.Equal(t, deltaExists, true, "found no delta on third pass")

			// Fail is expected if cleanup is skipped
			iptConfigurator.cfg.Reconcile = false
			require.NoError(t, err)
			require.Error(t, iptConfigurator.Run())

			// Second pass with cleanup
			iptConfigurator.cfg.Reconcile = true
			require.NoError(t, err)
			require.NoError(t, iptConfigurator.Run())
		})
	}
}

func TestMixedIPv4Ipv6State(t *testing.T) {
	scope := log
	testCases := []struct {
		name              string
		enableInboundIPv6 bool
		errorExpected     bool
		setup             func(t *testing.T, iptConfigurator *IptablesConfigurator)
		check             func(t *testing.T, ext *dep.RealDependencies, cfg *IptablesConfigurator, residueExists, deltaExists bool)
		teardown          func(t *testing.T, iptConfigurator *IptablesConfigurator)
	}{
		{
			name: "With pre-existing IPv6 rule",
			setup: func(t *testing.T, iptConfigurator *IptablesConfigurator) {
				require.NoError(
					t,
					exec.Command(iptConfigurator.ipt6V.DetectedBinary, "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--dport", "123", "-j", "ACCEPT").
						Run(),
				)
			},
			check: func(t *testing.T, ext *dep.RealDependencies, iptConfigurator *IptablesConfigurator, residueExists, deltaExists bool) {
				require.Equal(t, residueExists, true)
				require.Equal(t, deltaExists, false)

				output, err := ext.Run(scope, true, constants.IPTablesSave, &iptConfigurator.iptV, nil)
				require.NoError(t, err)
				require.Equal(
					t,
					len(HasAgentioLeftovers(iptConfigurator.ruleBuilder.GetStateFromSave(output.String()))) > 0,
					true,
				)
				output, err = ext.Run(scope, true, constants.IPTablesSave, &iptConfigurator.ipt6V, nil)
				require.NoError(t, err)
				require.Equal(
					t,
					len(HasAgentioLeftovers(iptConfigurator.ruleBuilder.GetStateFromSave(output.String()))) == 0,
					true,
				)
			},
			teardown: func(t *testing.T, iptConfigurator *IptablesConfigurator) {
				require.NoError(
					t,
					exec.Command(iptConfigurator.ipt6V.DetectedBinary, "-t", "nat", "-D", "OUTPUT", "-p", "tcp", "--dport", "123", "-j", "ACCEPT").
						Run(),
				)
			},
		},
		{
			name:              "With pre-existing IPv6 rule and IPv6 enabled",
			enableInboundIPv6: true,
			setup: func(t *testing.T, iptConfigurator *IptablesConfigurator) {
				require.NoError(
					t,
					exec.Command(iptConfigurator.ipt6V.DetectedBinary, "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--dport", "123", "-j", "ACCEPT").
						Run(),
				)
			},
			check: func(t *testing.T, ext *dep.RealDependencies, iptConfigurator *IptablesConfigurator, residueExists, deltaExists bool) {
				require.Equal(t, residueExists, true)
				require.Equal(t, deltaExists, false)

				output, err := ext.Run(scope, true, constants.IPTablesSave, &iptConfigurator.iptV, nil)
				require.NoError(t, err)
				require.Equal(
					t,
					len(HasAgentioLeftovers(iptConfigurator.ruleBuilder.GetStateFromSave(output.String()))) > 0,
					true,
				)
				output, err = ext.Run(scope, true, constants.IPTablesSave, &iptConfigurator.ipt6V, nil)
				require.NoError(t, err)
				require.Equal(
					t,
					len(HasAgentioLeftovers(iptConfigurator.ruleBuilder.GetStateFromSave(output.String()))) > 0,
					true,
				)
			},
			teardown: func(t *testing.T, iptConfigurator *IptablesConfigurator) {
				require.NoError(
					t,
					exec.Command(iptConfigurator.ipt6V.DetectedBinary, "-t", "nat", "-D", "OUTPUT", "-p", "tcp", "--dport", "123", "-j", "ACCEPT").
						Run(),
				)
			},
		},
		{
			name: "With no pre-existing IPv6 rules",
			setup: func(t *testing.T, iptConfigurator *IptablesConfigurator) {
				// No-op
			},
			check: func(t *testing.T, ext *dep.RealDependencies, iptConfigurator *IptablesConfigurator, residueExists, deltaExists bool) {
				require.Equal(t, residueExists, true)
				require.Equal(t, deltaExists, false)

				output, err := ext.Run(scope, true, constants.IPTablesSave, &iptConfigurator.iptV, nil)
				require.NoError(t, err)
				require.Equal(
					t,
					len(HasAgentioLeftovers(iptConfigurator.ruleBuilder.GetStateFromSave(output.String()))) > 0,
					true,
				)
				output, err = ext.Run(scope, true, constants.IPTablesSave, &iptConfigurator.ipt6V, nil)
				require.NoError(t, err)
				require.Equal(
					t,
					len(HasAgentioLeftovers(iptConfigurator.ruleBuilder.GetStateFromSave(output.String()))) == 0,
					true,
				)
			},
			// No specific teardown is needed for this case
			teardown: func(t *testing.T, iptConfigurator *IptablesConfigurator) {
			},
		},
		{
			name: "With pre-existing rule in Agentio IPv6 chain",
			setup: func(t *testing.T, iptConfigurator *IptablesConfigurator) {
				cmd := exec.Command(iptConfigurator.ipt6V.DetectedBinary,
					"-t", "nat",
					"-N", "AGENTIO_INBOUND")
				require.NoError(t, cmd.Run())
				cmd = exec.Command(iptConfigurator.ipt6V.DetectedBinary,
					"-t", "nat", "-A", "AGENTIO_INBOUND",
					"-p", "udp", "--dport", "123", "-j", "RETURN")
				require.NoError(t, cmd.Run())
			},
			check: func(t *testing.T, ext *dep.RealDependencies, iptConfigurator *IptablesConfigurator, residueExists, deltaExists bool) {
				require.Equal(t, residueExists, true)
				require.Equal(t, deltaExists, true)

				output, err := ext.Run(scope, true, constants.IPTablesSave, &iptConfigurator.iptV, nil)
				require.NoError(t, err)
				require.Equal(
					t,
					len(HasAgentioLeftovers(iptConfigurator.ruleBuilder.GetStateFromSave(output.String()))) > 0,
					true,
				)
				output, err = ext.Run(scope, true, constants.IPTablesSave, &iptConfigurator.ipt6V, nil)
				require.NoError(t, err)
				require.Equal(
					t,
					len(
						HasAgentioLeftovers(iptConfigurator.ruleBuilder.GetStateFromSave(output.String()))["nat"].Chains,
					) == 1,
					true,
				)
			},
			teardown: func(t *testing.T, iptConfigurator *IptablesConfigurator) {
				require.NoError(
					t,
					exec.Command(iptConfigurator.ipt6V.DetectedBinary, "-t", "nat", "-F", "AGENTIO_INBOUND").Run(),
				)
				require.NoError(
					t,
					exec.Command(iptConfigurator.ipt6V.DetectedBinary, "-t", "nat", "-X", "AGENTIO_INBOUND").Run(),
				)
			},
		},
		{
			name:              "With pre-existing rule in Agentio IPv6 chain and IPv6 enabled",
			enableInboundIPv6: true,
			errorExpected:     true,
			setup: func(t *testing.T, iptConfigurator *IptablesConfigurator) {
				cmd := exec.Command(iptConfigurator.ipt6V.DetectedBinary,
					"-t", "nat",
					"-N", "AGENTIO_INBOUND")
				require.NoError(t, cmd.Run())
				cmd = exec.Command(iptConfigurator.ipt6V.DetectedBinary,
					"-t", "nat", "-A", "AGENTIO_INBOUND",
					"-p", "udp", "--dport", "123", "-j", "RETURN")
				require.NoError(t, cmd.Run())
			},
			check: func(t *testing.T, ext *dep.RealDependencies, iptConfigurator *IptablesConfigurator, residueExists, deltaExists bool) {
				require.Equal(t, residueExists, true)
				require.Equal(t, deltaExists, true)

				output, err := ext.Run(scope, true, constants.IPTablesSave, &iptConfigurator.iptV, nil)
				require.NoError(t, err)
				require.Equal(
					t,
					len(HasAgentioLeftovers(iptConfigurator.ruleBuilder.GetStateFromSave(output.String()))) > 0,
					true,
				)
				output, err = ext.Run(scope, true, constants.IPTablesSave, &iptConfigurator.ipt6V, nil)
				require.NoError(t, err)
				require.Equal(
					t,
					len(
						HasAgentioLeftovers(iptConfigurator.ruleBuilder.GetStateFromSave(output.String()))["nat"].Chains,
					) == 1,
					true,
				)
			},
			teardown: func(t *testing.T, iptConfigurator *IptablesConfigurator) {
				require.NoError(
					t,
					exec.Command(iptConfigurator.ipt6V.DetectedBinary, "-t", "nat", "-F", "AGENTIO_INBOUND").Run(),
				)
				require.NoError(
					t,
					exec.Command(iptConfigurator.ipt6V.DetectedBinary, "-t", "nat", "-X", "AGENTIO_INBOUND").Run(),
				)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			setup(t)
			ext := &dep.RealDependencies{
				UsePodScopedXtablesLock: false,
				NetworkNamespace:        "",
			}
			cfg := constructTestConfig()
			scope := log
			cfg.EnableIPv6 = tc.enableInboundIPv6
			cfg.ProxyUID = "0"
			cfg.ProxyGID = "0"
			if cfg.OwnerGroupsExclude != "" {
				cfg.OwnerGroupsInclude = "0"
			}
			if cfg.OwnerGroupsInclude != "" {
				cfg.OwnerGroupsInclude = "0"
			}

			iptConfigurator, err := NewIptablesConfigurator(cfg, ext)
			require.NoError(t, err)

			defer func() {
				tc.teardown(t, iptConfigurator)
				cfg.CleanupOnly = true
				cleanupConfigurator, err := NewIptablesConfigurator(cfg, ext)
				require.NoError(t, err)
				require.NoError(t, cleanupConfigurator.Run())

				residueExists, deltaExists := VerifyIptablesState(
					scope,
					cleanupConfigurator.ext,
					cleanupConfigurator.ruleBuilder,
					&cleanupConfigurator.iptV,
					&cleanupConfigurator.ipt6V,
				)
				require.Equal(t, residueExists, false)
				require.Equal(t, deltaExists, true)
			}()

			tc.setup(t, iptConfigurator)
			if tc.errorExpected {
				require.Error(t, iptConfigurator.Run())
			} else {
				require.NoError(t, iptConfigurator.Run())
			}
			residueExists, deltaExists := VerifyIptablesState(
				scope,
				iptConfigurator.ext,
				iptConfigurator.ruleBuilder,
				&iptConfigurator.iptV,
				&iptConfigurator.ipt6V,
			)
			tc.check(t, ext, iptConfigurator, residueExists, deltaExists)
		})
	}
}
