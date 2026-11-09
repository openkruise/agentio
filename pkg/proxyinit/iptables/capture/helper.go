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
	"fmt"
	"strings"

	agentlog "github.com/openkruise/agentio/pkg/log"

	"github.com/openkruise/agentio/pkg/proxyinit/iptables/builder"
	"github.com/openkruise/agentio/pkg/proxyinit/iptables/constants"
	dep "github.com/openkruise/agentio/pkg/proxyinit/iptables/dependencies"
)

func CombineMatchers(values []string, matcher func(value string) []string) []string {
	matchers := make([][]string, 0, len(values))
	for _, value := range values {
		matchers = append(matchers, matcher(value))
	}
	return Flatten(matchers...)
}

func Flatten(lists ...[]string) []string {
	var result []string
	for _, list := range lists {
		result = append(result, list...)
	}
	return result
}

// VerifyIptablesState function verifies the current iptables state against the expected state.
// The current state is considered equal to the expected state if the following three conditions are met:
//   - Every AGENTIO_* chain in the expected state must also exist in the current state.
//   - Every AGENTIO_* chain must have the same number of elements in both the current and expected state.
//   - Every rule in the expected state (whether it is in an AGENTIO or non-AGENTIO chain) must also exist in the current state.
//     The verification is performed by using "iptables -C" on the rule produced by our iptables builder. No comparison of the parsed rules is done.
//
// Note: The order of the rules is not checked and is not used to determine the equivalence of the two states.
// The function returns two boolean values, the first one indicates whether residues exist,
// and the second one indicates whether differences were found between the current and expected state.

func VerifyIptablesState(
	log *agentlog.Logger,
	ext dep.Dependencies,
	ruleBuilder *builder.IptablesRuleBuilder,
	iptVer, ipt6Ver *dep.IptablesVersion,
) (bool, bool) {
	type ipFamilyResult struct {
		residueExists       bool // Indicates if iptables residues from previous executions are found
		deltaExists         bool // Indicates if the existing rules are different from the expected ones.
		plannedAgentioRules bool // Indicates if Agentio rules are planned
		versionName         string
	}

	var results []ipFamilyResult
	isEmptyState := func(state map[string]map[string][]string) bool {
		for _, chains := range state {
			if len(chains) > 0 {
				return false
			}
		}
		return true
	}

	for _, ipCfg := range []struct {
		ver         *dep.IptablesVersion
		expected    string
		checkRules  [][]string
		versionName string
	}{
		{iptVer, ruleBuilder.BuildV4Restore(), ruleBuilder.BuildCheckV4(), "IPv4"},
		{ipt6Ver, ruleBuilder.BuildV6Restore(), ruleBuilder.BuildCheckV6(), "IPv6"},
	} {
		if ipCfg.ver == nil {
			results = append(results, ipFamilyResult{})
			continue
		}
		curResidueExists := false
		curDeltaExists := false
		output, err := ext.Run(log, true, constants.IPTablesSave, ipCfg.ver, nil)
		expectedState := ruleBuilder.GetStateFromSave(ipCfg.expected)
		emptyExpectedState := isEmptyState(expectedState)

		if err != nil {
			log.Warn("iptables-save failed; assuming clean state", "version", ipCfg.versionName, "error", err)
			curResidueExists = false
			if !emptyExpectedState {
				curDeltaExists = true
			}
		} else {
			currentState := ruleBuilder.GetStateFromSave(output.String())
			log.Debug(fmt.Sprintf("[%s] Current iptables state: %#v", ipCfg.versionName, currentState))
			log.Debug(fmt.Sprintf("[%s] Expected iptables state: %#v", ipCfg.versionName, expectedState))

			curResidueExists = !isEmptyState(currentState)
			if !curResidueExists && !emptyExpectedState {
				curDeltaExists = true
			} else if curResidueExists {
				deltaFound := false
				for table, chains := range expectedState {
					_, ok := currentState[table]
					if !ok {
						deltaFound = true
						log.Debug(
							fmt.Sprintf("[%s] Can't find expected table %s in current state", ipCfg.versionName, table),
						)
						break
					}
					for chain, rules := range chains {
						currentRules, ok := currentState[table][chain]
						if !ok || (strings.HasPrefix(chain, "AGENTIO_") && len(rules) != len(currentRules)) {
							deltaFound = true
							log.Debug(
								fmt.Sprintf(
									"[%s] Mismatching number of rules in chain %s (table: %s) between current and expected state",
									ipCfg.versionName,
									chain,
									table,
								),
							)
							break
						}
					}
				}
				if !deltaFound {
					for table, chains := range currentState {
						for chain := range chains {
							if strings.HasPrefix(chain, "AGENTIO_") {
								_, ok := expectedState[table][chain]
								if !ok {
									deltaFound = true
									log.Debug(
										fmt.Sprintf(
											"[%s] Found chain %s (table: %s) in current state which is missing in expected state",
											ipCfg.versionName,
											chain,
											table,
										),
									)
									break
								}
							}
						}
					}
				}
				if !deltaFound {
					for _, cmd := range ipCfg.checkRules {
						if _, err := ext.Run(log, true, constants.IPTables, ipCfg.ver, nil, cmd...); err != nil {
							deltaFound = true
							log.Debug(fmt.Sprintf("[%s] iptables check rules failed", ipCfg.versionName))
							break
						}
					}
				}
				curDeltaExists = deltaFound
			}
		}
		results = append(
			results,
			ipFamilyResult{curResidueExists, curDeltaExists, !emptyExpectedState, ipCfg.versionName},
		)
	}
	log.Debug(fmt.Sprintf("iptables state verification summary: %+v", results))
	var globalResidueExists, globalDeltaExists bool
	for _, res := range results {
		globalDeltaExists = globalDeltaExists || res.deltaExists
		if res.residueExists && res.plannedAgentioRules {
			globalResidueExists = true
		} else if res.residueExists {
			log.Info(fmt.Sprintf("Ignoring residues because no rules are planned for %s", res.versionName))
		}
	}

	if !globalResidueExists {
		log.Info("Clean-state detected, new iptables are needed")
		return false, true
	}

	if globalDeltaExists {
		log.Info("Found residues of old iptables rules/chains, reconciliation is recommended")
	} else {
		log.Info("Found compatible residues of old iptables rules/chains, reconciliation not needed")
	}

	return globalResidueExists, globalDeltaExists
}

// HasAgentioLeftovers checks the given iptables state for any chains or rules related to Agentio.
// It scans the provided map of tables, chains, and rules to identify any chains that start with the "AGENTIO_" prefix,
// as well as any rules that involve Agentio-specific jumps.
// The function returns a map where the keys are the tables, and the values are structs containing the leftover
// "AGENTIO_" chains and jump rules for each table. Only tables with Agentio-related leftovers are included in the result.
func HasAgentioLeftovers(state map[string]map[string][]string) map[string]struct {
	Chains []string
	Rules  []string
} {
	output := make(map[string]struct {
		Chains []string
		Rules  []string
	})
	for table, chains := range state {
		agentioChains := []string{}
		agentioJumps := []string{}
		for chain, rules := range chains {
			if strings.HasPrefix(chain, "AGENTIO_") {
				agentioChains = append(agentioChains, chain)
			}
			for _, rule := range rules {
				if isAgentioJump(rule) {
					agentioJumps = append(agentioJumps, rule)
				}
			}
		}
		if len(agentioChains) != 0 || len(agentioJumps) != 0 {
			output[table] = struct {
				Chains []string
				Rules  []string
			}{
				Chains: agentioChains,
				Rules:  agentioJumps,
			}
		}
	}
	return output
}

// isAgentioJump checks if the given rule is a jump to an Agentio chain
func isAgentioJump(rule string) bool {
	// Split the rule into fields
	fields := strings.Fields(rule)
	for i, field := range fields {
		// Check for --jump or -j
		if field == "--jump" || field == "-j" {
			// Check if there's a next field (the target)
			if i+1 < len(fields) {
				target := strings.Trim(fields[i+1], "'\"")
				// Check if the target starts with AGENTIO_
				return strings.HasPrefix(target, "AGENTIO_")
			}
		}
	}
	return false
}
