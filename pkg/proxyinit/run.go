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
	"errors"

	"github.com/openkruise/agentio/pkg/proxyinit/config"
	"github.com/openkruise/agentio/pkg/proxyinit/iptables/capture"
	dep "github.com/openkruise/agentio/pkg/proxyinit/iptables/dependencies"
	"github.com/openkruise/agentio/pkg/proxyinit/iptables/validation"
	"github.com/openkruise/agentio/pkg/proxyinit/nftables"
)

// ErrValidation identifies the failure recognized by the CNI repair controller.
var ErrValidation = errors.New("proxy-init validation failed")

// Run applies a validated configuration in the workload's network namespace.
func Run(ctx context.Context, cfg *config.Config) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	if !cfg.SkipRuleApply {
		if cfg.NativeNftables {
			if err := nftables.ProgramNftables(cfg); err != nil {
				return err
			}
		} else {
			var ext dep.Dependencies = &dep.RealDependencies{
				UsePodScopedXtablesLock: cfg.HostFilesystemPodNetwork,
				NetworkNamespace:        cfg.NetworkNamespace,
				ForceIptablesBinary:     cfg.ForceIptablesBinary,
			}
			if cfg.DryRun {
				ext = &dep.DependenciesStub{}
			}
			configurator, err := capture.NewIptablesConfigurator(cfg, ext)
			if err != nil {
				return err
			}
			if err := configurator.Run(); err != nil {
				return err
			}
		}
	}
	if cfg.RunValidation {
		if err := validation.NewValidator(cfg).Run(); err != nil {
			return ErrValidation
		}
	}
	return nil
}
