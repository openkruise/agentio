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

package kubernetes

import (
	"fmt"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/model"
)

const (
	baseConfigMapName    = "agentio-config"
	primaryConfigMapName = "agentio-config-primary"
)

// AgentioConfigMapOptions identifies the ordered Kubernetes sources for
// Agentio configuration. PrimaryName may be empty to disable the overlay.
type AgentioConfigMapOptions struct {
	BaseName    string
	PrimaryName string
}

func defaultAgentioConfigMapOptions() AgentioConfigMapOptions {
	return AgentioConfigMapOptions{
		BaseName:    baseConfigMapName,
		PrimaryName: primaryConfigMapName,
	}
}

func defaultAgentioConfiguration() *configv1.AgentioConfig {
	return &configv1.AgentioConfig{
		SandboxIgnoredLabels: []string{
			"agentio.kruise.io/dataplane-mode",
			"pod-template-hash",
			"pod-template-generation",
			"controller-revision-hash",
		},
	}
}

func validateAgentioConfig(value *configv1.AgentioConfig) error {
	if err := model.ValidateExtProcTLS(value.GetSandboxExtProc().GetTls()); err != nil {
		return err
	}
	if err := normalizeEgressServiceEntries(value.GetEgressGateways()); err != nil {
		return err
	}
	for i, gateway := range value.GetEgressGateways() {
		if err := model.ValidateExtProcTLS(gateway.GetExtProc().GetTls()); err != nil {
			return fmt.Errorf("egressGateways[%d].%w", i, err)
		}
		if err := model.ValidateUpstreamTLS(gateway.GetUpstreamTls()); err != nil {
			return fmt.Errorf("egressGateways[%d].%w", i, err)
		}
		if err := model.ValidateAccessLogFormat(gateway.GetAccessLogFormat()); err != nil {
			return fmt.Errorf("egressGateways[%d].%w", i, err)
		}
	}
	return nil
}
