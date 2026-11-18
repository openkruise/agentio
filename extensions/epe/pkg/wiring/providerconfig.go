// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package wiring

import (
	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/extensionprovider"
)

// DefaultProviderConfig assembles EPE's defaults from environment-configured providers.
func DefaultProviderConfig() (*configv1.AgentioConfig, error) {
	provider, err := credentialProviderFromEnv()
	if err != nil {
		return nil, err
	}
	cfg := &configv1.AgentioConfig{}
	if provider != nil {
		cfg.ExtensionProviders = []*configv1.ExtensionProvider{{
			Name:     configv1.EnvironmentCredentialProviderName,
			Provider: &configv1.ExtensionProvider_CredentialProvider{CredentialProvider: provider},
		}}
		cfg.DefaultProviders = &configv1.DefaultExtensionProviders{
			CredentialProvider: configv1.EnvironmentCredentialProviderName,
		}
	}
	return cfg, extensionprovider.Validate(cfg)
}
