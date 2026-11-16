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

const defaultCredentialProviderName = "agentio-default-credential-provider"

// DefaultEPEConfig assembles the lowest layer from environment-configured providers.
func DefaultEPEConfig() (*configv1.EPEConfig, error) {
	provider, err := credentialProviderFromEnv()
	if err != nil {
		return nil, err
	}
	cfg := &configv1.EPEConfig{}
	if provider != nil {
		cfg.ExtensionProviders = []*configv1.ExtensionProvider{{
			Name:     defaultCredentialProviderName,
			Provider: &configv1.ExtensionProvider_CredentialProvider{CredentialProvider: provider},
		}}
		cfg.DefaultProviders = &configv1.DefaultExtensionProviders{CredentialProvider: defaultCredentialProviderName}
	}
	return cfg, extensionprovider.Validate(cfg)
}
