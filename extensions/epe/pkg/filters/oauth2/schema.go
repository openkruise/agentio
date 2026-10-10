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

package oauth2

import (
	"encoding/json"
	"fmt"

	"github.com/openkruise/agentio/extensions/epe/pkg/credential"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

// Definition returns an OAuth filter with its own payload schema. Production
// registration and SecurityProfile projection are separate integration steps.
func Definition(source Source) filter.Definition {
	return filter.Define(filter.Descriptor[Config]{
		Name:    FilterName,
		Phases:  filter.PhaseRequestHeaders | filter.PhaseRequestBody,
		OnError: filter.Always[Config](filter.FailClosed),
		New: func(rule filter.RuleConfig[Config]) filter.Filter {
			return &Filter{cfg: rule.Cfg, source: source}
		},
	}, parse)
}

func parse(raw json.RawMessage) (Config, error) {
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return Config{}, fmt.Errorf("decode OAuth payload: %w", err)
	}
	if cfg.CredentialProviderName == "" {
		return Config{}, fmt.Errorf("OAuth requires a credential provider name")
	}
	switch cfg.Operation {
	case credential.OAuth2OperationDeviceAuthorization, credential.OAuth2OperationResource:
		if len(cfg.AllowedGrantTypes) != 0 || (cfg.CustomResponse != nil && cfg.CustomResponse.Success != nil) {
			return Config{}, fmt.Errorf("allowedGrantTypes and success extensions require the Token operation")
		}
	case credential.OAuth2OperationToken:
	default:
		return Config{}, fmt.Errorf("unsupported OAuth operation %q", cfg.Operation)
	}
	if cfg.Operation != credential.OAuth2OperationDeviceAuthorization && cfg.AllowAuthorizedSession != nil {
		return Config{}, fmt.Errorf("allowAuthorizedSession requires the DeviceAuthorization operation")
	}
	if err := validateResponse(cfg.CustomResponse); err != nil {
		return Config{}, err
	}
	seen := make(map[string]bool)
	for _, grantType := range cfg.AllowedGrantTypes {
		if grantType == "" || seen[grantType] {
			return Config{}, fmt.Errorf("allowedGrantTypes requires unique non-empty grant types")
		}
		if grantType == credential.OAuth2GrantPassword {
			return Config{}, fmt.Errorf("the password grant is prohibited by RFC 9700")
		}
		seen[grantType] = true
	}
	return cfg, nil
}
