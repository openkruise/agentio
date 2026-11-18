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

package config

import (
	"fmt"

	"google.golang.org/protobuf/proto"

	configv1 "github.com/openkruise/agentio/api/config/v1"
)

// ApplyAgentioConfig overlays a layer using field replacement, except that
// non-empty provider lists merge by name. Each matching provider is replaced
// in full, including its type and TLS settings.
func ApplyAgentioConfig(content string, base *configv1.AgentioConfig) (*configv1.AgentioConfig, error) {
	next, err := Apply(content, base)
	if err != nil || len(next.GetExtensionProviders()) == 0 {
		return next, err
	}
	// Apply has already inherited an omitted or null list and cleared an
	// explicitly empty list. Merging an inherited list back by name is a no-op.
	providers := make([]*configv1.ExtensionProvider, 0, len(base.GetExtensionProviders()))
	positions := make(map[string]int, len(base.GetExtensionProviders()))
	for i, provider := range base.GetExtensionProviders() {
		positions[provider.GetName()] = i
		providers = append(providers, proto.CloneOf(provider))
	}
	seen := make(map[string]bool, len(next.ExtensionProviders))
	for _, provider := range next.ExtensionProviders {
		name := provider.GetName()
		if seen[name] {
			return nil, fmt.Errorf("duplicate extension provider %q", name)
		}
		seen[name] = true
		if i, found := positions[name]; found {
			providers[i] = provider
		} else {
			providers = append(providers, provider)
		}
	}
	next.ExtensionProviders = providers
	return next, nil
}
