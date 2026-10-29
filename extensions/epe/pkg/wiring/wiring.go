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

// Package wiring assembles the production filter chain. It is the
// composition root of the engine: the one engine-adjacent package allowed
// to know the policy API and concrete filter dependencies. The engine
// itself (pkg/engine) stays free of both — enforced by the arch guard
// tests in this package.
package wiring

import (
	"fmt"
	"time"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/extensionprovider"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/block"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/bypass"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/headermutation"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/httpcallout"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/mcpacl"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/oauth2"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/tokentransform"
	_ "github.com/openkruise/agentio/extensions/epe/pkg/filters/tokentransform/signers/aliyun" // registers the AliyunSTS signer
)

// Deps carries what plugin builders may need.
type Deps struct {
	// Providers resolves the effective EPEConfig. BuildFilters requires a registry.
	Providers *extensionprovider.Registry
	// Secrets supplies cached credentials within the configured watch scope.
	Secrets tokentransform.CredentialSource
}

// BuildFilters returns the production action order used inside every rule.
// Rules themselves always run in policy order. Bypass precedes block so a
// malformed rule carrying both bypasses; body enforcement follows the cheap
// header-only actions. Generic header mutations precede credential transforms
// so a credential-derived value wins if two policy sources target the same
// header. OAuth endpoint handling has its own filter; the remaining credential
// transformations use the tokentransform signer registry. Invalid configuration
// fails closed at projection time.
// HTTP callouts run after header mutation and before credential transformations.
func BuildFilters(deps Deps) ([]filter.Registration, error) {
	if deps.Providers == nil {
		return nil, fmt.Errorf("provider registry is required")
	}
	return buildFilters(deps)
}

// BuildValidationFilters exposes the production parsers without runtime services.
// Callers may use Parse/Project, but must not execute the returned filters.
func BuildValidationFilters() ([]filter.Registration, error) {
	return buildFilters(Deps{})
}

func buildFilters(deps Deps) ([]filter.Registration, error) {
	ttDeps := tokentransform.Deps{
		SecretSource:   deps.Secrets,
		Limiter:        tokentransform.NewLimiter(time.Minute, nil),
		ProviderSource: deps.Providers,
	}
	definitions := []filter.Definition{
		bypass.Definition(),
		block.Definition(),
		mcpacl.Definition(),
		headermutation.Definition(),
		httpcallout.NewDefinition(httpcallout.Deps{Client: httpcallout.NewHTTPClient(deps.Providers)}),
		tokentransform.NewDefinition(ttDeps),
		oauth2.Definition(deps.Providers),
	}
	return filter.Build(definitions...)
}
