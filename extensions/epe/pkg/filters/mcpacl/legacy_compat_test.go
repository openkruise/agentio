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

// Test shims that adapt the plugin-shaped decision tests to the filter
// contract.
package mcpacl

import (
	"context"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
)

type legacyAction int

const (
	legacyContinue legacyAction = iota
	legacyImmediate
	legacyRecord
)

type legacyResult struct {
	Action    legacyAction
	NeedsBody bool
}

type legacyRctx struct {
	Request     httpreq.HTTPRequest
	RequestBody []byte
}

func makeRctx(contentType string) *legacyRctx {
	headers := map[string]string{
		// Default to a supported MCP protocol version so enforcement-path tests
		// pass the version gate. Version-specific tests override this key.
		"mcp-protocol-version": "2025-11-25",
	}
	if contentType != "" {
		headers["content-type"] = contentType
	}
	return &legacyRctx{
		Request: httpreq.HTTPRequest{
			Host:    "mcp.example.com",
			Headers: headers,
		},
	}
}

// legacyRule is the per-rule carrier passed to the shim methods; a local
// type so the tests do not name the policy layer.
type legacyRule struct {
	Name   string
	Policy *Config
}

func makeRule(policy *Config) *legacyRule {
	return &legacyRule{Name: "test-rule", Policy: policy}
}

func configOf(policy *Config) Config { return *policy }

type legacyPlugin struct{}

func newLegacyPlugin() *legacyPlugin { return &legacyPlugin{} }

// OnRequestHeaders mirrors "payload presence + unconditional body need":
// rules without a policy do not mount this filter (payloadsFor omits the
// key); everything else asks for the body regardless of the version header.
func (p *legacyPlugin) OnRequestHeaders(_ context.Context, _ *legacyRctx, _ any, rule *legacyRule) (legacyResult, error) {
	if rule.Policy == nil {
		return legacyResult{Action: legacyContinue}, nil
	}
	return legacyResult{Action: legacyRecord, NeedsBody: true}, nil
}

// Finalize drives the filter body phase, mapping Stop onto legacyImmediate.
func (p *legacyPlugin) Finalize(ctx context.Context, rctx *legacyRctx, _ any, rule *legacyRule) (legacyResult, error) {
	f := New(filter.RuleConfig[Config]{
		ID:  filter.UnitID{Scope: "test/p", Name: rule.Name},
		Cfg: configOf(rule.Policy),
	})
	st := &filter.Stream{RequestContext: filter.RequestContext{Request: rctx.Request}}
	act, err := f.OnRequestBody(ctx, st, filter.Body{Bytes: rctx.RequestBody, Complete: true})
	if err != nil {
		return legacyResult{}, err
	}
	if act.Kind() == filter.KindStop {
		return legacyResult{Action: legacyImmediate}, nil
	}
	return legacyResult{Action: legacyContinue}, nil
}
