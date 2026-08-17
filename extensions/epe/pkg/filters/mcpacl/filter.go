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

// Package mcpacl enforces MCP tool ACLs. For MCP 2026-07-28 it uses the
// mandatory Mcp-Method and Mcp-Name headers for a fast path: non-governed
// methods pass without body buffering, and a header-derived deny short-
// circuits before the body arrives. An allow still needs the body to verify
// header/body consistency. For older revisions the method is only knowable
// from the JSON-RPC body, so the body is always requested.
package mcpacl

import (
	"context"

	log "sigs.k8s.io/controller-runtime/pkg/log"

	"istio.io/istio/extensions/epe/pkg/engine/filter"
)

// FilterName is the registry name used for attribution.
const FilterName = "mcpacl"

// actionAllow is the only value that admits a governed call. Every other
// value — actionDeny, a differently-cased or misspelled verb, an un-defaulted
// empty string — denies. Spelling the permissive value exactly, rather than the
// restrictive one, is what keeps an unrecognized action from silently disabling
// the rule it was written for.
const (
	actionAllow = "allow"
	actionDeny  = "deny"
)

// defaultDenyStatus is used when the policy does not configure a deny
// response status.
const defaultDenyStatus = 403

// Config is the filter's decoded form of an mcpacl policy payload.
type Config struct {
	DefaultAction            string
	UnsupportedVersionAction string
	// DenyStatus 0 means the default 403.
	DenyStatus int32
	DenyBody   string
	Rules      []RuleEntry
}

// RuleEntry is one policy rule.
type RuleEntry struct {
	Method    string
	ToolNames []string
	Action    string
}

// evaluate walks the policy rules for a decision; unmatched falls back to
// DefaultAction. The returned value is only ever honoured as an allow when it
// is exactly actionAllow — see the call site.
func evaluate(cfg Config, method, toolName string) string {
	for _, rule := range cfg.Rules {
		if rule.Method != method {
			continue
		}
		if len(rule.ToolNames) == 0 {
			return rule.Action
		}
		if toolName == "" {
			continue
		}
		if contains(rule.ToolNames, toolName) {
			return rule.Action
		}
	}
	return cfg.DefaultAction
}

func contains(names []string, target string) bool {
	for _, n := range names {
		if n == target {
			return true
		}
	}
	return false
}

func denyReply(cfg Config) filter.Reply {
	status := int(cfg.DenyStatus)
	if status == 0 {
		status = defaultDenyStatus
	}
	var body []byte
	if cfg.DenyBody != "" {
		body = []byte(cfg.DenyBody)
	}
	return filter.Reply{Status: status, Body: body}
}

// applyDefaultAction decides a request the ACL could not attribute to a tool by
// the policy's defaultAction, honoured as an allow only when it is exactly
// actionAllow. That is the same polarity the evaluate call site uses, so an
// action value this build does not recognise denies rather than admits.
//
// Its callers are the cases where the ACL cannot name what the upstream would
// execute: a batch or otherwise unreadable body, and a governed call with no
// readable tool name. They route here rather than denying outright to keep the
// verdict operators configure in defaultAction authoritative, matching
// traffix-extension.
//
// The residual risk is deliberate and belongs in the release notes: under
// defaultAction: allow, a body whose first JSON document is not the whole body
// is admitted even though a lenient upstream may go on to execute a second,
// uninspected tools/call. Whitelist policies (defaultAction: deny) are
// unaffected.
func applyDefaultAction(cfg Config) filter.Action {
	if cfg.DefaultAction == actionAllow {
		return filter.Continue()
	}
	return filter.Stop(denyReply(cfg))
}

// Filter evaluates one rule's MCP tool policy.
type Filter struct {
	filter.PassThrough
	rule filter.RuleConfig[Config]
}

func New(rule filter.RuleConfig[Config]) filter.Filter { return &Filter{rule: rule} }

// OnRequestHeaders decides whether the body phase is needed. For MCP
// 2026-07-28, the mandatory Mcp-Method and Mcp-Name headers enable a fast
// path: non-governed methods pass through without body buffering, and a
// header-derived deny short-circuits before the body arrives. An allow
// still needs the body to verify header/body consistency (anti-smuggling).
// For older revisions the method is only knowable from the JSON-RPC body.
func (f *Filter) OnRequestHeaders(ctx context.Context, st *filter.Stream) (filter.Action, error) {
	version := st.Request.Headers[mcpProtocolVersionHeader]

	// Fast path for MCP 2026-07-28: the spec makes Mcp-Method mandatory on
	// every request and Mcp-Name mandatory on tools/call, enabling gateway-
	// level decisions without buffering the JSON-RPC body.
	if version == gaMCPVersion {
		method := st.Request.Headers[mcpMethodHeader]
		if method != "" {
			// Non-governed method: pass through immediately — no body needed.
			// The MCP 2026-07-28 spec requires servers to reject requests
			// where Mcp-Method does not match the body's method, so a
			// compliant server will not execute a tools/call hidden behind
			// a tools/list header. Operators who cannot trust upstream
			// compliance should use a whitelist policy (defaultAction: deny).
			if !governedMethods[method] {
				return filter.Continue(), nil
			}
			// Governed method (tools/call): evaluate from headers. A deny is
			// safe to make immediately — deny is the safe-fail direction, and
			// a client sending contradictory headers/body is suspicious. An
			// allow still needs the body to verify the header-derived tool
			// name matches the JSON-RPC payload.
			toolName := st.Request.Headers[mcpNameHeader]
			if toolName != "" {
				// Decode Base64 sentinel encoding (MCP 2026-07-28 SEP-2243)
				// for non-ASCII tool names before evaluation.
				if decoded, ok := decodeMcpHeaderValue(toolName); ok {
					toolName = decoded
				} else {
					// Invalid encoding: cannot evaluate from header, fall back to body.
					return filter.NeedBody(), nil
				}
				rc := f.rule
				if decision := evaluate(rc.Cfg, method, toolName); decision != actionAllow {
					log.FromContext(ctx).Info("MCP tool denied by header fast-path",
						"rule", rc.ID.Name, "method", method, "toolName", toolName,
						"decision", decision, "pod", st.Peer.Pod.String())
					return filter.Stop(denyReply(rc.Cfg)), nil
				}
				// Allow: need body to verify header/body consistency.
				return filter.NeedBody(), nil
			}
		}
		// Absent or incomplete headers: fall back to body parsing.
		return filter.NeedBody(), nil
	}

	// Pre-2026-07-28: method is only knowable from the JSON-RPC body.
	return filter.NeedBody(), nil
}

// OnRequestBody applies the rule's policy to the single JSON-RPC message
// carried in the body; only an exact allow admits a governed call.
func (f *Filter) OnRequestBody(ctx context.Context, st *filter.Stream, body filter.Body) (filter.Action, error) {
	read := readBody(st.Request.Headers, body.Bytes)

	// A body the ACL cannot read as one JSON-RPC message — a batch, trailing
	// content after the first document, or an encoding this filter cannot undo —
	// hides the tool name while staying actionable by a lenient upstream parser,
	// so the policy's defaultAction decides (see applyDefaultAction). Evaluated
	// before the version header so the outcome cannot be changed through it.
	if read.status == statusUnreadable {
		rc := f.rule
		log.FromContext(ctx).Info("MCP request body is not a readable single JSON-RPC message, applying defaultAction",
			"rule", rc.ID.Name,
			"defaultAction", rc.Cfg.DefaultAction,
			"pod", st.Peer.Pod.String())
		return applyDefaultAction(rc.Cfg), nil
	}

	// Only tool invocations are governed; a body with no message at all, and
	// any other method (lifecycle, tools/list, resources/*, prompts/*,
	// tasks/*, ...) passes.
	if read.status == statusAbsent || !governedMethods[read.method] {
		return filter.Continue(), nil
	}
	method, toolName := read.method, read.tool

	version := st.Request.Headers[mcpProtocolVersionHeader]
	rc := f.rule
	cfg := rc.Cfg
	// A tool call MUST come from a supported protocol version unless
	// the policy opts out via unsupportedVersionAction=passthrough.
	if !supportedMCPVersions[version] {
		if cfg.UnsupportedVersionAction == "passthrough" {
			log.FromContext(ctx).Info("MCP tool call with unsupported/absent protocol version, passing through per policy",
				"rule", rc.ID.Name, "version", version, "pod", st.Peer.Pod.String())
			return filter.Continue(), nil
		}
		log.FromContext(ctx).Info("MCP tool call with unsupported/absent protocol version, denying",
			"rule", rc.ID.Name, "version", version, "pod", st.Peer.Pod.String())
		return filter.Stop(denyReply(cfg)), nil
	}

	// For 2026-07-28, verify header/body consistency. We only reach the body
	// phase when OnRequestHeaders returned NeedBody — i.e. the headers were
	// absent or the header-based evaluation returned allow. If the mandatory
	// headers are present and match the body, the allow is confirmed without
	// re-evaluating. If they mismatch, fall back to body-based evaluation
	// (the body is the source of truth for what upstream will execute).
	if version == gaMCPVersion {
		hMethod := st.Request.Headers[mcpMethodHeader]
		hName := st.Request.Headers[mcpNameHeader]
		if hName != "" {
			// Decode Base64 sentinel encoding before comparing to the body.
			// If decoding fails, hName stays raw and won't match the body's
			// tool name — triggering a mismatch fallback to body evaluation.
			if decoded, ok := decodeMcpHeaderValue(hName); ok {
				hName = decoded
			}
		}
		if hMethod != "" && hName != "" && hMethod == method && read.hasTool && hName == toolName {
			// Headers fully match the body. OnRequestHeaders only let us
			// through when the header-based evaluation was an allow, so the
			// allow is confirmed.
			return filter.Continue(), nil
		}
		if hMethod != "" || hName != "" {
			log.FromContext(ctx).Info("MCP header/body mismatch, falling back to body evaluation",
				"rule", rc.ID.Name,
				"headerMethod", hMethod, "bodyMethod", method,
				"headerTool", hName, "bodyTool", toolName,
				"pod", st.Peer.Pod.String())
		}
		// Fall through to body-based evaluation.
	}

	// A governed call whose tool name is absent or not a string cannot be
	// attributed to a tool-scoped rule, so the policy's defaultAction decides —
	// the same fallback evaluate reaches when no rule matches a named tool.
	if !read.hasTool {
		log.FromContext(ctx).Info("MCP tool call without a readable tool name, applying defaultAction",
			"rule", rc.ID.Name, "method", method,
			"defaultAction", cfg.DefaultAction, "pod", st.Peer.Pod.String())
		return applyDefaultAction(cfg), nil
	}

	if decision := evaluate(cfg, method, toolName); decision != actionAllow {
		log.FromContext(ctx).Info("MCP tool denied by policy",
			"rule", rc.ID.Name, "method", method, "toolName", toolName,
			"decision", decision, "pod", st.Peer.Pod.String())
		return filter.Stop(denyReply(cfg)), nil
	}
	return filter.Continue(), nil
}

// Descriptor declares mcpacl's phases and failure policy.
func Descriptor() filter.Descriptor[Config] {
	return filter.Descriptor[Config]{
		Name:    FilterName,
		Phases:  filter.PhaseRequestHeaders | filter.PhaseRequestBody,
		OnError: filter.Always[Config](filter.FailClosed),
		New:     New,
	}
}
