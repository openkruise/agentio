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
package tokentransform

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	log "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/logging"
)

// Filter evaluates one rule's token transformation.
type Filter struct {
	filter.PassThrough
	sources Sources
	signers map[string]Signer
	limiter *Limiter
	rule    filter.RuleConfig[Config]
	pending bool

	preparedSignerCfg any
	hasPreparedCfg    bool
}

// NewDescriptor declares tokentransform to the framework. The signer
// registry is snapshotted per chain build so later registrations cannot
// change an already-built chain.
func NewDescriptor(deps Deps) filter.Descriptor[Config] {
	return filter.Descriptor[Config]{
		Name:   FilterName,
		Phases: filter.PhaseRequestHeaders | filter.PhaseRequestBody,
		OnError: func(cfg Config) filter.FailurePolicy {
			if cfg.FailBlock {
				return filter.FailClosed
			}
			return filter.FailOpen
		},
		New: func(rule filter.RuleConfig[Config]) filter.Filter {
			return &Filter{
				sources: Sources{
					Secret:   NewSecretSource(deps.Kube),
					Provider: deps.ProviderSource,
				},
				signers: signerMap(),
				limiter: deps.Limiter,
				rule:    rule,
			}
		},
	}
}

// OnRequestHeaders evaluates this rule and either transforms, defers for a
// body, blocks, or continues to the next rule.
func (f *Filter) OnRequestHeaders(ctx context.Context, st *filter.Stream) (filter.Action, error) {
	// CONNECT headers are consumed by the explicit proxy; the target server
	// only sees protocol bytes sent after the proxy establishes the tunnel.
	// Applying a target TokenTransform here would therefore disclose the
	// credential to the proxy without authenticating the target request. This
	// protocol mismatch is always denied, independent of FailStrategy.
	if strings.EqualFold(st.Request.Method, http.MethodConnect) {
		return filter.Stop(filter.Reply{
			Status: 403,
			Body:   []byte("tokentransform: unsupported for CONNECT"),
		}), nil
	}

	rc := &f.rule
	cfg := rc.Cfg

	signer, ok := f.signers[cfg.Type]
	if !ok {
		// Projection guarantees this cannot happen; fail closed if it does.
		return filter.Action{}, fmt.Errorf("no signer registered for type %q", cfg.Type)
	}

	signerCfg := cfg.SignerCfg
	if preparer, ok := signer.(SignerPreparer); ok {
		prepared, empty, err := preparer.Prepare(st, rc.Scope, signerCfg)
		if err != nil {
			return f.resolveFailure(ctx, cfg, st, err), nil
		}
		if empty {
			return filter.Continue(), nil
		}
		signerCfg = prepared
	}
	f.preparedSignerCfg = signerCfg
	f.hasPreparedCfg = true

	if cfg.Source.Kind == SourceKindProvider &&
		(st.Peer.Token == nil || st.Peer.Token.AccessToken == "") {
		return f.resolveFailure(ctx, cfg, st,
			fmt.Errorf("sandbox token unavailable for CredentialProvider")), nil
	}

	if bw, ok := signer.(BodyWanter); ok {
		needs, err := bw.WantsBody(st)
		if err != nil {
			return f.resolveFailure(ctx, cfg, st, err), nil
		}
		if needs {
			f.pending = true
			return filter.NeedBody(filter.CompleteBody), nil
		}
	}

	return f.complete(ctx, rc, st, nil)
}

// OnRequestBody finishes a body-deferred signature.
func (f *Filter) OnRequestBody(ctx context.Context, st *filter.Stream, body filter.Body) (filter.Action, error) {
	if !f.pending {
		return filter.Continue(), nil
	}
	return f.complete(ctx, &f.rule, st, body.Bytes)
}

// complete fetches the credential and signs for one claimed unit.
func (f *Filter) complete(
	ctx context.Context,
	rc *filter.RuleConfig[Config],
	st *filter.Stream,
	body []byte,
) (filter.Action, error) {
	cfg := rc.Cfg
	signer := f.signers[cfg.Type]

	cred, err := f.fetch(ctx, rc, st, signer.Kind())
	if err != nil {
		// A denied read is still a credential this rule cannot apply, so it
		// resolves through failStrategy like any other fetch failure — the CRD
		// defaults that to Block, and honouring it here is what keeps an RBAC
		// regression from silently forwarding requests with the client's own
		// credential. The rate-limited warning names the missing permission,
		// which a bare 403 does not.
		if errors.Is(err, ErrNoPermission) {
			f.warnNoPermission(ctx, rc, st, err)
		}
		return f.resolveFailure(ctx, cfg, st, err), nil
	}

	signerCfg := cfg.SignerCfg
	if f.hasPreparedCfg {
		signerCfg = f.preparedSignerCfg
	}
	muts, err := signer.Sign(ctx, st, body, rc.Scope, cred, signerCfg)
	if err != nil {
		return f.resolveFailure(ctx, cfg, st, err), nil
	}
	log.FromContext(ctx).V(logging.DEBUG).Info("token transformation applied",
		"type", cfg.Type, "pod", st.Peer.Pod.String())
	return filter.Continue(muts...), nil
}

// fetch resolves the rule's credential and sanitizes it. Every source funnels
// through here, so this is the one place that has to guarantee the value is
// usable as a header value — see Credential.sanitized.
func (f *Filter) fetch(
	ctx context.Context,
	rc *filter.RuleConfig[Config],
	st *filter.Stream,
	kind CredentialKind,
) (Credential, error) {
	cred, err := f.fetchFromSource(ctx, rc, st, kind)
	if err != nil {
		return Credential{}, err
	}
	return cred.sanitized()
}

// secretNamespace resolves the ref -> profile -> pod namespace fallback for
// Secret credential sources. One implementation so the no-permission warn can
// never name a different namespace than the fetch reads.
func secretNamespace(rc *filter.RuleConfig[Config], st *filter.Stream) string {
	if ns := rc.Cfg.Source.Namespace; ns != "" {
		return ns
	}
	if rc.Scope != nil {
		if ns := rc.Scope.Profile().Namespace; ns != "" {
			return ns
		}
	}
	return st.Peer.Pod.Namespace
}

// fetchFromSource reads the credential from the configured source, applying the
// ref -> profile -> pod namespace fallback for Secrets.
func (f *Filter) fetchFromSource(
	ctx context.Context,
	rc *filter.RuleConfig[Config],
	st *filter.Stream,
	kind CredentialKind,
) (Credential, error) {
	spec := rc.Cfg.Source
	switch spec.Kind {
	case SourceKindSecret:
		return f.sources.Secret.Fetch(ctx, Ref{Kind: kind, Name: spec.Name, Namespace: secretNamespace(rc, st)})
	case SourceKindProvider:
		if f.sources.Provider == nil {
			return Credential{}, fmt.Errorf("credential provider source is not configured")
		}
		extra, err := renderParams(spec.Parameters, rc.Scope)
		if err != nil {
			return Credential{}, err
		}
		return f.sources.Provider.Fetch(ctx, Ref{
			Kind:            kind,
			Name:            spec.Name,
			AccessToken:     st.Peer.Token.AccessToken,
			SandboxClientID: st.Peer.Token.SandboxClientID,
			ExtraMetadata:   extra,
		})
	default:
		return Credential{}, fmt.Errorf("unsupported credential source kind %q", spec.Kind)
	}
}

// resolveFailure runs a transformation failure through FailStrategy: Block
// stops the walk with a generic 403; otherwise the walk continues without
// this filter's mutations. Pre-transform and post-claim failures resolve
// identically — a claimed unit already had its chance either way.
func (f *Filter) resolveFailure(ctx context.Context, cfg Config, st *filter.Stream, err error) filter.Action {
	if cfg.FailBlock {
		log.FromContext(ctx).Error(err, "token transformation failed, blocking request", "pod", st.Peer.Pod.String())
		return blockReply(err)
	}
	log.FromContext(ctx).Error(err, "token transformation failed, passing through", "pod", st.Peer.Pod.String())
	return filter.Continue()
}

// blockReply denies the request without telling the caller why.
//
// The body reaches the client, which is untrusted, and the failures routed here
// name internal infrastructure: Secret names, Kubernetes RBAC messages ("User
// system:serviceaccount:… cannot get resource secrets"), credential-provider
// endpoints. Operators lose nothing by keeping it generic — every caller logs
// the full error alongside this reply, and it is recorded on the stream.
func blockReply(error) filter.Action {
	return filter.Stop(filter.Reply{
		Status: 403,
		Body:   []byte("tokentransform: credential unavailable"),
	})
}

// warnNoPermission logs the no-Secret-permission warn, throttled per
// credential ref.
func (f *Filter) warnNoPermission(ctx context.Context, rc *filter.RuleConfig[Config], st *filter.Stream, err error) {
	ns := secretNamespace(rc, st)
	key := ns + "/" + rc.Cfg.Source.Name + ":no_secret_permission"
	if f.limiter == nil || f.limiter.Allow(key) {
		log.FromContext(ctx).Info("tokentransform skipping rule: no permission to read credential",
			"source", string(rc.Cfg.Source.Kind)+"/"+ns+"/"+rc.Cfg.Source.Name, "pod", st.Peer.Pod.String(), "error", err)
	}
}
