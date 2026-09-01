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

	log "sigs.k8s.io/controller-runtime/pkg/log"

	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/logging"
)

// RateLimiter is the warn-throttle seam (*Limiter in production).
type RateLimiter interface{ Allow(key string) bool }

// Filter evaluates one rule's token transformation.
type Filter struct {
	filter.PassThrough
	sources Sources
	signers map[string]Signer
	limiter RateLimiter
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
			var rl RateLimiter
			// A nil *Limiter stored in the interface would compare
			// non-nil; keep the interface nil instead.
			if deps.Limiter != nil {
				rl = deps.Limiter
			}
			return &Filter{
				sources: Sources{
					Secret:   NewSecretSource(deps.Kube),
					Provider: NewProviderSource(deps.Tokens, deps.STS),
				},
				signers: signerMap(),
				limiter: rl,
				rule:    rule,
			}
		},
	}
}

// OnRequestHeaders evaluates this rule and either transforms, defers for a
// body, blocks, or continues to the next rule.
func (f *Filter) OnRequestHeaders(ctx context.Context, st *filter.Stream) (filter.Action, error) {
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
			return f.failEligible(ctx, cfg, st, err), nil
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
		return f.failEligible(ctx, cfg, st,
			fmt.Errorf("sandbox token unavailable for CredentialProvider")), nil
	}

	if bw, ok := signer.(BodyWanter); ok {
		needs, err := bw.WantsBody(st, signerCfg)
		if err != nil {
			return f.failEligible(ctx, cfg, st, err), nil
		}
		if needs {
			f.pending = true
			return filter.NeedBody(), nil
		}
	}

	return f.complete(ctx, rc, st, nil)
}

// OnRequestBody finishes a body-deferred signature.
func (f *Filter) OnRequestBody(ctx context.Context, st *filter.Stream, body filter.Body) (filter.Action, error) {
	if !f.pending {
		return filter.Continue(), nil
	}
	if !body.Complete {
		return f.failClaimed(ctx, f.rule.Cfg, st,
			fmt.Errorf("request body is incomplete")), nil
	}
	return f.complete(ctx, &f.rule, st, body.Bytes)
}

// complete fetches the credential and signs for one claimed unit.
func (f *Filter) complete(ctx context.Context, rc *filter.RuleConfig[Config], st *filter.Stream, body []byte) (filter.Action, error) {
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
		return f.failClaimed(ctx, cfg, st, err), nil
	}

	signerCfg := cfg.SignerCfg
	if f.hasPreparedCfg {
		signerCfg = f.preparedSignerCfg
	}
	muts, err := signer.Sign(ctx, st, body, rc.Scope, cred, signerCfg)
	if err != nil {
		return f.failClaimed(ctx, cfg, st, err), nil
	}
	log.FromContext(ctx).V(logging.DEBUG).Info("token transformation applied",
		"type", cfg.Type, "pod", st.Peer.Pod.String())
	return filter.Continue(muts...), nil
}

// fetch resolves the rule's credential and sanitizes it. Every source funnels
// through here, so this is the one place that has to guarantee the value is
// usable as a header value — see Credential.sanitized.
func (f *Filter) fetch(ctx context.Context, rc *filter.RuleConfig[Config], st *filter.Stream, kind CredentialKind) (Credential, error) {
	cred, err := f.fetchFromSource(ctx, rc, st, kind)
	if err != nil {
		return Credential{}, err
	}
	return cred.sanitized()
}

// fetchFromSource reads the credential from the configured source, applying the
// ref -> profile -> pod namespace fallback for Secrets.
func (f *Filter) fetchFromSource(ctx context.Context, rc *filter.RuleConfig[Config], st *filter.Stream, kind CredentialKind) (Credential, error) {
	spec := rc.Cfg.Source
	switch spec.Kind {
	case SourceKindSecret:
		ns := spec.Namespace
		if ns == "" && rc.Scope != nil {
			ns = rc.Scope.Profile().Namespace
		}
		if ns == "" {
			ns = st.Peer.Pod.Namespace
		}
		return f.sources.Secret.Fetch(ctx, Ref{Kind: kind, Name: spec.Name, Namespace: ns})
	case SourceKindProvider:
		extra, err := renderParams(spec.Parameters, rc.Scope)
		if err != nil {
			return Credential{}, err
		}
		return f.sources.Provider.Fetch(ctx, Ref{
			Kind: kind, Name: spec.Name,
			AccessToken:     st.Peer.Token.AccessToken,
			SandboxClientID: st.Peer.Token.SandboxClientID,
			ExtraMetadata:   extra,
		})
	default:
		return Credential{}, fmt.Errorf("unsupported credential source kind %q", spec.Kind)
	}
}

// failEligible resolves a pre-transform failure through FailStrategy.
func (f *Filter) failEligible(ctx context.Context, cfg Config, st *filter.Stream, err error) filter.Action {
	if cfg.FailBlock {
		log.FromContext(ctx).Error(err, "token transformation failed, blocking request", "pod", st.Peer.Pod.String())
		return blockReply(err)
	}
	log.FromContext(ctx).Error(err, "token transformation failed, passing through", "pod", st.Peer.Pod.String())
	return filter.Continue()
}

// failClaimed resolves a POST-claim failure: Block stops, otherwise the
// walk ends without mutations (the claimed unit already had its chance).
func (f *Filter) failClaimed(ctx context.Context, cfg Config, st *filter.Stream, err error) filter.Action {
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
	ns := rc.Cfg.Source.Namespace
	if ns == "" && rc.Scope != nil {
		ns = rc.Scope.Profile().Namespace
	}
	if ns == "" {
		ns = st.Peer.Pod.Namespace
	}
	key := ns + "/" + rc.Cfg.Source.Name + ":no_secret_permission"
	if f.limiter == nil || f.limiter.Allow(key) {
		log.FromContext(ctx).Info("tokentransform skipping rule: no permission to read credential",
			"source", string(rc.Cfg.Source.Kind)+"/"+ns+"/"+rc.Cfg.Source.Name, "pod", st.Peer.Pod.String(), "err", err.Error())
	}
}
