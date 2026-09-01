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
	"reflect"
	"regexp"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/types"

	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/eval"
	"istio.io/istio/extensions/epe/pkg/inputs"
)

type fakeSource struct {
	cred Credential
	err  error
	got  []Ref
}

func (f *fakeSource) Fetch(_ context.Context, ref Ref) (Credential, error) {
	f.got = append(f.got, ref)
	return f.cred, f.err
}

type preparingSigner struct {
	prepared   any
	empty      bool
	prepareErr error
	wantsBody  bool

	prepareCalls int
	signCalls    int
	signedCfg    any
}

var _ SignerPreparer = (*preparingSigner)(nil)

func (s *preparingSigner) Kind() CredentialKind { return CredentialKindToken }

func (s *preparingSigner) Prepare(_ *filter.Stream, _ *inputs.Scope, _ any) (any, bool, error) {
	s.prepareCalls++
	return s.prepared, s.empty, s.prepareErr
}

func (s *preparingSigner) WantsBody(*filter.Stream, any) (bool, error) { return s.wantsBody, nil }

func (s *preparingSigner) Sign(_ context.Context, _ *filter.Stream, _ []byte, _ *inputs.Scope, cred Credential, cfg any) ([]filter.Mutation, error) {
	s.signCalls++
	s.signedCfg = cfg
	return []filter.Mutation{{HeaderOps: []filter.HeaderOp{{
		Kind: filter.HeaderSet, Name: "x-prepared", Value: fmt.Sprintf("%s:%s", cfg, cred.Token),
	}}}}, nil
}

// newTestFilter builds a Filter over one config with scripted
// sources and the real ApiKey signer under its key.
func newTestFilter(secret, provider CredentialSource, cfg Config) *Filter {
	tmpl, _ := eval.CompileTemplate("valueTemplate", "Bearer {{ .Token }}")
	if cfg.SignerCfg == nil {
		cfg.SignerCfg = ApiKeyConfig{Headers: []ApiKeyHeaderConfig{{
			Names: []string{"authorization"}, Value: HeaderValueSource{Template: tmpl},
		}}}
	}
	return &Filter{
		sources: Sources{Secret: secret, Provider: provider},
		signers: map[string]Signer{TypeAPIKey: apiKeySigner{}},
		rule:    filter.RuleConfig[Config]{Cfg: cfg, Scope: inputs.NewScope(inputs.Request{}, inputs.Pod{}, inputs.Profile{}, inputs.Rule{}, nil)},
	}
}

func secretCfg(failBlock bool) Config {
	return Config{Type: TypeAPIKey, FailBlock: failBlock,
		Source: SourceSpec{Kind: SourceKindSecret, Name: "s", Namespace: "ns"}}
}

func withHeaderCondition(cfg Config) Config {
	tmpl, _ := eval.CompileTemplate("valueTemplate", "Bearer {{ .Token }}")
	cfg.SignerCfg = ApiKeyConfig{Headers: []ApiKeyHeaderConfig{{
		Names:     []string{"authorization"},
		Condition: &When{Header: "x-guard", Re: regexp.MustCompile(`^go$`)},
		Value:     HeaderValueSource{Template: tmpl},
	}}}
	return cfg
}

func streamWithPeerToken() *filter.Stream {
	return &filter.Stream{Peer: filter.Peer{
		Pod:   types.NamespacedName{Namespace: "podns", Name: "pod-x"},
		Token: &filter.SandboxToken{AccessToken: "at", SandboxClientID: "cid"},
	}}
}

func streamWithoutPeerToken() *filter.Stream {
	return &filter.Stream{Peer: filter.Peer{Pod: types.NamespacedName{Namespace: "podns", Name: "pod-x"}}}
}

func bodyTargetCfg(t *testing.T, failBlock bool, expression string) Config {
	t.Helper()
	tmpl, err := eval.CompileTemplate("apiKey.value.template", "{{ .Token }}")
	if err != nil {
		t.Fatal(err)
	}
	prog, err := eval.CompileBodyMutation(expression)
	if err != nil {
		t.Fatal(err)
	}
	cfg := secretCfg(failBlock)
	cfg.SignerCfg = ApiKeyConfig{Body: &ApiKeyBodyConfig{
		Program: prog,
		Value:   HeaderValueSource{Template: tmpl},
	}}
	return cfg
}

func TestFilterSignerPreparationBeforeCredentialFetch(t *testing.T) {
	t.Run("header condition skips credential fetch", func(t *testing.T) {
		source := &fakeSource{cred: Credential{Token: "credential"}}
		cfg := withHeaderCondition(secretCfg(false))
		f := newTestFilter(source, nil, cfg)
		st := streamWithPeerToken()
		st.Request.Headers = map[string]string{"x-guard": "skip"}

		act, err := f.OnRequestHeaders(context.Background(), st)
		if err != nil {
			t.Fatal(err)
		}
		if act.Kind() != filter.KindContinue || len(act.Mutations()) != 0 {
			t.Fatalf("action = %+v, want unmodified Continue", act)
		}
		if len(source.got) != 0 {
			t.Fatalf("fetches=%d, want 0", len(source.got))
		}
	})

	t.Run("empty preparation skips provider without a peer token", func(t *testing.T) {
		provider := &fakeSource{}
		cfg := Config{Type: TypeAPIKey, Source: SourceSpec{Kind: SourceKindProvider, Name: "provider"}, SignerCfg: "original"}
		f := newTestFilter(nil, provider, cfg)
		signer := &preparingSigner{empty: true}
		f.signers[TypeAPIKey] = signer

		act, err := f.OnRequestHeaders(context.Background(), streamWithoutPeerToken())
		if err != nil {
			t.Fatal(err)
		}
		if act.Kind() != filter.KindContinue || len(act.Mutations()) != 0 {
			t.Fatalf("action = %+v, want unmodified Continue", act)
		}
		if signer.prepareCalls != 1 || signer.signCalls != 0 || len(provider.got) != 0 {
			t.Fatalf("prepare=%d sign=%d provider fetches=%d, want 1, 0, 0", signer.prepareCalls, signer.signCalls, len(provider.got))
		}
	})

	for _, tc := range []struct {
		name      string
		failBlock bool
		wantKind  filter.ActionKind
	}{
		{name: "block preparation error stops before fetch", failBlock: true, wantKind: filter.KindStop},
		{name: "allow preparation error continues before fetch", wantKind: filter.KindContinue},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := &fakeSource{cred: Credential{Token: "credential"}}
			f := newTestFilter(source, nil, secretCfg(tc.failBlock))
			signer := &preparingSigner{prepareErr: errors.New("cannot prepare")}
			f.signers[TypeAPIKey] = signer

			act, err := f.OnRequestHeaders(context.Background(), streamWithPeerToken())
			if err != nil {
				t.Fatal(err)
			}
			if act.Kind() != tc.wantKind {
				t.Fatalf("action kind = %v, want %v", act.Kind(), tc.wantKind)
			}
			if tc.failBlock {
				reply, ok := act.Reply()
				if !ok || reply.Status != 403 {
					t.Fatalf("reply = %+v, present=%t; want a 403 block reply", reply, ok)
				}
			}
			if signer.prepareCalls != 1 || signer.signCalls != 0 || len(source.got) != 0 {
				t.Fatalf("prepare=%d sign=%d fetches=%d, want 1, 0, 0", signer.prepareCalls, signer.signCalls, len(source.got))
			}
		})
	}

	t.Run("prepared config signs after body fetch", func(t *testing.T) {
		source := &fakeSource{cred: Credential{Token: "credential"}}
		cfg := secretCfg(false)
		cfg.SignerCfg = "original"
		f := newTestFilter(source, nil, cfg)
		signer := &preparingSigner{prepared: "prepared", wantsBody: true}
		f.signers[TypeAPIKey] = signer
		st := streamWithPeerToken()

		headersAct, err := f.OnRequestHeaders(context.Background(), st)
		if err != nil {
			t.Fatal(err)
		}
		if headersAct.Kind() != filter.KindNeedBody || len(source.got) != 0 {
			t.Fatalf("headers action = %+v, fetches=%d; want NeedBody with no fetch", headersAct, len(source.got))
		}
		bodyAct, err := f.OnRequestBody(context.Background(), st, filter.Body{Bytes: []byte("body"), Complete: true})
		if err != nil {
			t.Fatal(err)
		}
		muts := bodyAct.Mutations()
		if len(muts) != 1 || len(muts[0].HeaderOps) != 1 || muts[0].HeaderOps[0].Value != "prepared:credential" {
			t.Fatalf("body action = %+v, want prepared credential mutation", bodyAct)
		}
		if signer.prepareCalls != 1 || signer.signCalls != 1 || signer.signedCfg != "prepared" || len(source.got) != 1 {
			t.Fatalf("prepare=%d sign=%d cfg=%v fetches=%d, want 1, 1, prepared, 1", signer.prepareCalls, signer.signCalls, signer.signedCfg, len(source.got))
		}
	})

	t.Run("existing signer still uses its original config", func(t *testing.T) {
		source := &fakeSource{cred: Credential{Token: "credential"}}
		f := newTestFilter(source, nil, secretCfg(false))

		act, err := f.OnRequestHeaders(context.Background(), streamWithPeerToken())
		if err != nil {
			t.Fatal(err)
		}
		muts := act.Mutations()
		if len(muts) != 1 || len(muts[0].HeaderOps) != 1 || muts[0].HeaderOps[0].Value != "Bearer credential" {
			t.Fatalf("action = %+v, want existing signer mutation", act)
		}
		if len(source.got) != 1 {
			t.Fatalf("fetches = %d, want 1", len(source.got))
		}
	})
}

func TestFilterAPIKeyBodyTargetDefersAndMutates(t *testing.T) {
	src := &fakeSource{cred: Credential{Token: "new-token"}}
	f := newTestFilter(src, nil, bodyTargetCfg(t, true,
		"json(request.body).merge({'api_key': value})"))
	st := streamWithPeerToken()
	st.Request.Method = "POST"
	st.Request.Headers = map[string]string{"content-type": "application/json"}

	headers, err := f.OnRequestHeaders(context.Background(), st)
	if err != nil {
		t.Fatal(err)
	}
	if headers.Kind() != filter.KindNeedBody {
		t.Fatalf("headers action kind = %v, want KindNeedBody", headers.Kind())
	}
	if len(src.got) != 0 {
		t.Fatalf("credential fetched before body arrived: %d fetches", len(src.got))
	}

	body, err := f.OnRequestBody(context.Background(), st, filter.Body{
		Bytes: []byte(`{"keep":true}`), Complete: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	mutations := body.Mutations()
	if len(mutations) != 1 || string(mutations[0].Body) != `{"api_key":"new-token","keep":true}` {
		t.Fatalf("body mutations = %+v", mutations)
	}
	if len(mutations[0].HeaderOps) != 0 {
		t.Fatalf("body target also changed headers: %+v", mutations[0].HeaderOps)
	}
	if len(src.got) != 1 {
		t.Fatalf("credential fetches = %d, want 1 in body phase", len(src.got))
	}
}

func TestFilterAPIKeyBodyTargetFailureUsesFailStrategy(t *testing.T) {
	for _, tc := range []struct {
		name      string
		failBlock bool
		wantKind  filter.ActionKind
	}{
		{name: "block", failBlock: true, wantKind: filter.KindStop},
		{name: "allow", failBlock: false, wantKind: filter.KindContinue},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := &fakeSource{cred: Credential{Token: "TOKEN-MUST-NOT-LEAK"}}
			f := newTestFilter(src, nil, bodyTargetCfg(t, tc.failBlock, "json(request.body)"))
			st := streamWithPeerToken()
			headers, _ := f.OnRequestHeaders(context.Background(), st)
			if headers.Kind() != filter.KindNeedBody {
				t.Fatalf("headers action kind = %v, want KindNeedBody", headers.Kind())
			}
			body, _ := f.OnRequestBody(context.Background(), st, filter.Body{
				Bytes: []byte("BODY-MUST-NOT-LEAK"), Complete: true,
			})
			if body.Kind() != tc.wantKind || len(body.Mutations()) != 0 {
				t.Fatalf("body action = %+v, want kind %v without mutations", body, tc.wantKind)
			}
		})
	}
}

func TestFilterAPIKeyBodyTargetRejectsIncompleteBody(t *testing.T) {
	src := &fakeSource{cred: Credential{Token: "new-token"}}
	f := newTestFilter(src, nil, bodyTargetCfg(t, true, "request.body"))
	st := streamWithPeerToken()
	headers, _ := f.OnRequestHeaders(context.Background(), st)
	if headers.Kind() != filter.KindNeedBody {
		t.Fatalf("headers action kind = %v, want KindNeedBody", headers.Kind())
	}
	body, _ := f.OnRequestBody(context.Background(), st, filter.Body{
		Bytes: []byte("{}"), Complete: false,
	})
	if body.Kind() != filter.KindStop || len(body.Mutations()) != 0 {
		t.Fatalf("body action = %+v, want fail-closed stop", body)
	}
	if len(src.got) != 0 {
		t.Fatalf("credential fetched for incomplete body: %d fetches", len(src.got))
	}
}

func TestFilterInjectsForEligibleRule(t *testing.T) {
	src := &fakeSource{cred: Credential{Token: "k"}}
	f := newTestFilter(src, nil, secretCfg(false))
	act, err := f.OnRequestHeaders(context.Background(), streamWithPeerToken())
	if err != nil {
		t.Fatal(err)
	}
	muts := act.Mutations()
	if len(muts) != 1 || muts[0].HeaderOps[0].Value != "Bearer k" {
		t.Fatalf("action = %+v", act)
	}
	if len(src.got) != 1 {
		t.Fatalf("fetches = %d, want 1", len(src.got))
	}
}

// A multi-header config is still one transformation: the credential is fetched
// once and every configured header is rewritten from that single fetch.
func TestFilterInjectsEveryHeaderFromOneFetch(t *testing.T) {
	bearer, err := eval.CompileTemplate("valueTemplate", "Bearer {{ .Token }}")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := eval.CompileTemplate("valueTemplate", "{{ .Token }}")
	if err != nil {
		t.Fatal(err)
	}
	cfg := secretCfg(false)
	cfg.SignerCfg = ApiKeyConfig{Headers: []ApiKeyHeaderConfig{
		{Names: []string{"authorization"}, Value: HeaderValueSource{Template: bearer}},
		{Names: []string{"x-api-key"}, Value: HeaderValueSource{Template: raw}},
	}}
	src := &fakeSource{cred: Credential{Token: "k"}}

	act, err := newTestFilter(src, nil, cfg).OnRequestHeaders(context.Background(), streamWithPeerToken())
	if err != nil {
		t.Fatal(err)
	}
	muts := act.Mutations()
	if len(muts) != 1 {
		t.Fatalf("mutations = %d, want the whole group folded into one", len(muts))
	}
	want := []filter.HeaderOp{
		{Kind: filter.HeaderSet, Name: "authorization", Value: "Bearer k"},
		{Kind: filter.HeaderSet, Name: "x-api-key", Value: "k"},
	}
	if !reflect.DeepEqual(muts[0].HeaderOps, want) {
		t.Fatalf("header ops = %+v, want %+v", muts[0].HeaderOps, want)
	}
	if len(src.got) != 1 {
		t.Fatalf("fetches = %d, want 1 for the whole group", len(src.got))
	}
}

func TestFilterWhenNotMetSkipsUnit(t *testing.T) {
	src := &fakeSource{cred: Credential{Token: "k"}}
	cfg := withHeaderCondition(secretCfg(false))
	f := newTestFilter(src, nil, cfg)
	st := streamWithPeerToken()
	st.Request.Headers = map[string]string{"x-guard": "stop"}
	act, _ := f.OnRequestHeaders(context.Background(), st)
	if len(act.Mutations()) != 0 || len(src.got) != 0 {
		t.Fatalf("when condition must skip: muts=%v fetches=%d", act.Mutations(), len(src.got))
	}
}

func TestFilterWhenMetClaimsUnit(t *testing.T) {
	src := &fakeSource{cred: Credential{Token: "k"}}
	cfg := withHeaderCondition(secretCfg(false))
	f := newTestFilter(src, nil, cfg)
	st := streamWithPeerToken()
	st.Request.Headers = map[string]string{"x-guard": "go"}
	act, _ := f.OnRequestHeaders(context.Background(), st)
	if len(act.Mutations()) != 1 {
		t.Fatalf("met condition must claim: %+v", act)
	}
}

func TestFilterProviderWithoutPeerTokenAllowContinues(t *testing.T) {
	providerCfg := Config{Type: TypeAPIKey,
		Source: SourceSpec{Kind: SourceKindProvider, Name: "prov"}}
	f := newTestFilter(nil, &fakeSource{}, providerCfg)
	act, _ := f.OnRequestHeaders(context.Background(), streamWithoutPeerToken())
	if act.Kind() != filter.KindContinue || len(act.Mutations()) != 0 {
		t.Fatalf("Allow pre-transform failure must continue: %+v", act)
	}
}

func TestFilterProviderWithoutPeerTokenBlockStops(t *testing.T) {
	cfg := Config{Type: TypeAPIKey, FailBlock: true,
		Source: SourceSpec{Kind: SourceKindProvider, Name: "prov"}}
	f := newTestFilter(nil, &fakeSource{}, cfg)
	act, _ := f.OnRequestHeaders(context.Background(), streamWithoutPeerToken())
	if act.Kind() != filter.KindStop {
		t.Fatalf("kind = %v, want KindStop", act.Kind())
	}
	reply, ok := act.Reply()
	if !ok || reply.Status != 403 || !strings.Contains(string(reply.Body), "tokentransform:") {
		t.Fatalf("reply = %+v, ok=%v", reply, ok)
	}
}

func TestFilterFetchErrorBlockStops(t *testing.T) {
	src := &fakeSource{err: errors.New("boom")}
	f := newTestFilter(src, nil, secretCfg(true))
	act, _ := f.OnRequestHeaders(context.Background(), streamWithPeerToken())
	if act.Kind() != filter.KindStop {
		t.Fatalf("kind = %v, want KindStop", act.Kind())
	}
}

func TestFilterFetchErrorAllowEndsWalk(t *testing.T) {
	src := &fakeSource{err: errors.New("boom")}
	f := newTestFilter(src, nil, secretCfg(false))
	act, _ := f.OnRequestHeaders(context.Background(), streamWithPeerToken())
	if act.Kind() != filter.KindContinue || len(act.Mutations()) != 0 {
		t.Fatalf("action = %+v", act)
	}
	if len(src.got) != 1 {
		t.Fatalf("fetches = %d, want 1: claimed unit's Allow failure ends the walk", len(src.got))
	}
}

// A denied credential read resolves through failStrategy like any other fetch
// failure. It used to pass through unconditionally, which meant an RBAC
// regression silently forwarded requests carrying the client's own credential
// even under the CRD-default Block.
func TestFilterNoPermissionHonoursFailStrategy(t *testing.T) {
	forbidden := func() *fakeSource {
		return &fakeSource{err: fmt.Errorf("%w: forbidden", ErrNoPermission)}
	}

	blocked, _ := newTestFilter(forbidden(), nil, secretCfg(true)).
		OnRequestHeaders(context.Background(), streamWithPeerToken())
	if blocked.Kind() != filter.KindStop {
		t.Fatalf("failStrategy=Block must block a denied read: %+v", blocked)
	}

	open, _ := newTestFilter(forbidden(), nil, secretCfg(false)).
		OnRequestHeaders(context.Background(), streamWithPeerToken())
	if open.Kind() != filter.KindContinue || len(open.Mutations()) != 0 {
		t.Fatalf("failStrategy=Open must pass a denied read through unmodified: %+v", open)
	}
}

func TestFilterSecretNamespaceFallback(t *testing.T) {
	src := &fakeSource{cred: Credential{Token: "k"}}
	cfg := secretCfg(false)
	cfg.Source.Namespace = "" // force fallback
	f := newTestFilter(src, nil, cfg)
	f.rule.Scope = inputs.NewScope(inputs.Request{}, inputs.Pod{}, inputs.Profile{Namespace: "profilens"}, inputs.Rule{}, nil)
	_, _ = f.OnRequestHeaders(context.Background(), streamWithPeerToken())
	if len(src.got) != 1 || src.got[0].Namespace != "profilens" {
		t.Fatalf("ref = %+v, want profile-namespace fallback", src.got)
	}
}

func TestFilterSecretNamespaceFallbackToPod(t *testing.T) {
	src := &fakeSource{cred: Credential{Token: "k"}}
	cfg := secretCfg(false)
	cfg.Source.Namespace = ""
	f := newTestFilter(src, nil, cfg)
	f.rule.Scope = inputs.NewScope(inputs.Request{}, inputs.Pod{}, inputs.Profile{}, inputs.Rule{}, nil) // no profile namespace
	_, _ = f.OnRequestHeaders(context.Background(), streamWithPeerToken())
	if len(src.got) != 1 || src.got[0].Namespace != "podns" {
		t.Fatalf("ref = %+v, want pod-namespace fallback", src.got)
	}
}

type wantBodySigner struct{ apiKeySigner }

func (wantBodySigner) WantsBody(*filter.Stream, any) (bool, error) { return true, nil }

func TestFilterDefersToBodyPhase(t *testing.T) {
	src := &fakeSource{cred: Credential{Token: "k"}}
	f := newTestFilter(src, nil, secretCfg(false))
	f.signers[TypeAPIKey] = wantBodySigner{}
	st := streamWithPeerToken()
	act, _ := f.OnRequestHeaders(context.Background(), st)
	if act.Kind() != filter.KindNeedBody {
		t.Fatalf("headers action kind = %v, want KindNeedBody", act.Kind())
	}
	if len(src.got) != 0 {
		t.Fatalf("fetches in headers phase = %d, want 0 (deferred)", len(src.got))
	}
	bodyAct, _ := f.OnRequestBody(context.Background(), st, filter.Body{Bytes: []byte("x"), Complete: true})
	if len(bodyAct.Mutations()) != 1 {
		t.Fatalf("body action = %+v, want the injection", bodyAct)
	}
}

type ineligibleSigner struct{ apiKeySigner }

func (ineligibleSigner) WantsBody(*filter.Stream, any) (bool, error) {
	return false, errors.New("cannot detect scheme")
}

func TestFilterBodyWanterErrorAllowContinues(t *testing.T) {
	src := &fakeSource{cred: Credential{Token: "k"}}
	f := newTestFilter(src, nil, secretCfg(false))
	f.signers[TypeAPIKey] = ineligibleSigner{}
	act, _ := f.OnRequestHeaders(context.Background(), streamWithPeerToken())
	if act.Kind() != filter.KindContinue || len(act.Mutations()) != 0 {
		t.Fatalf("action = %+v", act)
	}
	if len(src.got) != 0 {
		t.Fatalf("fetches = %d, want 0", len(src.got))
	}
}

func TestFilterBodyWanterErrorBlockStops(t *testing.T) {
	f := newTestFilter(&fakeSource{}, nil, secretCfg(true))
	f.signers[TypeAPIKey] = ineligibleSigner{}
	act, _ := f.OnRequestHeaders(context.Background(), streamWithPeerToken())
	if act.Kind() != filter.KindStop {
		t.Fatalf("kind = %v, want KindStop", act.Kind())
	}
}
