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

package extproc

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/structpb"

	"github.com/openkruise/agentio/extensions/epe/pkg/extproc/attributes"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/egressauthz"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"

	extProcV3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/pkg/dns"
)

func TestRequestAuthorization(t *testing.T) {
	target := upstreamRoute("192.0.2.9:8443", true)
	rewrite := filter.Continue(filter.Mutation{Route: target}, filter.SetHeader("x-token", "injected"))
	block := filter.Stop(filter.Reply{Status: 451, Details: "profile_block"})
	for _, tc := range []struct {
		name        string
		before      []filter.Action
		body        *bodyProbe
		after       []filter.Action
		endOfStream bool
		blocked     bool
		bodyBlocked bool
		hasTarget   bool
	}{
		{name: "no matching rules"},
		{name: "normal completion", before: []filter.Action{rewrite}, hasTarget: true},
		{name: "bypass skips later block", before: []filter.Action{rewrite, filter.Bypass(), block}, hasTarget: true},
		{name: "earlier block wins", before: []filter.Action{block, filter.Bypass()}, blocked: true},
		{name: "later header block precedes body", body: &bodyProbe{}, after: []filter.Action{block}, blocked: true},
		{name: "body then target rewrite", body: &bodyProbe{}, after: []filter.Action{rewrite}, hasTarget: true},
		{name: "body bypass", before: []filter.Action{rewrite}, body: &bodyProbe{bodyAct: filter.Bypass()}, hasTarget: true},
		{name: "body block", before: []filter.Action{rewrite}, body: &bodyProbe{bodyAct: block}, bodyBlocked: true},
		{name: "empty body inline", body: &bodyProbe{}, after: []filter.Action{rewrite}, endOfStream: true, hasTarget: true},
	} {
		for _, outcome := range []string{"allow", "deny", "error"} {
			t.Run(tc.name+"/"+outcome, func(t *testing.T) {
				bodyCallsBefore := 0
				if tc.body != nil {
					bodyCallsBefore = tc.body.bodyCalls
				}
				var regs []filter.Registration
				add := func(action filter.Action) { regs = append(regs, fixedRegHeaders("action", action)) }
				for _, action := range tc.before {
					add(action)
				}
				if tc.body != nil {
					regs = append(regs, fixedReg("body", tc.body))
				}
				for _, action := range tc.after {
					add(action)
				}
				// Put each action in its own rule to exercise ordering across units.
				var units []engine.Unit
				for i := range regs {
					cfgs := make([]any, len(regs))
					cfgs[i] = struct{}{}
					units = append(units, engine.Unit{Cfgs: cfgs})
				}
				calls := 0
				server := NewServer(ServerDeps{
					Registrations: regs,
					Resolve: func(context.Context, subject.Subject, *httpreq.HTTPRequest) (engine.Resolution, error) {
						return engine.Resolution{Units: units}, nil
					},
					AuthorizeRequest: func(_ context.Context, stream *filter.Stream) (*filter.UpstreamTarget, *filter.Reply, error) {
						calls++
						if tc.body != nil && tc.body.bodyCalls != bodyCallsBefore {
							t.Fatal("body callback ran before authorization")
						}
						if tc.hasTarget &&
							(stream.Upstream == nil || *stream.Upstream.Address != *target.Upstream.Address) {
							t.Fatalf("authorization missed final target: %v", stream.Upstream)
						}
						switch outcome {
						case "deny":
							return nil, &filter.Reply{Status: 403, Details: "authorization_denied"}, nil
						case "error":
							return nil, nil, errors.New("authorization unavailable")
						default:
							return target.Upstream, nil, nil
						}
					},
				})
				state := newStreamState()
				headers := makeRequestHeaders("original.example:443", "/", "POST")
				headers.EndOfStream = tc.endOfStream
				responses, err := server.HandleRequestHeaders(
					t.Context(),
					headers,
					makeAttrsWithLabels("ns", "pod", ""),
					state,
				)
				if err != nil {
					t.Fatal(err)
				}
				pendingBody := tc.body != nil && !tc.endOfStream && !tc.blocked
				if pendingBody {
					if calls != 1 {
						t.Fatalf("authorization must run before buffering body: calls=%d", calls)
					}
					if outcome == "allow" {
						if responses[0].GetModeOverride().GetRequestBodyMode() != extProcV3.ProcessingMode_BUFFERED {
							t.Fatal("allowed request must remain buffered while rules wait for body")
						}
						if got := responseUpstream(responses[0]).GetFields()[upstreamAddressField].GetStringValue(); got != "192.0.2.9:8443" {
							t.Fatalf("header authorization did not pin target: %s", got)
						}
						if len(
							responses[0].GetRequestHeaders().GetResponse().GetHeaderMutation().GetSetHeaders(),
						) != 0 {
							t.Fatal("pending rule mutations emitted before body inspection")
						}
						responses, err = server.HandleRequestBody(
							t.Context(),
							&extProcPb.HttpBody{Body: []byte("payload"), EndOfStream: true},
							state,
						)
						if err != nil {
							t.Fatal(err)
						}
					} else if state.requestBodyContinuation != nil {
						t.Fatal("denied request still waits for body")
					}
				}
				wantCalls, wantStatus := 1, 0
				if outcome == "deny" {
					wantStatus = 403
				}
				if outcome == "error" {
					wantStatus = 500
				}
				if pendingBody && outcome == "allow" {
					if tc.bodyBlocked {
						wantCalls, wantStatus = 1, 451
					}
				} else if tc.blocked && !pendingBody {
					wantCalls, wantStatus = 0, 451
				}
				if calls != wantCalls {
					t.Fatalf("authorization calls=%d, want %d", calls, wantCalls)
				}
				response := responses[0]
				if wantStatus != 0 {
					if int(response.GetImmediateResponse().GetStatus().GetCode()) != wantStatus ||
						response.GetDynamicMetadata() != nil {
						t.Fatalf("want denial %d without target, got %v", wantStatus, response)
					}
					for _, h := range response.GetImmediateResponse().GetHeaders().GetSetHeaders() {
						if h.GetHeader().GetKey() != "content-type" {
							t.Fatalf("denial leaked pending header: %v", h)
						}
					}
					if response.GetModeOverride() != nil {
						t.Fatalf("denial leaked pending token or mode override: %v", response)
					}
				} else {
					if got := responseUpstream(response).GetFields()[upstreamAddressField].GetStringValue(); got != "192.0.2.9:8443" {
						t.Fatalf("target=%q response=%v", got, response)
					}
					common := response.GetRequestHeaders().GetResponse()
					if response.GetRequestBody() != nil {
						common = response.GetRequestBody().GetResponse()
					}
					if tc.hasTarget && !common.GetClearRouteCache() {
						t.Fatal("route cache mutation lost")
					}
				}
				if state.stream.Request.Host != "original.example" || state.stream.Upstream != nil {
					t.Fatal("authorization modified original stream used for matching")
				}
			})
		}
	}
}

func TestAuthorizationPreservesBypassResponseScope(t *testing.T) {
	bypasser := &wantRespFilter{requestAct: filter.Bypass()}
	later := &wantRespFilter{requestAct: filter.Continue()}
	server, _ := wantsServer(
		t,
		[]filter.Registration{respReg("bypass", bypasser), respReg("later", later)},
		[]string{"r"},
	)
	calls := 0
	server.authorizeRequest = func(context.Context, *filter.Stream) (*filter.UpstreamTarget, *filter.Reply, error) {
		calls++
		return upstreamRoute("192.0.2.9:443", false).Upstream, nil, nil
	}
	state := newStreamState()
	runRequestHeaders(t, server, state, false)
	server.finishAfterSend(t.Context(), state)
	if _, err := server.HandleResponseHeaders(t.Context(), responseHeaderMsg("200"), state); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || bypasser.respCalls != 1 || later.respCalls != 0 {
		t.Fatalf("authorization=%d bypass response=%d later response=%d", calls, bypasser.respCalls, later.respCalls)
	}
}

func TestAuthorizationBudgetReturnsLocalFailure(t *testing.T) {
	server := NewServer(ServerDeps{
		PluginBudget: time.Millisecond,
		Resolve: func(context.Context, subject.Subject, *httpreq.HTTPRequest) (engine.Resolution, error) {
			return engine.Resolution{}, nil
		},
		AuthorizeRequest: func(ctx context.Context, _ *filter.Stream) (*filter.UpstreamTarget, *filter.Reply, error) {
			<-ctx.Done()
			return nil, nil, ctx.Err()
		},
	})
	responses, err := server.HandleRequestHeaders(
		t.Context(),
		makeRequestHeaders("example.com:443", "/", "GET"),
		makeAttrsWithLabels("ns", "pod", ""),
		newStreamState(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := responses[0].GetImmediateResponse(); got.GetStatus().GetCode() != 500 ||
		got.GetDetails() != "epe_request_authorization_failed" {
		t.Fatalf("timeout must be a local failure: %v", responses)
	}
}

func TestAuthorizationChecksAllHeaderTargetsBeforeBody(t *testing.T) {
	denied := upstreamRoute("192.0.2.10:443", false)
	for _, tc := range []struct {
		name   string
		before filter.Action
		after  filter.Action
	}{
		{
			name:   "explicit route",
			before: filter.Continue(),
			after:  filter.Continue(filter.Mutation{Route: denied}),
		},
		{
			name:   "authority",
			before: filter.Continue(filter.SetHeader(":authority", "allowed.example:443")),
			after:  filter.Continue(filter.SetHeader(":authority", "denied.example:443")),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &bodyProbe{}
			server := NewServer(ServerDeps{
				Registrations: []filter.Registration{
					fixedRegHeaders("before", tc.before),
					fixedReg("body", body),
					fixedRegHeaders("after", tc.after),
				},
				Resolve: func(context.Context, subject.Subject, *httpreq.HTTPRequest) (engine.Resolution, error) {
					return engine.Resolution{
						Units: []engine.Unit{{Cfgs: []any{struct{}{}, struct{}{}, struct{}{}}}},
					}, nil
				},
			})
			calls := 0
			server.authorizeRequest = func(_ context.Context, stream *filter.Stream) (*filter.UpstreamTarget, *filter.Reply, error) {
				calls++
				if tc.name == "explicit route" {
					if stream.Upstream == nil || *stream.Upstream.Address != *denied.Upstream.Address {
						t.Fatal("authorization missed later header route", stream.Upstream)
					}
				} else if stream.Request.Host != "denied.example" {
					t.Fatal("authorization missed later authority", stream.Request.Host)
				}
				return nil, &filter.Reply{Status: 403, Details: "authorization_denied"}, nil
			}
			state := newStreamState()
			responses := runRequestHeaders(t, server, state, false)
			if calls != 1 || body.bodyCalls != 0 || responses[0].GetImmediateResponse().GetStatus().GetCode() != 403 ||
				state.requestBodyContinuation != nil || responses[0].GetDynamicMetadata() != nil {
				t.Fatalf("target was not rejected before body: calls=%d response=%v", calls, responses)
			}
		})
	}
}

func TestHeaderBypassRetainsBodyChecks(t *testing.T) {
	for _, denied := range []bool{false, true} {
		for _, response := range []bool{false, true} {
			body := &bodyProbe{}
			if denied {
				body.bodyAct = filter.Stop(filter.Reply{Status: 451})
			}
			bypass := &wantRespFilter{requestAct: filter.Bypass()}
			later := &wantRespFilter{requestAct: filter.Continue()}
			regs := []filter.Registration{fixedReg("body", body)}
			if response {
				regs = append(regs, respReg("bypass", bypass), respReg("later", later))
			} else {
				regs = append(regs, fixedRegHeaders("bypass", filter.Bypass()))
			}
			server, _ := wantsServer(t, regs, []string{"rule"})
			state := newStreamState()
			runRequestHeaders(t, server, state, false)
			server.finishAfterSend(t.Context(), state)
			if state.lifecycle != lifecycleActive || state.requestBodyContinuation == nil || body.bodyCalls != 0 {
				t.Fatalf("bypass finalized before body: state=%+v", state)
			}
			responses, err := server.HandleRequestBody(t.Context(), &extProcPb.HttpBody{Body: []byte("payload")}, state)
			if err != nil {
				t.Fatal(err)
			}
			if body.bodyCalls != 1 {
				t.Fatal("earlier body check skipped")
			}
			if denied && responses[0].GetImmediateResponse().GetStatus().GetCode() != 451 {
				t.Fatal("bypass suppressed body denial")
			}
			server.finishAfterSend(t.Context(), state)
			if response && !denied {
				if _, err := server.HandleResponseHeaders(t.Context(), responseHeaderMsg("200"), state); err != nil {
					t.Fatal(err)
				}
				if bypass.respCalls != 1 || later.respCalls != 0 {
					t.Fatal("body lost header bypass response scope")
				}
			} else if state.lifecycle != lifecycleFinalized {
				t.Fatal("terminal body result was not finalized")
			}
		}
	}
}

func TestServiceEntryTargetAuthorization(t *testing.T) {
	for _, tc := range []struct {
		name      string
		candidate string
		want      string
		action    filter.Action
		disabled  bool
		status    int
	}{
		{name: "allowed without DNS", candidate: "192.0.2.2:8443", want: "192.0.2.2:8443"},
		{name: "denied does not fall back to allowed original", candidate: "192.0.2.99:8443", status: 403},
		{name: "path rewrite preserves selected endpoint", candidate: "192.0.2.2:8443", action: filter.Continue(filter.SetPath("/rewritten", true)), want: "192.0.2.2:8443"},
		{name: "explicit route replaces candidate", candidate: "192.0.2.99:8443", action: filter.Continue(filter.Mutation{Route: upstreamRoute("192.0.2.2:8443", true)}), want: "192.0.2.2:8443"},
		{name: "bypass still authorizes", candidate: "192.0.2.99:8443", action: filter.Bypass(), status: 403},
		{name: "invalid input fails locally", candidate: "invalid", status: 500},
		{name: "invalid input fails with authorization disabled", candidate: "invalid", disabled: true, status: 500},
		{name: "disabled does not publish candidate", candidate: "192.0.2.99:8443", disabled: true},
		{name: "absent target requires Host resolution", status: 500},
	} {
		t.Run(tc.name, func(t *testing.T) {
			regs := []filter.Registration{fixedRegHeaders("mutation", tc.action)}
			deps := ServerDeps{
				Registrations: regs,
				Resolve: func(context.Context, subject.Subject, *httpreq.HTTPRequest) (engine.Resolution, error) {
					return engine.Resolution{Units: []engine.Unit{{Cfgs: []any{struct{}{}}}}}, nil
				},
			}
			if !tc.disabled {
				deps.AuthorizeRequest = func(ctx context.Context, st *filter.Stream) (*filter.UpstreamTarget, *filter.Reply, error) {
					cfg := egressauthz.Config{DeniedCIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.99/32")}}
					return egressauthz.NewAggregate(nil, cfg).Authorize(ctx, st)
				}
			}
			attrs := makeAttrsWithLabels("ns", "pod", "")
			fields := attrs[attributes.ExtProcAttrsKey].Fields
			fields[attributes.AttrDestinationAddress] = structpb.NewStringValue("192.0.2.1:8443")
			if tc.candidate != "" {
				fields[attributes.FilterStateRouteUpstream] = structpb.NewStringValue(tc.candidate)
			}
			state := newStreamState()
			responses, err := NewServer(
				deps,
			).HandleRequestHeaders(t.Context(), makeRequestHeaders("unresolved.invalid:443", "/", "GET"), attrs, state)
			if err != nil {
				t.Fatal(err)
			}
			if tc.disabled && tc.status == 0 && state.stream.Upstream.Address.String() != tc.candidate {
				t.Fatal("routing input lost with authorization disabled")
			}
			response := responses[0]
			if got := int(response.GetImmediateResponse().GetStatus().GetCode()); got != tc.status {
				t.Fatalf("status=%d want=%d response=%v", got, tc.status, response)
			}
			if tc.want != "" {
				if got := responseUpstream(response).GetFields()["address"].GetStringValue(); got != tc.want {
					t.Fatalf("target=%s want=%s", got, tc.want)
				}
			} else if response.GetDynamicMetadata() != nil {
				t.Fatalf("candidate escaped as output: %v", response)
			}
		})
	}
}

func TestStaticAuthorizationWithoutIdentityAndWithBypass(t *testing.T) {
	cfg := egressauthz.Config{DeniedCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}
	for _, mode := range []string{"missing-identity", "no-profile", "bypass", "identity-required"} {
		for _, host := range []string{"127.0.0.1:15000", "192.0.2.1:15000"} {
			t.Run(mode+"/"+host, func(t *testing.T) {
				resolves := 0
				server := NewServer(ServerDeps{
					Registrations: []filter.Registration{fixedRegHeaders("bypass", filter.Bypass())},
					Resolve: func(context.Context, subject.Subject, *httpreq.HTTPRequest) (engine.Resolution, error) {
						resolves++
						if mode == "bypass" {
							return engine.Resolution{Units: []engine.Unit{{Cfgs: []any{struct{}{}}}}}, nil
						}
						return engine.Resolution{}, nil
					},
					AuthorizeRequest: egressauthz.NewAggregate(
						dns.NewClient(nil, 0),
						egressauthz.NewStaticAuthorizer(cfg),
					).Authorize,
					FailClosedOnMissingIdentity: mode == "identity-required",
				})
				attrs := makeAttrsWithLabels("ns", "pod", "")
				if mode == "missing-identity" || mode == "identity-required" {
					attrs = nil
				}
				responses, err := server.HandleRequestHeaders(
					t.Context(),
					makeRequestHeaders(host, "/", "GET"),
					attrs,
					newStreamState(),
				)
				if err != nil {
					t.Fatal(err)
				}
				if mode == "identity-required" {
					if responses[0].GetImmediateResponse() == nil {
						t.Fatal("missing identity was allowed")
					}
				} else if host == "127.0.0.1:15000" {
					if reply := responses[0].GetImmediateResponse(); reply.GetStatus().GetCode() != 403 ||
						reply.GetDetails() != "epe_egress_denied" {
						t.Fatalf("global deny bypassed: %v", responses)
					}
				} else if got := responseUpstream(responses[0]).GetFields()[upstreamAddressField].GetStringValue(); got != host {
					t.Fatalf("allowed target not pinned: %s", got)
				}
				if attrs == nil && resolves != 0 {
					t.Fatal("profile resolution ran without identity")
				}
			})
		}
	}
}
