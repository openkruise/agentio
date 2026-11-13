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
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/structpb"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"

	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/extproc/attributes"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/egressauthz"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
	"github.com/openkruise/agentio/pkg/dns"
)

func TestAuthorizationDenialHasCorrelatedJSONResponse(t *testing.T) {
	audit := &capturedAuditLogger{}
	client := dns.NewClient(nil, time.Second)
	cfg := egressauthz.Config{DeniedCIDRs: []netip.Prefix{netip.MustParsePrefix("1.1.1.1/32")}}
	server := NewServer(
		ServerDeps{
			AuditLogger: audit,
			Resolve: func(context.Context, subject.Subject, *httpreq.HTTPRequest) (engine.Resolution, error) {
				return engine.Resolution{}, nil
			},
			AuthorizeRequest: egressauthz.NewAggregate(client, cfg).Authorize,
		},
	)
	headers := makeRequestHeaders("1.1.1.1:80", "/", "GET")
	headers.Headers.Headers = append(
		headers.Headers.Headers,
		&corev3.HeaderValue{Key: "x-request-id", RawValue: []byte("request-123")},
	)
	stream := &collectingStream{
		ctx: t.Context(),
		msgs: []*extProcPb.ProcessingRequest{
			{
				Request:    &extProcPb.ProcessingRequest_RequestHeaders{RequestHeaders: headers},
				Attributes: makeAttrsWithLabels("sandbox", "client-v1", ""),
			},
		},
	}
	if err := server.Process(stream); err != nil {
		t.Fatal(err)
	}
	if len(audit.entries) != 1 {
		t.Fatalf("audit entries: %v", audit.entries)
	}
	reply := stream.sent[0].GetImmediateResponse()
	entry := audit.entries[0]
	if entry.Outcome != "blocked" || entry.Units != 0 || len(entry.Actions) != 0 {
		t.Fatalf("audit: %+v", entry)
	}
	decision := entry.Authorization
	if decision == nil || decision.Action != "deny" || decision.Reason != filter.AuthorizationReasonPolicyDenied ||
		decision.Destination != "1.1.1.1:80" ||
		decision.Policy != "EPEConfig/egressAuthorization" ||
		decision.RuleIndex == nil ||
		*decision.RuleIndex != 0 {
		t.Fatalf("decision: %+v", decision)
	}
	headersOut := reply.GetHeaders().GetSetHeaders()
	if len(headersOut) != 1 || headersOut[0].GetHeader().GetKey() != "content-type" ||
		string(headersOut[0].GetHeader().GetRawValue()) != "application/json" {
		t.Fatalf("headers: %v", headersOut)
	}
	var body map[string]string
	if err := json.Unmarshal(reply.GetBody(), &body); err != nil {
		t.Fatalf("expected JSON denial body, got %q: %v", reply.GetBody(), err)
	}
	if reply.GetStatus().GetCode() != 403 || body["code"] != "epe_egress_denied" ||
		body["message"] != "Outbound destination is denied by policy." ||
		body["requestID"] != audit.entries[0].RequestID ||
		body["requestID"] != "request-123" {
		t.Fatalf("reply=%v body=%v", reply, body)
	}
}

func TestAuthorizationFailureResponseDoesNotExposeInternalError(t *testing.T) {
	audit := &capturedAuditLogger{}
	server := NewServer(ServerDeps{AuditLogger: audit,
		Resolve: func(context.Context, subject.Subject, *httpreq.HTTPRequest) (engine.Resolution, error) {
			return engine.Resolution{}, nil
		},
		AuthorizeRequest: func(context.Context, *filter.Stream) (*filter.UpstreamTarget, *filter.Reply, error) {
			return nil, nil, errors.New("private control-plane failure")
		},
	})
	stream := &collectingStream{
		ctx: t.Context(),
		msgs: []*extProcPb.ProcessingRequest{
			{
				Request: &extProcPb.ProcessingRequest_RequestHeaders{
					RequestHeaders: makeRequestHeaders("example.com:80", "/", "GET"),
				},
				Attributes: makeAttrsWithLabels("sandbox", "client-v1", ""),
			},
		},
	}
	if err := server.Process(stream); err != nil {
		t.Fatal(err)
	}
	reply := stream.sent[0].GetImmediateResponse()
	var body map[string]string
	if err := json.Unmarshal(reply.GetBody(), &body); err != nil {
		t.Fatal(err)
	}
	if reply.GetStatus().GetCode() != 500 || body["code"] != "epe_request_authorization_failed" ||
		strings.Contains(string(reply.GetBody()), "private") {
		t.Fatalf("reply: %v", reply)
	}
	entry := audit.entries[0]
	if entry.Authorization.Action != "error" ||
		entry.Authorization.Reason != filter.AuthorizationReasonFailed ||
		!strings.Contains(entry.Error, "private control-plane failure") {
		t.Fatalf("audit: %+v", entry)
	}
}

func TestAuthorizationPreservesOutcome(t *testing.T) {
	bypass := fixedRegHeaders("bypass", filter.Bypass())
	header := fixedRegHeaders("header", filter.Continue(filter.SetHeader("x-policy", "applied")))
	route := fixedRegHeaders("route", filter.Continue(filter.Mutation{Route: upstreamRoute("192.0.2.2:80", false)}))
	body := &extProcPb.ProcessingRequest{
		Request: &extProcPb.ProcessingRequest_RequestBody{
			RequestBody: &extProcPb.HttpBody{Body: []byte("payload"), EndOfStream: true},
		},
	}
	for _, tc := range []struct {
		name        string
		regs        []filter.Registration
		followup    *extProcPb.ProcessingRequest
		want        string
		target      string
		candidate   string
		endOfStream bool
		status      int
	}{
		{name: "no matching policy", want: "passthrough"},
		{name: "no-op filter", regs: []filter.Registration{fixedRegHeaders("allow", filter.Continue())}, want: "passthrough"},
		{name: "bypass", regs: []filter.Registration{bypass}, want: "bypassed"},
		{name: "gateway-selected target", candidate: "192.0.2.3:8080", target: "192.0.2.3:8080", want: "passthrough"},
		{name: "gateway-selected target with bypass", regs: []filter.Registration{bypass}, candidate: "192.0.2.3:8080", target: "192.0.2.3:8080", want: "bypassed"},
		{name: "explicit rewrite of gateway target", regs: []filter.Registration{route, bypass}, candidate: "192.0.2.3:8080", target: "192.0.2.2:80", want: "mutated"},
		{
			name: "cache invalidation before bypass",
			regs: []filter.Registration{
				fixedRegHeaders("cache", filter.Continue(filter.Mutation{Route: &filter.RouteMutation{ClearCache: true}})),
				bypass,
			},
			want: "bypassed",
		},
		{name: "header mutation before bypass", regs: []filter.Registration{header, bypass}, want: "mutated"},
		{name: "explicit upstream before bypass", regs: []filter.Registration{route, bypass}, want: "mutated", target: "192.0.2.2:80"},
		{
			name:     "body inspection before bypass",
			regs:     []filter.Registration{fixedReg("body", &bodyProbe{}), bypass},
			followup: body,
			want:     "bypassed",
		},
		{
			name:     "explicit upstream with deferred body inspection",
			regs:     []filter.Registration{route, fixedReg("body", &bodyProbe{}), bypass},
			followup: body,
			target:   "192.0.2.2:80",
			want:     "mutated",
		},
		{
			name:        "inline empty body inspection with bypass",
			regs:        []filter.Registration{fixedReg("body", &bodyProbe{}), bypass},
			endOfStream: true,
			want:        "bypassed",
		},
		{
			name: "body denial overrides upstream rewrite and bypass",
			regs: []filter.Registration{
				route,
				fixedReg("body", &bodyProbe{bodyAct: filter.Stop(filter.Reply{Status: 451})}),
				bypass,
			},
			followup: body,
			target:   "192.0.2.2:80",
			want:     "blocked",
			status:   451,
		},
		{
			name: "body mutation after header bypass",
			regs: []filter.Registration{
				fixedReg("body", &bodyProbe{bodyAct: filter.Continue(filter.Mutation{Body: []byte("replaced")})}),
				bypass,
			},
			followup: body,
			want:     "mutated",
		},
		{
			name: "response mutation after bypass",
			regs: []filter.Registration{
				respReg("response", &wantRespFilter{responseOp: []filter.Mutation{filter.SetHeader("x-policy", "applied")}}),
				bypass,
			},
			followup: &extProcPb.ProcessingRequest{
				Request: &extProcPb.ProcessingRequest_ResponseHeaders{ResponseHeaders: responseHeaderMsg("200")},
			},
			want: "mutated",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var units []engine.Unit
			if len(tc.regs) > 0 {
				cfgs := make([]any, len(tc.regs))
				for i := range cfgs {
					cfgs[i] = struct{}{}
				}
				units = []engine.Unit{{Cfgs: cfgs}}
			}
			audit := &capturedAuditLogger{}
			server := NewServer(ServerDeps{
				AuditLogger:   audit,
				Registrations: tc.regs,
				Resolve: func(context.Context, subject.Subject, *httpreq.HTTPRequest) (engine.Resolution, error) {
					return engine.Resolution{Units: units}, nil
				},
				AuthorizeRequest: egressauthz.NewAggregate(dns.NewClient(nil, time.Second)).Authorize,
			})
			stream := &collectingStream{
				ctx: t.Context(),
				msgs: []*extProcPb.ProcessingRequest{{
					Request: &extProcPb.ProcessingRequest_RequestHeaders{
						RequestHeaders: makeRequestHeaders("192.0.2.1:80", "/", "POST"),
					},
					Attributes: makeAttrsWithLabels("sandbox", "client", ""),
				}},
			}
			stream.msgs[0].GetRequestHeaders().EndOfStream = tc.endOfStream
			if tc.candidate != "" {
				stream.msgs[0].Attributes[attributes.ExtProcAttrsKey].Fields[attributes.FilterStateRouteUpstream] =
					structpb.NewStringValue(tc.candidate)
			}
			if tc.followup != nil {
				stream.msgs = append(stream.msgs, tc.followup)
			}
			if err := server.Process(stream); err != nil {
				t.Fatal(err)
			}
			if len(audit.entries) != 1 {
				t.Fatalf("audit entries: %v", audit.entries)
			}
			last := stream.sent[len(stream.sent)-1]
			if got := int(last.GetImmediateResponse().GetStatus().GetCode()); got != tc.status {
				t.Fatalf("final response status = %d, want %d", got, tc.status)
			}
			entry := audit.entries[0]
			if entry.Outcome != tc.want {
				t.Errorf("outcome = %q, want %q", entry.Outcome, tc.want)
			}
			target := tc.target
			if target == "" {
				target = "192.0.2.1:80"
			}
			if entry.Authorization == nil || entry.Authorization.Action != "allow" ||
				entry.Authorization.Destination != target {
				t.Fatalf("authorization = %+v, want allow %s", entry.Authorization, target)
			}
			if len(stream.sent) == 0 ||
				responseUpstream(stream.sent[0]).GetFields()[upstreamAddressField].GetStringValue() != target {
				t.Fatalf("authorized target %s was not sent: %v", target, stream.sent)
			}
		})
	}
}

func TestAuthorizationOutcomeWithSendFailure(t *testing.T) {
	client := dns.NewClient(nil, time.Second)
	denied := egressauthz.Config{DeniedCIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}
	for _, tc := range []struct {
		name      string
		authorize engine.RequestAuthorizer
		want      string
		status    int
	}{
		{name: "allow", authorize: egressauthz.NewAggregate(client).Authorize, want: "bypassed"},
		{name: "deny", authorize: egressauthz.NewAggregate(client, denied).Authorize, want: "blocked", status: 403},
		{name: "error", authorize: egressauthz.NewAggregate(nil).Authorize, want: "blocked", status: 500},
	} {
		for _, failSend := range []bool{false, true} {
			name := tc.name + "/sent"
			if failSend {
				name = tc.name + "/send-failed"
			}
			t.Run(name, func(t *testing.T) {
				audit := &capturedAuditLogger{}
				server := NewServer(ServerDeps{
					AuditLogger:   audit,
					Registrations: []filter.Registration{fixedRegHeaders("bypass", filter.Bypass())},
					Resolve: func(context.Context, subject.Subject, *httpreq.HTTPRequest) (engine.Resolution, error) {
						return engine.Resolution{Units: []engine.Unit{{Cfgs: []any{struct{}{}}}}}, nil
					},
					AuthorizeRequest: tc.authorize,
				})
				stream := &collectingStream{
					ctx: t.Context(),
					msgs: []*extProcPb.ProcessingRequest{{
						Request: &extProcPb.ProcessingRequest_RequestHeaders{
							RequestHeaders: makeRequestHeaders("192.0.2.1:80", "/", "GET"),
						},
						Attributes: makeAttrsWithLabels("sandbox", "client", ""),
					}},
				}
				want := tc.want
				if failSend {
					stream.sendErr = errors.New("test send failed")
					want = "error"
				}
				if err := server.Process(stream); (err != nil) != failSend {
					t.Fatalf("Process error = %v, failSend = %v", err, failSend)
				}
				if len(audit.entries) != 1 {
					t.Fatalf("audit entries: %v", audit.entries)
				}
				entry := audit.entries[0]
				if entry.Outcome != want || entry.Authorization == nil || entry.Authorization.Action != tc.name {
					t.Fatalf(
						"outcome=%s authorization=%+v, want %s/%s",
						entry.Outcome,
						entry.Authorization,
						want,
						tc.name,
					)
				}
				if failSend {
					if len(stream.sent) != 0 || entry.Error == "" {
						t.Fatalf("failed send recorded responses=%v error=%q", stream.sent, entry.Error)
					}
					return
				}
				if len(stream.sent) != 1 {
					t.Fatalf("sent responses = %v, want one", stream.sent)
				}
				response := stream.sent[0]
				if got := int(response.GetImmediateResponse().GetStatus().GetCode()); got != tc.status {
					t.Fatalf("status = %d, want %d", got, tc.status)
				}
				if (responseUpstream(response) != nil) != (tc.name == "allow") {
					t.Fatalf("upstream must only be sent on allow: %v", response)
				}
			})
		}
	}
}
