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

package extproc

import (
	"context"
	"net/netip"
	"testing"

	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/go-logr/logr"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	structpb "google.golang.org/protobuf/types/known/structpb"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
)

func upstreamRoute(address string, clear bool) *filter.RouteMutation {
	a := netip.MustParseAddrPort(address)
	return &filter.RouteMutation{Upstream: &filter.UpstreamTarget{Address: &a}, ClearCache: clear}
}

func TestRouteTranslation(t *testing.T) {
	for _, address := range []string{"192.0.2.10:443", "[2001:db8::10]:443"} {
		for _, clear := range []bool{false, true} {
			route := upstreamRoute(address, clear)
			headers := translateRequestHeadersResult(&engine.RequestHeadersResult{Disposition: engine.DispositionMutated, Route: route}, logr.Discard(), filter.Peer{})
			body := translateRequestBodyResult(&engine.RequestBodyResult{Disposition: engine.DispositionMutated, Route: route})
			for _, response := range []*extProcPb.ProcessingResponse{headers[0], body[0]} {
				if classifyResponse(response) != effectMutated {
					t.Fatal("upstream metadata was not recorded as a mutation")
				}
				fields := responseUpstream(response).GetFields()
				if fields[upstreamAddressField].GetStringValue() != address || fields[upstreamIPField].GetStringValue() != route.Upstream.Address.Addr().String() || fields[upstreamPortField].GetStringValue() != "443" {
					t.Fatalf("metadata=%v", fields)
				}
				common := response.GetRequestHeaders().GetResponse()
				if response.GetRequestBody() != nil {
					common = response.GetRequestBody().GetResponse()
				}
				if common.GetClearRouteCache() != clear {
					t.Fatal("cache flag lost")
				}
				if len(common.GetHeaderMutation().GetSetHeaders()) != 0 {
					t.Fatal("target translation changed HTTP headers")
				}
			}
		}
	}
	if defaultPassThrough[0].GetDynamicMetadata() != nil || defaultPassThroughBody[0].GetDynamicMetadata() != nil {
		t.Fatal("shared response modified")
	}
}

func TestRouteTranslationMergesWithoutAliasing(t *testing.T) {
	original := cloneResponse(defaultPassThrough[0])
	metadata, err := structpb.NewStruct(map[string]any{
		"other":                map[string]any{"value": "keep"},
		routeMetadataNamespace: map[string]any{"trace": "keep", routeUpstreamField: map[string]any{"extra": "keep"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	original.DynamicMetadata = metadata
	before := proto.Clone(original)
	result := applyRouteMutation(original, upstreamRoute("192.0.2.10:443", false))
	if !proto.Equal(before, original) {
		t.Fatal("input response modified")
	}
	if responseUpstream(result).GetFields()["extra"].GetStringValue() != "keep" || result.DynamicMetadata.Fields["other"].GetStructValue().Fields["value"].GetStringValue() != "keep" || result.DynamicMetadata.Fields[routeMetadataNamespace].GetStructValue().Fields["trace"].GetStringValue() != "keep" {
		t.Fatal("unrelated metadata lost")
	}
	if applyRouteMutation(result, upstreamRoute("192.0.2.11:443", false)).GetImmediateResponse() == nil {
		t.Fatal("conflicting metadata target accepted")
	}
	invalid := &filter.RouteMutation{Upstream: &filter.UpstreamTarget{}}
	if applyRouteMutation(original, invalid).GetImmediateResponse() == nil {
		t.Fatal("invalid target accepted")
	}
	blocked := immediateFromReply(filter.Reply{Status: 403})
	if applyRouteMutation(blocked, upstreamRoute("192.0.2.10:443", true)) != blocked {
		t.Fatal("blocked response modified")
	}
}

func TestExplicitRouteThroughPolicyEvaluation(t *testing.T) {
	for _, buffered := range []bool{false, true} {
		regs := []filter.Registration{fixedRegHeaders("target", filter.Continue(filter.Mutation{Route: upstreamRoute("192.0.2.99:8443", false)}))}
		cfgs := []any{struct{}{}}
		if buffered {
			regs = append(regs, fixedReg("body", &bodyProbe{}))
			cfgs = append(cfgs, struct{}{})
		}
		server := NewServer(ServerDeps{
			Registrations: regs,
			Resolve: func(context.Context, inputs.Pod, *httpreq.HTTPRequest) (engine.Resolution, error) {
				return engine.Resolution{Units: []engine.Unit{{Cfgs: cfgs}}}, nil
			},
		})
		state := newStreamState()
		responses, err := server.HandleRequestHeaders(context.Background(), makeRequestHeaders("api.example.com:443", "/", "GET"), makeAttrsWithLabels("default", "pod", ""), state)
		if err != nil {
			t.Fatal(err)
		}
		if buffered {
			if responses[0].GetDynamicMetadata() != nil {
				t.Fatal("pending route escaped before body evaluation")
			}
			responses, err = server.HandleRequestBody(context.Background(), &extProcPb.HttpBody{Body: []byte("payload"), EndOfStream: true}, state)
			if err != nil {
				t.Fatal(err)
			}
		}
		if got := responseUpstream(responses[0]).GetFields()[upstreamAddressField].GetStringValue(); got != "192.0.2.99:8443" {
			t.Fatalf("buffered=%v target=%q response=%v", buffered, got, responses)
		}
	}
}

func TestWithoutUpstreamDoesNotEmitTarget(t *testing.T) {
	for _, branch := range []string{"no-profile", "missing-identity", "bypass", "body"} {
		t.Run(branch, func(t *testing.T) {
			var regs []filter.Registration
			switch branch {
			case "bypass":
				regs = []filter.Registration{fixedRegHeaders("bypass", filter.Bypass())}
			case "body":
				regs = []filter.Registration{fixedReg("body", &bodyProbe{})}
			}
			server := NewServer(ServerDeps{
				Registrations: regs,
				Resolve: func(context.Context, inputs.Pod, *httpreq.HTTPRequest) (engine.Resolution, error) {
					if len(regs) == 0 {
						return engine.Resolution{}, nil
					}
					return engine.Resolution{Units: []engine.Unit{{Cfgs: []any{struct{}{}}}}}, nil
				},
			})
			attrs := makeAttrsWithLabels("default", "pod", "")
			if branch == "missing-identity" {
				attrs = nil
			}
			// The former automatic-DNS switch must no longer create a target.
			ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-agentio-resolve-upstream-dns", "true"))
			state := newStreamState()
			responses, err := server.HandleRequestHeaders(ctx, makeRequestHeaders("unresolved.invalid:443", "/", "GET"), attrs, state)
			if err != nil || len(responses) != 1 || responses[0].GetDynamicMetadata() != nil || responses[0].GetImmediateResponse() != nil {
				t.Fatalf("headers=%v err=%v", responses, err)
			}
			if branch == "body" {
				responses, err = server.HandleRequestBody(ctx, &extProcPb.HttpBody{Body: []byte("payload"), EndOfStream: true}, state)
				if err != nil || len(responses) != 1 || responses[0].GetDynamicMetadata() != nil || responses[0].GetImmediateResponse() != nil {
					t.Fatalf("body=%v err=%v", responses, err)
				}
			}
		})
	}
}
