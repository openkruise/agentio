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
	"reflect"
	"testing"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extproc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	agents "github.com/openkruise/agents-api/agents/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/block"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/egressauthz"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
	"github.com/openkruise/agentio/extensions/epe/pkg/policy/profilestore"
	"github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"
	"github.com/openkruise/agentio/pkg/dns"
)

type requestScopeProbe struct {
	filter.PassThrough
	scope *inputs.Scope
	visit func(string, *inputs.Scope, *filter.Stream)
}

func (p requestScopeProbe) OnRequestHeaders(_ context.Context, st *filter.Stream) (filter.Action, error) {
	p.visit("request", p.scope, st)
	return filter.Continue(), nil
}
func (p requestScopeProbe) OnResponseHeaders(_ context.Context, st *filter.Stream) (filter.Action, error) {
	p.visit("response", p.scope, st)
	return filter.Continue(), nil
}

func TestRequestContextPinsPoliciesAndProfileInputs(t *testing.T) {
	var seen []string
	visit := func(phase string, scope *inputs.Scope, st *filter.Stream) {
		t.Helper()
		in, err := scope.Inputs()
		if err != nil {
			t.Fatal(err)
		}
		value := in["routing"].(map[string]string)["target"]
		seen = append(seen, phase+"/"+scope.Profile().Name+"/"+value)
		if len(st.Policies.FilterRules) != 4 || st.Policies.DestinationAuthorizer == nil ||
			st.Caller.Subject.Workload.Labels["version"] != scope.Pod().Labels["version"] ||
			st.Request.Host != scope.Request().Host {
			t.Fatalf("filter received inconsistent context: %+v", st.RequestContext)
		}
	}
	regs, err := filter.Build(filter.Define(filter.Descriptor[string]{
		Name:         block.FilterName,
		Phases:       filter.PhaseRequestHeaders | filter.PhaseResponseHeaders,
		SubscribesOf: func(string) filter.Phase { return filter.PhaseResponseHeaders },
		New: func(rc filter.RuleConfig[string]) filter.Filter {
			return requestScopeProbe{scope: rc.Scope, visit: visit}
		},
	}, func(raw json.RawMessage) (string, error) { return string(raw), nil }))
	if err != nil {
		t.Fatal(err)
	}
	store := profilestore.MakeFakeStore(regs...)
	install := func(version string) {
		action := agents.TCPActionAllow
		if version == "new" {
			action = agents.TCPActionDeny
		}
		for _, name := range []string{"a", "b"} {
			store.ProfileSet(&agents.SecurityProfile{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns"},
				Spec: agents.SecurityProfileSpec{
					TCPRules: []agents.TCPRule{
						{
							Name:   "destination",
							Action: action,
							Match:  []agents.TCPMatch{{CIDRs: []string{"203.0.113.0/24"}}},
						},
					},
					Inputs: []agents.SecurityProfileInput{
						{Name: "routing", Inline: map[string]string{"target": name + "-" + version}},
					},
					Rules: []agents.SecurityRule{
						{
							Name:    "probe",
							Match:   []agents.RuleMatch{{Domains: []string{"*"}}},
							Actions: agents.SecurityRuleActions{Block: &agents.BlockAction{StatusCode: 451}},
						},
					},
				},
			})
		}
	}
	install("old")
	version := "old"
	targets := egressauthz.NewAggregate(dns.NewClient(nil, 0))
	srv := NewServer(ServerDeps{
		ResolveContext: func(_ context.Context, request filter.RequestContext) (filter.RequestContext, error) {
			request.Caller.Subject.Workload.Labels = map[string]string{"version": version}
			request.Caller.Subject.Workload.SecurityProfileReferences = []string{"namespaced/ns/a", "namespaced/ns/b"}
			return request, nil
		},
		Resolve:          securityprofile.NewResolver(store, regs, nil, targets),
		Registrations:    regs,
		AuthorizeRequest: targets.Authorize,
	})
	headers := makeRequestHeaders("203.0.113.7:443", "/", "GET")
	headers.EndOfStream = true
	attrs := makeAttrsWithLabels("ns", "pod", testLabelsB64)
	state := newStreamState()
	if _, err := srv.HandleRequestHeaders(t.Context(), headers, attrs, state); err != nil {
		t.Fatal(err)
	}
	pinned := state.stream.Policies.DestinationAuthorizer
	install("new")
	version = "new"
	if _, err := srv.HandleResponseHeaders(
		t.Context(),
		&extproc.HttpHeaders{
			Headers:     &core.HeaderMap{Headers: []*core.HeaderValue{{Key: ":status", Value: "200"}}},
			EndOfStream: true,
		},
		state,
	); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(state.stream.Policies.DestinationAuthorizer, pinned) ||
		state.stream.Caller.Subject.Workload.Labels["version"] != "old" {
		t.Fatal("source update replaced in-flight snapshot")
	}
	responses, err := srv.HandleRequestHeaders(t.Context(), headers, attrs, newStreamState())
	if err != nil || responses[0].GetImmediateResponse().GetStatus().GetCode() != 403 {
		t.Fatalf("new request did not use updated TCP policy: %v %v", responses, err)
	}
	want := []string{
		"request/a/a-old",
		"response/a/a-old",
		"request/a/a-new",
	}
	if !reflect.DeepEqual(seen, want) {
		t.Fatalf("scopes mixed across profiles or requests: got %v want %v", seen, want)
	}
}
