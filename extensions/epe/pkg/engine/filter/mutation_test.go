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
package filter

import (
	"net/netip"
	"testing"
)

func TestMutationEqualComparesRouteValues(t *testing.T) {
	address := netip.MustParseAddrPort("192.0.2.1:443")
	same := address
	different := netip.MustParseAddrPort("192.0.2.2:443")
	mutation := func(a *netip.AddrPort) Mutation {
		return Mutation{Route: &RouteMutation{Upstream: &UpstreamTarget{Address: a}}}
	}
	if !mutation(&address).equal(mutation(&same)) {
		t.Fatal("equal addresses at different pointers must compare equal")
	}
	if mutation(&address).equal(mutation(&different)) || mutation(&address).equal(mutation(nil)) {
		t.Fatal("different or missing addresses must not compare equal")
	}
	if mutation(&address).equal(Mutation{}) {
		t.Fatal("a target mutation must not equal an absent route")
	}
	if (Mutation{Route: &RouteMutation{ClearCache: true}}).equal(Mutation{Route: &RouteMutation{}}) {
		t.Fatal("clearing the route cache must affect mutation equality")
	}
	if err := mutation(nil).Route.Validate(); err == nil {
		t.Fatal("an empty upstream target must be rejected")
	}
	if err := mutation(&address).Route.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSetPathHonorsClearCache(t *testing.T) {
	for _, clear := range []bool{false, true} {
		m := SetPath("/new", clear)
		if m.Route == nil || m.Route.ClearCache != clear {
			t.Errorf("SetPath must preserve clearCache=%v", clear)
		}
		if len(m.HeaderOps) != 1 || m.HeaderOps[0].Kind != HeaderSet || m.HeaderOps[0].Name != ":path" || m.HeaderOps[0].Value != "/new" {
			t.Errorf("SetPath ops = %+v", m.HeaderOps)
		}
	}
}

func TestHeaderHelpers(t *testing.T) {
	if op := SetHeader("a", "1").HeaderOps[0]; op != (HeaderOp{Kind: HeaderSet, Name: "a", Value: "1"}) {
		t.Errorf("SetHeader op = %+v", op)
	}
	if op := AddHeader("a", "2").HeaderOps[0]; op != (HeaderOp{Kind: HeaderAdd, Name: "a", Value: "2"}) {
		t.Errorf("AddHeader op = %+v", op)
	}
	if op := RemoveHeader("a").HeaderOps[0]; op != (HeaderOp{Kind: HeaderRemove, Name: "a"}) {
		t.Errorf("RemoveHeader op = %+v", op)
	}
	if m := SetHeader("a", "1"); m.Route != nil && m.Route.ClearCache {
		t.Error("plain SetHeader must not clear the route cache")
	}
}

func TestMutationEqualComparesStatusValueAndPresence(t *testing.T) {
	statusOK := 200
	statusOKAgain := 200
	statusAccepted := 202

	if !((Mutation{StatusCode: &statusOK}).equal(Mutation{StatusCode: &statusOKAgain})) {
		t.Fatal("equal status values at different addresses must compare equal")
	}
	if (Mutation{StatusCode: &statusOK}).equal(Mutation{StatusCode: &statusAccepted}) {
		t.Fatal("different status values must not compare equal")
	}
	if (Mutation{StatusCode: &statusOK}).equal(Mutation{}) {
		t.Fatal("present and absent status values must not compare equal")
	}
}

// Ops are ordered, so equal must be order-sensitive: a set/append pair
// reversed is a different header outcome, not the same reply.
func TestReplyEqualComparesHeaderOpsInOrder(t *testing.T) {
	setCookieA := HeaderOp{Kind: HeaderAdd, Name: "set-cookie", Value: "a=1"}
	setCookieB := HeaderOp{Kind: HeaderAdd, Name: "set-cookie", Value: "b=2"}

	base := Reply{Status: 403, HeaderOps: []HeaderOp{setCookieA, setCookieB}}
	if !base.equal(Reply{Status: 403, HeaderOps: []HeaderOp{setCookieA, setCookieB}}) {
		t.Fatal("identical op sequences must compare equal")
	}
	if base.equal(Reply{Status: 403, HeaderOps: []HeaderOp{setCookieB, setCookieA}}) {
		t.Fatal("reordered op sequences must not compare equal")
	}
	if base.equal(Reply{Status: 403, HeaderOps: []HeaderOp{setCookieA}}) {
		t.Fatal("op sequences of different length must not compare equal")
	}
	if base.equal(Reply{Status: 403}) {
		t.Fatal("present and absent ops must not compare equal")
	}
	if !(Reply{Status: 403}).equal(Reply{Status: 403, HeaderOps: []HeaderOp{}}) {
		t.Fatal("nil and empty op lists both mean no headers")
	}
	if base.equal(Reply{Status: 403, HeaderOps: []HeaderOp{{Kind: HeaderSet, Name: "set-cookie", Value: "a=1"}, setCookieB}}) {
		t.Fatal("differing op kinds must not compare equal")
	}
}

func TestUnitIDString(t *testing.T) {
	id := UnitID{Scope: "ns/prof", Name: "rule", Ordinal: 2}
	if got := id.String(); got != "ns/prof/rule#2" {
		t.Errorf("UnitID.String() = %q, want %q", got, "ns/prof/rule#2")
	}
}
