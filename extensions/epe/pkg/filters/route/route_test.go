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

package route

import (
	"context"
	"net/netip"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
)

func run(t *testing.T, f filter.Filter, host string, port int32) *filter.RouteMutation {
	t.Helper()
	action, err := f.OnRequestHeaders(context.Background(), &filter.Stream{
		Request: httpreq.HTTPRequest{Host: host, Port: port},
	})
	if err != nil {
		t.Fatal(err)
	}
	if action.Kind() != filter.KindContinue || len(action.Mutations()) != 1 {
		t.Fatalf("unexpected action: %+v", action)
	}
	return action.Mutations()[0].Route
}

func TestConfigSnapshotsAndIsolatesRequests(t *testing.T) {
	address := netip.MustParseAddrPort("192.0.2.1:443")
	f := New(filter.RuleConfig[Config]{Cfg: Config{
		Upstream: &filter.UpstreamTarget{Address: &address},
	}})
	address = netip.MustParseAddrPort("192.0.2.2:80")
	first := run(t, f, "unrelated.example", 80)
	if first.Upstream.Address.String() != "192.0.2.1:443" || first.ClearCache {
		t.Fatalf("unexpected route: %+v", first)
	}
	*first.Upstream.Address = address
	if next := run(t, f, "", 0); next.Upstream.Address.String() != "192.0.2.1:443" {
		t.Fatal("requests share mutable route state")
	}
}

func TestInvalidConfigDoesNotProduceMutations(t *testing.T) {
	for _, cfg := range []Config{
		{},
		{Upstream: &filter.UpstreamTarget{}},
	} {
		f := New(filter.RuleConfig[Config]{Cfg: cfg})
		action, err := f.OnRequestHeaders(context.Background(), &filter.Stream{})
		if err == nil || len(action.Mutations()) != 0 {
			t.Fatalf("action=%+v, err=%v", action, err)
		}
	}
	if d := Descriptor(); d.Phases != filter.PhaseRequestHeaders || d.OnError(Config{}) != filter.FailClosed {
		t.Fatal("route must run at request headers with FailClosed")
	}
}
