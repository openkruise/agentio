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

package egresspolicy

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

func TestExamplePolicy(t *testing.T) {
	raw, err := os.ReadFile("../../../examples/egresspolicy/filter-config.json")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	f := New(filter.RuleConfig[Config]{Cfg: cfg})
	for _, tc := range []struct {
		addr  string
		port  uint16
		allow bool
	}{
		{"169.254.169.254", 443, false}, {"100.100.100.200", 443, false},
		{"10.20.1.2", 443, true}, {"10.20.1.2", 8443, true}, {"10.20.1.2", 80, false},
		{"fd00:20::1", 8443, true}, {"fd00:21::1", 8443, false},
		{"::ffff:10.20.1.2", 443, true},
		{"10.30.1.2", 7999, false}, {"10.30.1.2", 8000, true}, {"10.30.1.2", 8099, true}, {"10.30.1.2", 8100, false},
		{"10.20.1.2", 0, false}, {"fe80::1%eth0", 443, false},
	} {
		t.Run(netip.AddrPortFrom(netip.MustParseAddr(tc.addr), tc.port).String(), func(t *testing.T) {
			a, err := f.OnRequestHeaders(context.Background(), &filter.Stream{Destination: filter.Destination{IP: netip.MustParseAddr(tc.addr), Port: tc.port}})
			if err != nil || (a.Kind() == filter.KindContinue) != tc.allow {
				t.Fatalf("action=%v err=%v", a.Kind(), err)
			}
		})
	}
}

func TestOrderedRulesAndMissingInput(t *testing.T) {
	cfg, err := Parse(json.RawMessage(`{"defaultAction":"allow","denyResponse":{"statusCode":451,"body":"blocked"},"rules":[{"name":"first","match":{"cidrs":["::ffff:10.0.0.0/104"],"ports":[443],"portRanges":[{"start":8000,"end":8099}]},"action":"deny"},{"name":"second","match":{"cidrs":["10.0.0.0/8"]},"action":"allow"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	f := New(filter.RuleConfig[Config]{Cfg: cfg})
	for _, s := range []*filter.Stream{nil, {}, {Destination: filter.Destination{IP: netip.MustParseAddr("10.1.1.1"), Port: 443}}, {Destination: filter.Destination{IP: netip.MustParseAddr("10.1.1.1"), Port: 8000}}} {
		a, err := f.OnRequestHeaders(context.Background(), s)
		r, ok := a.Reply()
		if err != nil || !ok || r.Status != 451 || string(r.Body) != "blocked" {
			t.Fatalf("reply=%v err=%v", r, err)
		}
	}
	for _, ip := range []string{"10.1.1.1", "192.0.2.1"} {
		a, _ := f.OnRequestHeaders(context.Background(), &filter.Stream{Destination: filter.Destination{IP: netip.MustParseAddr(ip), Port: 80}})
		if a.Kind() != filter.KindContinue {
			t.Fatal("expected allow")
		}
	}
}

func TestInvalidConfigs(t *testing.T) {
	for _, raw := range []string{
		`null`, `[]`, `{} {}`, `{"extra":true}`, `{"defaultAction":"bad"}`,
		`{"denyResponse":{"statusCode":200}}`,
		`{"rules":[{"name":"x","match":{},"action":"allow"}]}`,
		`{"rules":[{"match":{"ports":[80]},"action":"allow"}]}`,
		`{"rules":[{"name":"x","match":{"ports":[80]},"action":"allow"},{"name":"x","match":{"ports":[81]},"action":"deny"}]}`,
		`{"rules":[{"name":"x","match":{"ports":[80]},"action":"bad"}]}`,
		`{"rules":[{"name":"x","match":{"cidrs":["bad"]},"action":"allow"}]}`,
		`{"rules":[{"name":"x","match":{"cidrs":["::ffff:10.0.0.0/80"]},"action":"allow"}]}`,
		`{"rules":[{"name":"x","match":{"ports":[0]},"action":"allow"}]}`,
		`{"rules":[{"name":"x","match":{"ports":[65536]},"action":"allow"}]}`,
		`{"rules":[{"name":"x","match":{"ports":[-1]},"action":"allow"}]}`,
		`{"rules":[{"name":"x","match":{"portRanges":[{"start":81,"end":80}]},"action":"allow"}]}`,
		`{"rules":[{"name":"x","match":{"portRanges":[{"start":0,"end":80}]},"action":"allow"}]}`,
		`{"rules":[{"name":"x","match":{"port":[80]},"action":"allow"}]}`,
	} {
		t.Run(raw, func(t *testing.T) {
			if _, err := Parse(json.RawMessage(raw)); err == nil {
				t.Fatal("accepted invalid config")
			}
		})
	}
	cfg, err := Parse(json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	a, _ := New(filter.RuleConfig[Config]{Cfg: cfg}).OnRequestHeaders(context.Background(), &filter.Stream{Destination: filter.Destination{IP: netip.MustParseAddr("10.1.1.1"), Port: 443}})
	r, ok := a.Reply()
	if !ok || r.Status != 403 {
		t.Fatal("default must deny with 403")
	}
}
