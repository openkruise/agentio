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

package egresspolicy_test

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/block"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/egresspolicy"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
	"github.com/openkruise/agentio/extensions/epe/pkg/testing/enginetest"
)

func TestCallerDestinationThroughExtProc(t *testing.T) {
	regs, err := filter.Build(egresspolicy.Definition(), block.Definition())
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"CONNECT", "GET", "POST"} {
		for _, tc := range []struct {
			name, ip        string
			subsequentBlock bool
			status          int
		}{
			{"allow", "10.20.1.2", false, 0}, {"deny", "192.0.2.1", false, 403}, {"missing", "", false, 403}, {"continue-chain", "10.20.1.2", true, 451},
		} {
			t.Run(method+"/"+tc.name, func(t *testing.T) {
				payloads := map[string]json.RawMessage{egresspolicy.FilterName: json.RawMessage(`{"rules":[{"name":"https","match":{"cidrs":["10.20.0.0/16"],"ports":[443]},"action":"allow"}]}`)}
				if tc.subsequentBlock {
					payloads[block.FilterName] = json.RawMessage(`{"statusCode":451}`)
				}
				cfgs, errs := filter.Project(regs, payloads)
				for _, err := range errs {
					if err != nil {
						t.Fatal(err)
					}
				}
				h := enginetest.New(t, enginetest.Options{Registrations: regs, Resolve: func(context.Context, inputs.Pod, *httpreq.HTTPRequest) (engine.Resolution, error) {
					var dst filter.Destination
					if tc.ip != "" {
						dst = filter.Destination{IP: netip.MustParseAddr(tc.ip), Port: 443}
					}
					return engine.Resolution{Destination: dst, Units: []engine.Unit{{ID: filter.UnitID{Scope: "test", Name: "rule"}, Cfgs: cfgs}}}, nil
				}})
				// Deliberately conflicting authority: only caller-supplied destination counts.
				req := enginetest.NewRequest(method, "203.0.113.1:80", "/").Peer("default", "sandbox", nil)
				if method == "CONNECT" {
					req.StreamingHeaders()
				}
				v := h.Run(t, req)
				if v.Err != nil {
					t.Fatal(v.Err)
				}
				if tc.status != 0 {
					v.RequireBlocked(t, tc.status)
				} else {
					v.RequirePassthrough(t)
				}
			})
		}
	}
}
