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
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type testCfg struct{ V string }

type cfgCapturingFilter struct {
	PassThrough
	cfg RuleConfig[testCfg]
}

func testDescriptor(name string) Descriptor[testCfg] {
	return Descriptor[testCfg]{
		Name:   name,
		Phases: PhaseRequestHeaders,
		New: func(cfg RuleConfig[testCfg]) Filter {
			return &cfgCapturingFilter{cfg: cfg}
		},
	}
}

func testProject(raw json.RawMessage) (testCfg, error) {
	var s struct {
		V string `json:"v"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return testCfg{}, err
	}
	return testCfg{V: s.V}, nil
}

func TestDefinitionRejectsInvalidContracts(t *testing.T) {
	tests := []struct {
		name string
		desc Descriptor[testCfg]
	}{
		{name: "empty name", desc: testDescriptor("")},
		{name: "nil New", desc: func() Descriptor[testCfg] { d := testDescriptor("f"); d.New = nil; return d }()},
		{name: "no phase", desc: func() Descriptor[testCfg] { d := testDescriptor("f"); d.Phases = 0; return d }()},
		{name: "undispatched phase", desc: func() Descriptor[testCfg] { d := testDescriptor("ghost"); d.Phases |= Phase(1 << 7); return d }()},
		{name: "body phase without request headers", desc: func() Descriptor[testCfg] { d := testDescriptor("f"); d.Phases = PhaseRequestBody; return d }()},
		{name: "response body phase without response headers", desc: func() Descriptor[testCfg] { d := testDescriptor("f"); d.Phases = PhaseResponseBody; return d }()},
		// A nil SubscribesOf means no config ever subscribes, so the response
		// pair is skipped at dispatch and the declared phase is unreachable. That
		// is the same defect as the two implications above, and it used to be the
		// only one that failed silently instead of here.
		{
			name: "response headers phase without SubscribesOf",
			desc: func() Descriptor[testCfg] {
				d := testDescriptor("f")
				d.Phases = PhaseRequestHeaders | PhaseResponseHeaders
				return d
			}(),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Build(Define(tc.desc, testProject)); err == nil {
				t.Fatal("Build accepted an invalid descriptor")
			}
		})
	}
}

func TestDefinitionAcceptsMatchingResponsePhases(t *testing.T) {
	d := testDescriptor("response")
	d.Phases = PhaseResponseHeaders | PhaseResponseBody
	// Declaring the phase obliges the descriptor to say when a config wants it.
	d.SubscribesOf = func(testCfg) Phase { return PhaseResponseHeaders }
	if _, err := Build(Define(d, testProject)); err != nil {
		t.Fatalf("Build matching response phases: %v", err)
	}
}

func TestBuildRejectsZeroAndDuplicateDefinitions(t *testing.T) {
	if _, err := Build(Definition{}); err == nil {
		t.Fatal("Build accepted a zero Definition")
	}
	if _, err := Build(Define(testDescriptor("f"), testProject), Define(testDescriptor("f"), testProject)); err == nil {
		t.Fatal("Build accepted duplicate names")
	}
}

func TestDefinitionParsePropagatesError(t *testing.T) {
	boom := errors.New("malformed")
	regs, err := Build(Define(testDescriptor("f"), func(json.RawMessage) (testCfg, error) {
		return testCfg{}, boom
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := regs[0].Parse([]byte(`{}`)); !errors.Is(err, boom) {
		t.Fatalf("Parse err = %v, want boom", err)
	}
}

func TestDefinitionErasedRoundTripIsSingleRule(t *testing.T) {
	regs, err := Build(Define(testDescriptor("f"), testProject))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := regs[0].Parse([]byte(`{"v":"hello"}`))
	if err != nil {
		t.Fatal(err)
	}
	f := regs[0].New(ErasedRuleConfig{ID: UnitID{Scope: "ns/p", Name: "r"}, Cfg: cfg})
	cf, ok := f.(*cfgCapturingFilter)
	if !ok {
		t.Fatalf("New returned %T", f)
	}
	if cf.cfg.Cfg.V != "hello" || cf.cfg.ID.Scope != "ns/p" {
		t.Fatalf("typed config = %+v", cf.cfg)
	}
}

func TestBuildPreservesOrderAndReturnsFreshSlice(t *testing.T) {
	regs, err := Build(
		Define(testDescriptor("first"), testProject),
		Define(testDescriptor("second"), testProject),
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := regs[0].Name + "," + regs[1].Name; got != "first,second" {
		t.Fatalf("order = %s", got)
	}
	regs[0].Name = "mutated"
	again, err := Build(Define(testDescriptor("first"), testProject))
	if err != nil || again[0].Name != "first" {
		t.Fatalf("definition retained caller mutation: regs=%v err=%v", again, err)
	}
}

func TestOnError(t *testing.T) {
	d := testDescriptor("f")
	d.OnError = func(cfg testCfg) FailurePolicy {
		if cfg.V == "open" {
			return FailOpen
		}
		return FailClosed
	}
	regs, err := Build(Define(d, testProject))
	if err != nil {
		t.Fatal(err)
	}
	if got := regs[0].OnError(testCfg{V: "open"}); got != FailOpen {
		t.Fatalf("OnError(open) = %v", got)
	}
	if _, err := Build(Define(Descriptor[testCfg]{Name: "ghost", Phases: Phase(1 << 7), New: d.New}, testProject)); err == nil || !strings.Contains(err.Error(), "ghost") {
		t.Fatalf("undispatched phase error = %v", err)
	}
}
