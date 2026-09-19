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
package securityprofile

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/block"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
)

// A matched resolution must carry the per-stream audit logger. Nothing else
// wires it: the logger left the static logger list when the units stopped
// travelling through StreamInfo.Metadata, so if the resolver forgets it, audit
// events silently never fire and only the end-to-end delivery tests notice.
func TestResolverSuppliesStreamLoggerWhenPolicyMatches(t *testing.T) {
	regs := claimAll(t, nil)

	p := compile(t, regs, "p", "ns", "1", []v1alpha1.SecurityRule{matchAllRule("r")})
	resolve := NewResolver(benchStore{profiles: []*Profile{p}}, regs, nil)

	res, err := resolve(context.Background(), inputs.Pod{}, testRequest("example.com"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(res.Units) != 1 {
		t.Fatalf("units = %d, want 1", len(res.Units))
	}
	if res.StreamLogger == nil {
		t.Fatal("resolution carries no stream logger; audit events would never fire")
	}
}

// A projection failure fails the request closed, but the profile still
// matched and its audit entries still describe a stream worth recording —
// with result="error", which is exactly the case an operator writes an audit
// rule for. Returning the logger alongside the error keeps this symmetric
// with an engine-eval failure, which the adapter already audits.
func TestResolverSuppliesStreamLoggerWhenProjectionFails(t *testing.T) {
	boom := errors.New("malformed")
	regs, err := filter.Build(filter.Define(filter.Descriptor[string]{
		Name:   block.FilterName,
		Phases: filter.PhaseRequestHeaders,
		New:    func(filter.RuleConfig[string]) filter.Filter { return nopFilter{} },
	}, func(json.RawMessage) (string, error) { return "", boom }))
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	p := compile(t, regs, "p", "ns", "1", []v1alpha1.SecurityRule{matchAllRule("r")})
	resolve := NewResolver(benchStore{profiles: []*Profile{p}}, regs, nil)

	res, err := resolve(context.Background(), inputs.Pod{}, testRequest("example.com"))
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the wrapped projection error", err)
	}
	if len(res.Units) != 0 {
		t.Errorf("units = %d, want 0: a failed projection must not be evaluated", len(res.Units))
	}
	if res.StreamLogger == nil {
		t.Fatal("resolution carries no stream logger; a resolve failure would never be audited")
	}
}

// The zero resolutions must stay zero: a nil logger is how the adapter knows
// there is nothing to log, and a non-nil logger over zero units would emit an
// empty audit pass for every unmatched request.
func TestResolverOmitsStreamLoggerWhenNothingMatches(t *testing.T) {
	regs := claimAll(t, nil)

	for _, tc := range []struct {
		name  string
		store benchStore
	}{
		{name: "no profiles match the pod", store: benchStore{}},
		{
			name:  "profile matches but no rule fires",
			store: benchStore{profiles: []*Profile{compile(t, regs, "p", "ns", "1", nil)}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolve := NewResolver(tc.store, regs, nil)
			res, err := resolve(context.Background(), inputs.Pod{}, testRequest("example.com"))
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if len(res.Units) != 0 {
				t.Fatalf("units = %d, want 0", len(res.Units))
			}
			if res.StreamLogger != nil {
				t.Fatalf("stream logger = %T, want nil when no policy applies", res.StreamLogger)
			}
		})
	}
}

// A nil sink must not reach the logger: NewResolver substitutes the no-op sink
// so callers that do not audit need no branch, and Enqueue never runs against
// a nil interface.
func TestResolverNilSinkBecomesNoop(t *testing.T) {
	regs := claimAll(t, nil)

	p := compile(t, regs, "p", "ns", "1", []v1alpha1.SecurityRule{matchAllRule("r")})
	resolve := NewResolver(benchStore{profiles: []*Profile{p}}, regs, nil)

	res, err := resolve(context.Background(), inputs.Pod{}, testRequest("example.com"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	l, ok := res.StreamLogger.(*streamLogger)
	if !ok {
		t.Fatalf("stream logger = %T, want *streamLogger", res.StreamLogger)
	}
	if l.sink == nil {
		t.Fatal("nil sink was passed through; Enqueue would panic on a matched audit entry")
	}
}

type snapshotMatcher struct {
	benchStore
	snapshot PolicySnapshot
	err      error
	wait     time.Duration
	calls    int
}

func (s *snapshotMatcher) AwaitSnapshot(_ context.Context, _ inputs.Pod, wait time.Duration) (PolicySnapshot, error) {
	s.wait = wait
	s.calls++
	return s.snapshot, s.err
}

func sandboxPod() inputs.Pod {
	return inputs.Pod{Name: "sbx-1", Namespace: "sandboxes"}
}

// The readiness gate is keyed on the store's own snapshot, never on propagated
// labels: a pod that merely carries the claimed label, without a Sandbox the
// store has observed, is an ordinary caller and must pass immediately. The
// label is what label propagation happens to say, not proof of identity — and
// the removed sandbox.id header never existed in any released ztunnel, so a
// gate that needs either of them cannot fail closed where it matters.
func TestResolverGateKeysOnStoreNotPropagatedLabels(t *testing.T) {
	matcher := &snapshotMatcher{snapshot: PolicySnapshot{SandboxState: SandboxPolicyUnknown}}
	resolve := NewResolver(matcher, nil, nil, WithSandboxPolicyWait(25*time.Millisecond))

	res, err := resolve(context.Background(), inputs.Pod{
		Name: "sbx-1", Namespace: "sandboxes",
		Labels: map[string]string{v1alpha1.LabelSandboxIsClaimed: v1alpha1.True},
	}, testRequest("example.com"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.Failure != nil {
		t.Fatalf("failure = %+v, want passthrough: a propagated label must not gate traffic", res.Failure)
	}
	if matcher.calls != 1 {
		t.Fatalf("AwaitSnapshot calls = %d, want 1", matcher.calls)
	}
}

// The store retains the last-known-good inline version while a newer one is
// rejected as Invalid. The request path honors the same last-known-good
// contract: blocking on Invalid would turn a rejected policy version into an
// egress outage for a Sandbox whose earlier rules are still enforceable.
func TestResolverInvalidPolicyServesRetainedRules(t *testing.T) {
	regs := claimAll(t, nil)
	retained := compile(t, regs, "sbx-1", "sandboxes", "2", []v1alpha1.SecurityRule{matchAllRule("r")})
	matcher := &snapshotMatcher{snapshot: PolicySnapshot{
		Profiles:      []*Profile{retained},
		SandboxExists: true,
		SandboxState:  SandboxPolicyInvalid,
	}}
	resolve := NewResolver(matcher, regs, nil)

	res, err := resolve(context.Background(), sandboxPod(), testRequest("example.com"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.Failure != nil {
		t.Fatalf("failure = %+v, want the retained rules served instead", res.Failure)
	}
	if len(res.Units) != 1 {
		t.Fatalf("units = %d, want the retained profile's unit", len(res.Units))
	}
}

// A Sandbox whose first rules version never compiled has no inline chain to
// fall back on: the request degrades to the selector-matched administrator
// profiles instead of failing closed.
func TestResolverFirstInvalidVersionPassesWithoutInlineRules(t *testing.T) {
	regs := claimAll(t, nil)
	matcher := &snapshotMatcher{snapshot: PolicySnapshot{
		SandboxExists: true,
		SandboxState:  SandboxPolicyInvalid,
	}}
	resolve := NewResolver(matcher, regs, nil)

	res, err := resolve(context.Background(), sandboxPod(), testRequest("example.com"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.Failure != nil {
		t.Fatalf("failure = %+v, want passthrough for a Sandbox with no enforceable inline rules", res.Failure)
	}
	if len(res.Units) != 0 {
		t.Fatalf("units = %d, want 0 with nothing retained", len(res.Units))
	}
}

func TestResolverStoreRecognizedSandboxWithoutPropagatedIdentityWaitsForPolicy(t *testing.T) {
	matcher := &snapshotMatcher{snapshot: PolicySnapshot{
		SandboxExists: true,
		SandboxState:  SandboxPolicyUnknown,
	}}
	resolve := NewResolver(matcher, nil, nil, WithSandboxPolicyWait(25*time.Millisecond))

	res, err := resolve(context.Background(), inputs.Pod{
		Name: "sbx-1", Namespace: "sandboxes",
	}, testRequest("example.com"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.Failure == nil || res.Failure.Status != 503 || res.Failure.Details != policyNotReadyDetails {
		t.Fatalf("failure = %+v, want 503/%s", res.Failure, policyNotReadyDetails)
	}
	if matcher.calls != 1 {
		t.Fatalf("AwaitSnapshot calls = %d, want 1", matcher.calls)
	}
}

type blockingSnapshotMatcher struct {
	benchStore
	entered chan struct{}
	ready   chan PolicySnapshot
}

func (s *blockingSnapshotMatcher) AwaitSnapshot(ctx context.Context, _ inputs.Pod, _ time.Duration) (PolicySnapshot, error) {
	close(s.entered)
	select {
	case snapshot := <-s.ready:
		return snapshot, nil
	case <-ctx.Done():
		return PolicySnapshot{}, ctx.Err()
	}
}

func TestResolverOrdinaryPodDoesNotEnterSandboxReadinessGate(t *testing.T) {
	matcher := &snapshotMatcher{snapshot: PolicySnapshot{SandboxState: SandboxPolicyUnknown}}
	resolve := NewResolver(matcher, nil, nil, WithSandboxPolicyWait(25*time.Millisecond))

	res, err := resolve(context.Background(), inputs.Pod{
		Name: "pod-1", Namespace: "default", Labels: map[string]string{"app": "client"},
	}, testRequest("example.com"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.Failure != nil {
		t.Fatalf("failure = %+v, want ordinary Pod passthrough", res.Failure)
	}
	if matcher.calls != 1 {
		t.Fatalf("AwaitSnapshot calls = %d, want one immediate Store lookup", matcher.calls)
	}
}

func TestResolverPreClaimSandboxRequestWakesOnReadySnapshot(t *testing.T) {
	matcher := &blockingSnapshotMatcher{
		entered: make(chan struct{}),
		ready:   make(chan PolicySnapshot, 1),
	}
	resolve := NewResolver(matcher, nil, nil, WithSandboxPolicyWait(time.Second))
	result := make(chan engine.Resolution, 1)
	errCh := make(chan error, 1)
	go func() {
		resolution, err := resolve(context.Background(), inputs.Pod{
			Name: "sbx-1", Namespace: "sandboxes",
		}, testRequest("example.com"))
		result <- resolution
		errCh <- err
	}()

	select {
	case <-matcher.entered:
	case <-time.After(time.Second):
		t.Fatal("request did not enter AwaitSnapshot")
	}
	matcher.ready <- PolicySnapshot{SandboxExists: true, SandboxState: SandboxPolicyReadyEmpty}

	if err := <-errCh; err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolution := <-result; resolution.Failure != nil {
		t.Fatalf("failure = %+v, want request released by ready snapshot", resolution.Failure)
	}
}

func TestResolverSandboxReadinessFailures(t *testing.T) {
	tests := []struct {
		name    string
		state   SandboxPolicyState
		err     error
		details string
	}{
		{name: "not ready", state: SandboxPolicyUnknown, details: "epe_policy_not_ready"},
		{name: "overloaded", state: SandboxPolicyUnknown, err: ErrSandboxPolicyWaitOverloaded, details: "epe_policy_wait_overloaded"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := &snapshotMatcher{snapshot: PolicySnapshot{SandboxExists: true, SandboxState: tt.state}, err: tt.err}
			resolve := NewResolver(matcher, nil, nil, WithSandboxPolicyWait(25*time.Millisecond))
			res, err := resolve(context.Background(), sandboxPod(), testRequest("example.com"))
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if res.Failure == nil || res.Failure.Status != 503 || res.Failure.Details != tt.details {
				t.Fatalf("failure = %+v, want 503/%s", res.Failure, tt.details)
			}
			if matcher.wait != 25*time.Millisecond {
				t.Fatalf("wait = %v, want 25ms", matcher.wait)
			}
		})
	}
}

func TestResolverReadyEmptyUsesProfilesFromSameSnapshot(t *testing.T) {
	regs := claimAll(t, nil)
	admin := compile(t, regs, "admin", "ns", "1", []v1alpha1.SecurityRule{matchAllRule("r")})
	matcher := &snapshotMatcher{
		benchStore: benchStore{profiles: nil},
		snapshot: PolicySnapshot{
			Profiles:      []*Profile{admin},
			SandboxExists: true,
			SandboxState:  SandboxPolicyReadyEmpty,
		},
	}
	resolve := NewResolver(matcher, regs, nil)

	res, err := resolve(context.Background(), sandboxPod(), testRequest("example.com"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.Failure != nil {
		t.Fatalf("failure = %+v, want none", res.Failure)
	}
	if len(res.Units) != 1 || res.Units[0].ID.Scope != "ns/admin" {
		t.Fatalf("units = %+v, want administrator profile from captured snapshot", res.Units)
	}
}
