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
	"errors"
	"time"

	"github.com/openkruise/agentio/extensions/epe/pkg/audit"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
)

// Matcher is the profile lookup NewResolver needs. It is declared here, on
// the consumer side, rather than imported from pkg/policy/profilestore: the
// store holds *Profile values, so naming that package from this one would be
// an import cycle. The profilestore Store satisfies this implicitly.
//
// ProfilesFor returns every profile that applies to the pod in evaluation
// order: selector-matched administrator profiles first, then the pod's own
// own pod-matched profile (looked up by exact identity, never by labels).
type Matcher interface {
	ProfilesFor(pod inputs.Pod) []*Profile
}

type SnapshotMatcher interface {
	AwaitSnapshot(ctx context.Context, pod inputs.Pod, wait time.Duration) (PolicySnapshot, error)
}

const (
	DefaultSandboxPolicyWait = 200 * time.Millisecond
	policyNotReadyDetails    = "epe_policy_not_ready"
	policyWaitOverloaded     = "epe_policy_wait_overloaded"
	policyUnavailableStatus  = 503
)

type ResolverOption func(*resolverOptions)

type resolverOptions struct {
	sandboxPolicyWait time.Duration
}

func WithSandboxPolicyWait(wait time.Duration) ResolverOption {
	return func(options *resolverOptions) {
		options.sandboxPolicyWait = wait
	}
}

// NewResolver adapts the SecurityProfile store and binder to the ext_proc
// adapter's engine.Resolver seam: profile lookup, rule matching and config
// projection all happen on this side, and the adapter receives neutral
// engine.Units plus one opaque per-stream logger.
//
// This direction of dependency is the point: the policy layer knows the
// adapter's neutral contract, the adapter knows nothing about policy. A
// second policy API supplies its own engine.Resolver and needs no change
// under pkg/engine/.
//
// sink receives the audit events the returned logger produces at stream end.
// A nil sink becomes a no-op, so callers that do not audit need no branch.
func NewResolver(matcher Matcher, regs []filter.Registration, sink audit.Sink, options ...ResolverOption) engine.Resolver {
	binder := newBinder(regs)
	if sink == nil {
		sink = audit.NopSink()
	}
	resolverOptions := resolverOptions{sandboxPolicyWait: DefaultSandboxPolicyWait}
	for _, option := range options {
		option(&resolverOptions)
	}
	return func(ctx context.Context, pod inputs.Pod, req *httpreq.HTTPRequest) (engine.Resolution, error) {
		var profiles []*Profile
		snapshotMatcher, supportsSnapshots := matcher.(SnapshotMatcher)
		if supportsSnapshots {
			snapshot, err := snapshotMatcher.AwaitSnapshot(ctx, pod, resolverOptions.sandboxPolicyWait)
			if errors.Is(err, ErrSandboxPolicyWaitOverloaded) {
				return policyFailure(policyWaitOverloaded), nil
			}
			if err != nil {
				return engine.Resolution{}, err
			}
			// The store's snapshot is the only signal that the caller is a
			// Sandbox: propagated identity is not consulted — ztunnel never
			// emits sandbox.id, and the pod's claimed label is copied from the
			// pod template at creation and never flips — so a Sandbox the store
			// has not observed is an ordinary caller. An observed Sandbox whose
			// policy is not yet usable is the first-claim window: fail closed
			// while Unknown, and otherwise serve the snapshot, which carries
			// the last-known-good inline rules when the newest version was
			// rejected as Invalid. An Invalid first version therefore degrades
			// to the selector-matched administrator profiles instead of
			// blocking traffic a Sandbox author never gave rules to.
			if snapshot.SandboxExists && snapshot.SandboxState == SandboxPolicyUnknown {
				return policyFailure(policyNotReadyDetails), nil
			}
			profiles = snapshot.Profiles
		} else {
			profiles = matcher.ProfilesFor(pod)
		}
		if len(profiles) == 0 {
			return engine.Resolution{}, nil
		}
		units, err := binder.bind(profiles, req, pod)
		if err != nil {
			// The request fails closed, but the rules that matched still
			// describe a stream worth recording. Returning the logger with
			// the error keeps a resolve failure as auditable as an
			// engine-eval failure; Units stays empty so nothing is evaluated.
			return engine.Resolution{StreamLogger: streamLoggerFor(sink, units)}, err
		}
		if len(units) == 0 {
			return engine.Resolution{}, nil
		}
		engineUnits := make([]engine.Unit, len(units))
		for i := range units {
			engineUnits[i] = units[i].Unit
		}
		return engine.Resolution{
			Units: engineUnits,
			// The logger keeps the full units — profile, rule and the match
			// clause that fired — in this package's own types. The adapter
			// invokes it at stream end without naming any of them.
			StreamLogger: streamLoggerFor(sink, units),
		}, nil
	}
}

func policyFailure(details string) engine.Resolution {
	reply := filter.Reply{Status: policyUnavailableStatus, Details: details}
	return engine.Resolution{Failure: &reply}
}

// streamLoggerFor returns nil rather than a logger over zero units: a nil
// logger is how the adapter knows there is nothing to record, and a typed-nil
// in the interface would panic instead.
func streamLoggerFor(sink audit.Sink, units []unit) filter.StreamLogger {
	if len(units) == 0 {
		return nil
	}
	return newStreamLogger(sink, units)
}
