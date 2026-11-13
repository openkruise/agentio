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

	"github.com/openkruise/agentio/extensions/epe/pkg/audit"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/egressauthz"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
)

// Matcher is the profile lookup NewResolver needs. It is declared here, on
// the consumer side, rather than imported from pkg/policy/profilestore: the
// store holds *Profile values, so naming that package from this one would be
// an import cycle. The profilestore Store satisfies this implicitly.
//
// ResolveProfiles returns policies bound to the subject in evaluation order,
// waiting for initial Sandbox policy readiness. The backend owns binding lookup;
// callers do not depend on local selectors or the representation of xDS bindings.
type Matcher interface {
	ResolveProfiles(context.Context, subject.Subject) ([]*Profile, error)
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
func NewResolver(
	matcher Matcher,
	regs []filter.Registration,
	sink audit.Sink,
	targets *egressauthz.Aggregate,
) engine.Resolver {
	binder := newBinder(regs, targets)
	if sink == nil {
		sink = audit.NopSink()
	}
	return func(ctx context.Context, subject subject.Subject, req *httpreq.HTTPRequest) (engine.Resolution, error) {
		profiles, err := matcher.ResolveProfiles(ctx, subject)
		if err != nil {
			return engine.Resolution{}, err
		}
		if len(profiles) == 0 {
			return engine.Resolution{}, nil
		}
		bound, err := binder.bind(profiles, req, inputs.WorkloadFromSubject(subject))
		if err != nil {
			// The request fails closed, but the rules that matched still
			// describe a stream worth recording. Returning the logger with
			// the error keeps a resolve failure as auditable as an
			// engine-eval failure; Units stays empty so nothing is evaluated.
			return engine.Resolution{StreamLogger: streamLoggerFor(sink, bound.rules)}, err
		}

		return engine.Resolution{
			Units:                 bound.units,
			DestinationAuthorizer: bound.authorizer,
			// The logger keeps the full units — profile, rule and the match
			// clause that fired — in this package's own types. The adapter
			// invokes it at stream end without naming any of them.
			StreamLogger: streamLoggerFor(sink, bound.rules),
		}, nil
	}
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
