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

package trafficpolicy

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/egressauthz"
)

type authorizer struct{}

// NewAuthorizer evaluates the immutable policy snapshot prepared with the caller.
func NewAuthorizer() egressauthz.Authorizer { return authorizer{} }

func (authorizer) Authorize(
	ctx context.Context,
	stream *filter.Stream,
	candidates []netip.AddrPort,
) ([]netip.AddrPort, error) {
	caller := stream.Caller
	if !caller.Subject.Workload.HasIdentity() {
		stream.Info.RecordAuthorization(filter.AuthorizationDecision{
			Action: "deny",
			Reason: filter.AuthorizationReasonMissingIdentity,
		})
		return nil, nil
	}
	if stream.Policies.DestinationAuthorizer == nil {
		return nil, fmt.Errorf("workload policy snapshot is not prepared")
	}
	return stream.Policies.DestinationAuthorizer.Authorize(ctx, stream, candidates)
}
