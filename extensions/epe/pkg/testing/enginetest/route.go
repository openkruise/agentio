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

package enginetest

import (
	"net/netip"
	"strconv"
	"testing"

	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/protobuf/types/known/structpb"
)

// RequireUpstream checks the target actually emitted on the ext_proc wire,
// including the separate address, IP and port fields consumed by the proxy.
// It returns the sole response carrying that target for phase-specific checks.
func (v *Verdict) RequireUpstream(t *testing.T, want string) *extProcPb.ProcessingResponse {
	t.Helper()
	v.requireNoErr(t)
	address := netip.MustParseAddrPort(want)
	var found *extProcPb.ProcessingResponse
	for _, response := range v.Raw {
		upstream := wireUpstream(response)
		if upstream == nil {
			continue
		}
		if found != nil {
			t.Fatal("upstream target emitted more than once")
		}
		found = response
		fields := upstream.GetFields()
		if fields["address"].GetStringValue() != want ||
			fields["ip"].GetStringValue() != address.Addr().String() ||
			fields["port"].GetStringValue() != strconv.Itoa(int(address.Port())) {
			t.Fatalf("upstream metadata=%v, want %s", upstream, want)
		}
		if response.GetRequestHeaders() == nil && response.GetRequestBody() == nil {
			t.Fatalf("upstream emitted outside request processing: %v", response)
		}
	}
	if found == nil {
		t.Fatalf("missing upstream target %s: %v", want, v.Raw)
	}
	return found
}

// RequireNoUpstream checks every response, including responses preceding a deny.
func (v *Verdict) RequireNoUpstream(t *testing.T) {
	t.Helper()
	for _, response := range v.Raw {
		if upstream := wireUpstream(response); upstream != nil {
			t.Fatalf("unexpected upstream target: %v", upstream)
		}
	}
}

func wireUpstream(response *extProcPb.ProcessingResponse) *structpb.Struct {
	return response.GetDynamicMetadata().GetFields()["agentio.route"].
		GetStructValue().GetFields()["upstream"].GetStructValue()
}
