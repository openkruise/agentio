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

package egressauthz

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/pkg/dns"
)

// resolveDNS returns candidates using the client's cache/custom records.
// Authorization and target selection happen together in OnRequestHeaders.
func resolveDNS(ctx context.Context, client *dns.Client, stream *filter.Stream, family dns.Family) ([]netip.Addr, error) {
	if client == nil {
		return nil, fmt.Errorf("DNS client is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if stream == nil {
		return nil, fmt.Errorf("request stream is required")
	}
	request := stream.Request
	if request.Port <= 0 || request.Port > 65535 {
		return nil, fmt.Errorf("invalid request port: %d", request.Port)
	}
	ip, err := netip.ParseAddr(request.Host)
	if err == nil {
		ip = ip.Unmap()
		if ip.Zone() != "" {
			return nil, fmt.Errorf("scoped upstream address is not supported")
		}
		if family == dns.IPv4Only && !ip.Is4() || family == dns.IPv6Only && !ip.Is6() {
			return nil, dns.ErrNoAddresses
		}
	} else {
		result, err := client.Resolve(ctx, request.Host, family)
		if err != nil {
			return nil, err
		}
		return result.Addresses, nil
	}
	return []netip.Addr{ip}, nil
}
