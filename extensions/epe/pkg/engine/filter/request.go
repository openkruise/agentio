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
	"maps"
	"net/netip"
	"strings"

	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
)

// RequestAfterMutations projects routing headers without changing the matching input.
func RequestAfterMutations(request httpreq.HTTPRequest, ops []HeaderOp) httpreq.HTTPRequest {
	var headers map[string]string
	for _, op := range ops {
		name := strings.ToLower(op.Name)
		if op.Kind != HeaderSet || (name != ":authority" && name != "host" && name != ":scheme" && name != ":method") {
			continue
		}
		if headers == nil {
			headers = maps.Clone(request.Headers)
			if headers == nil {
				headers = make(map[string]string)
			}
		}
		if name == "host" {
			name = ":authority"
		}
		headers[name] = op.Value
	}
	if headers == nil {
		return request
	}
	result := request
	result.Headers = headers
	authority := headers[":authority"]
	if authority == "" {
		authority = headers["host"]
	}
	result.Host, result.Port = httpreq.SplitHostPort(authority)
	result.Method, result.Scheme = headers[":method"], headers[":scheme"]
	if result.Port == 0 && !strings.EqualFold(result.Method, "CONNECT") {
		result.Port = httpreq.InferPortFromScheme(result.Scheme)
	}
	if result.Host != request.Host || result.Port != request.Port {
		result.OriginalDestination = netip.AddrPort{}
	}
	return result
}
