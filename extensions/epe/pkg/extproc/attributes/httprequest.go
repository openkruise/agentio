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
package attributes

import (
	"context"
	"maps"
	"net/url"
	"strconv"
	"strings"

	log "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/logging"
)

// splitHostPort extracts (host, port) from a request authority. IPv6
// authorities in bracket form (e.g. "[::1]:8080") are returned without the
// brackets and the trailing port. A non-numeric or out-of-range port is
// returned as 0 (no match for any non-empty Ports list).
func splitHostPort(authority string) (string, int32) {
	if authority == "" {
		return "", 0
	}
	if authority[0] == '[' {
		end := strings.IndexByte(authority, ']')
		if end <= 0 {
			return authority, 0
		}
		host := authority[1:end]
		if end+1 < len(authority) && authority[end+1] == ':' {
			return host, parsePort(authority[end+2:])
		}
		return host, 0
	}
	if idx := strings.IndexByte(authority, ':'); idx >= 0 {
		return authority[:idx], parsePort(authority[idx+1:])
	}
	return authority, 0
}

// parsePort returns the port number, or 0 when the input is empty,
// non-numeric, or out of the [1, 65535] range.
func parsePort(s string) int32 {
	if s == "" {
		return 0
	}
	v, err := strconv.Atoi(s)
	if err != nil || v <= 0 || v > 65535 {
		return 0
	}
	return int32(v)
}

// splitPathAndQuery separates the "/path" and "query=string" halves of a
// raw ":path" pseudo-header. The returned query is the verbatim text after
// the first "?" (empty when the path has no query).
func splitPathAndQuery(rawPath string) (string, string) {
	if idx := strings.IndexByte(rawPath, '?'); idx >= 0 {
		return rawPath[:idx], rawPath[idx+1:]
	}
	return rawPath, ""
}

// parseHTTPRequest extracts httpreq.HTTPRequest from Envoy header values.
// Envoy sends pseudo-headers (:method, :path, :authority, :scheme) and the
// Host header. :authority is the gRPC/HTTP2 equivalent of Host.
//
// Splits performed here:
//   - :authority "host:port"  -> Host, Port
//   - :path "/p?q=1"          -> Path, Query
//
// Port inference: for ordinary requests whose :authority does not include an
// explicit port, the default is taken from :scheme — http=80, https=443. A
// CONNECT authority must name its target port explicitly; its :scheme belongs
// to the proxy hop and is never used to invent a tunnel target port. The
// :scheme value itself is stored on HTTPRequest.Scheme.
//
// Query-string parse errors are logged at DEBUG via the logger in ctx (the
// returned Query still holds whatever url.ParseQuery managed to extract).
func parseHTTPRequest(ctx context.Context, headers map[string]string) httpreq.HTTPRequest {
	info := httpreq.HTTPRequest{Headers: headers}

	if auth, ok := headers[":authority"]; ok && auth != "" {
		info.Host, info.Port = splitHostPort(auth)
	} else if host, ok := headers["host"]; ok && host != "" {
		info.Host, info.Port = splitHostPort(host)
	}

	if info.Port == 0 && !strings.EqualFold(headers[":method"], "CONNECT") {
		info.Port = inferPortFromScheme(headers[":scheme"])
	}

	if path, ok := headers[":path"]; ok {
		var rawQuery string
		info.Path, rawQuery = splitPathAndQuery(path)
		info.RawQuery = rawQuery
		if rawQuery != "" {
			var err error
			info.Query, err = url.ParseQuery(rawQuery)
			if err != nil {
				log.FromContext(ctx).V(logging.DEBUG).Info(
					"failed to parse request query string; using partial result",
					"rawQuery", rawQuery, "error", err)
			}
		}
	}

	if method, ok := headers[":method"]; ok {
		info.Method = method
	}

	if scheme, ok := headers[":scheme"]; ok {
		info.Scheme = scheme
	}

	return info
}

// inferPortFromScheme returns the conventional default port for the scheme,
// or 0 when the scheme is empty or unrecognized.
func inferPortFromScheme(scheme string) int32 {
	switch strings.ToLower(scheme) {
	case "http":
		return 80
	case "https":
		return 443
	default:
		return 0
	}
}

// RequestAfterMutations projects routing-header replacements for final target
// authorization without changing the original request used for rule matching.
func RequestAfterMutations(
	ctx context.Context,
	request httpreq.HTTPRequest,
	ops []filter.HeaderOp,
) httpreq.HTTPRequest {
	var headers map[string]string
	for _, op := range ops {
		name := strings.ToLower(op.Name)
		if name != ":authority" && name != "host" && name != ":scheme" && name != ":method" {
			continue
		}
		// Routing headers cannot be removed. Appending is not a routing rewrite.
		if op.Kind != filter.HeaderSet {
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
	result := parseHTTPRequest(ctx, headers)
	// A rewritten destination must not reuse the previous destination's IP.
	if result.Host == request.Host && result.Port == request.Port {
		result.OriginalDestination = request.OriginalDestination
		result.DNSCandidates = request.DNSCandidates
	}
	return result
}
