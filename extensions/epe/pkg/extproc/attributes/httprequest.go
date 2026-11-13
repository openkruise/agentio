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
	"net/url"
	"strings"

	log "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/logging"
)

func splitHostPort(authority string) (string, int32) { return httpreq.SplitHostPort(authority) }
func inferPortFromScheme(scheme string) int32        { return httpreq.InferPortFromScheme(scheme) }

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

// RequestAfterMutations projects routing-header replacements for final target
// authorization without changing the original request used for rule matching.
func RequestAfterMutations(
	ctx context.Context,
	request httpreq.HTTPRequest,
	ops []filter.HeaderOp,
) httpreq.HTTPRequest {
	return filter.RequestAfterMutations(request, ops)
}
