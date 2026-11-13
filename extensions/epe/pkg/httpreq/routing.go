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

package httpreq

import (
	"strconv"
	"strings"
)

// SplitHostPort extracts (host, port) from a request authority. IPv6
// authorities in bracket form (e.g. "[::1]:8080") are returned without the
// brackets and the trailing port. A non-numeric or out-of-range port is
// returned as 0 (no match for any non-empty Ports list).
func SplitHostPort(authority string) (string, int32) {
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
	if host, port, ok := strings.Cut(authority, ":"); ok {
		return host, parsePort(port)
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

// InferPortFromScheme returns the conventional default port for the scheme,
// or 0 when the scheme is empty or unrecognized.
func InferPortFromScheme(scheme string) int32 {
	switch strings.ToLower(scheme) {
	case "http":
		return 80
	case "https":
		return 443
	default:
		return 0
	}
}
