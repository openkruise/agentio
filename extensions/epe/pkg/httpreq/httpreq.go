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

// Package httpreq holds the neutral request tuple shared by the filter
// framework and the policy model. It is a leaf: importing it pulls in no
// policy API, no protos, nothing but the standard library — which is what
// lets the engine's dependency closure stay free of agents-api.
package httpreq

import (
	"net/netip"
	"net/url"
)

// HTTPRequest is the request tuple parsed from Envoy request headers: what
// the caller asked for. Headers is the canonical lowercase-keyed header
// map — the single holder of the request headers for the whole request
// path.
type HTTPRequest struct {
	Host string
	Port int32
	// OriginalDestination is the restored downstream IP:port supplied by Envoy.
	// A zero value means it is unavailable. It is never taken from HTTP headers,
	// and a CONNECT proxy's listener address is not a tunnel destination.
	OriginalDestination netip.AddrPort
	// DNSCandidates are ztunnel-observed names for the original HBONE destination IP.
	// They are candidate names, not an authenticated application Host or TLS SNI.
	DNSCandidates []string
	Path          string
	// Query is the parsed query, convenient for matching. It is lossy:
	// url.ParseQuery drops pairs it cannot parse (';' separators, invalid
	// escapes) and normalizes percent-encoding, so anything that must agree
	// byte-for-byte with the wire — a request signature, above all — has to
	// use RawQuery instead.
	Query url.Values
	// RawQuery is the query exactly as it arrived on :path, before parsing.
	RawQuery string
	Method   string
	Scheme   string
	Headers  map[string]string
}

// HTTPResponse is the response tuple recorded from Envoy response headers.
type HTTPResponse struct {
	Status  int
	Headers map[string]string
}
