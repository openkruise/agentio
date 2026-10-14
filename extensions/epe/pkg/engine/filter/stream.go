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

import "github.com/openkruise/agentio/extensions/epe/pkg/httpreq"

// Body is one direction's original body input. Complete-body consumers receive
// it once; explicitly incremental consumers may receive multiple chunks.
// Bytes is read-only. A filter retaining it beyond the callback must copy it.
type Body struct {
	Bytes []byte
	// Complete marks the final input. In buffered delivery Bytes is the whole
	// body; in incremental delivery it is only the final chunk, possibly empty.
	Complete bool
}

// Stream is the per-request view handed to every filter. Filters must treat
// its fields as read-only.
type Stream struct {
	Peer      Peer
	Request   httpreq.HTTPRequest
	RequestID string
	// Upstream is the destination selected by preceding request filters.
	// The engine supplies a read-only view, reusing it while routing is unchanged.
	// Routing filters must precede authorization.
	Upstream *UpstreamTarget
	// Response is populated from OnResponseHeaders onward.
	Response httpreq.HTTPResponse
	// Info accumulates per-stream observations; the engine writes execution
	// records, content filters use RecordContent, and stream loggers read them.
	Info *StreamInfo
}
