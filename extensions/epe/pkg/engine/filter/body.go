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

// BodyRequirement describes this invocation's body input, independently of transport.
// The zero value requires a complete body.
type BodyRequirement uint8

const (
	// CompleteBody requires one callback containing the complete body.
	CompleteBody BodyRequirement = iota
	// IncrementalBody accepts repeated callbacks ending with Complete=true,
	// including one complete-body callback. Each callback sees original input.
	// Header preparation must have no external side effects. Body callbacks may
	// Continue with body mutations or Stop, but cannot change headers or Bypass,
	// even when another consumer causes buffered delivery.
	IncrementalBody
)

// BodyMode is the engine's delivery decision. The adapter chooses a supported
// wire protocol; BodyStreamed does not itself enable Envoy full duplex.
type BodyMode uint8

const (
	// BodyNone means no body continuation is outstanding.
	BodyNone BodyMode = iota
	// BodyBuffered requires one complete body, buffered by the caller.
	BodyBuffered
	// BodyStreamed accepts incremental body calls and returns releasable chunks.
	BodyStreamed
)
