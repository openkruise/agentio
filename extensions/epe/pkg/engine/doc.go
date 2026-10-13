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

// Package engine evaluates rules in policy order and actions within each
// rule in registration order. It owns request and response body continuation,
// the per-phase evaluation budget, the per-invocation metrics wrapper,
// failure-policy reduction, and net-effect mutation folding. It knows the
// filter contract and nothing else — no policy API, no ext_proc protos;
// assembly lives in pkg/wiring.
//
// # Phase subscription and body continuation
//
// Config declares response-header subscriptions before evaluation so the adapter
// can open that phase on its request-header reply. Body demand remains dynamic.
// Both directions finish headers in order, registering NeedBody callbacks for
// the body phase. Request authorization pins the final target before body runs.
// Header Bypass preserves registered body callbacks; Stop discards them.
// Body Stop/Bypass skips later body callbacks, not headers that already ran.
//
// Complete request-body callbacks run in registration order against the original
// request and body, with the authorized upstream target available in their view.
// Buffered delivery holds rule mutations until body completion; the adapter may
// publish the authorized target at headers. Streaming commits header mutations
// before any chunk is released. Body callbacks cannot change the pinned route.
//
// Invocation errors are resolved through the registration's FailurePolicy.
// FailOpen records and skips the failed invocation. FailClosed returns a local
// 500 blocked result without an engine error. Contract and protocol faults stay
// on the error channel for the ext_proc adapter and Envoy failure mode.
//
// # Incremental body consumers
//
// NeedBody(IncrementalBody) opts this invocation into repeated body callbacks.
// The requirement is fixed at headers; WithRequestStreaming / WithResponseStreaming
// request its use. BodyMode otherwise stays Buffered. All
// registered body consumers must accept incremental input with FailClosed.
// A pending body replacement also requires buffered delivery.
// Request and response decisions are independent; existing filters default to
// Buffered. An already available complete body is still evaluated inline.
//
// Streamed consumers prepare their instances in the header phase with NeedBody;
// this preparation must have no external side effects. Header mutations are
// returned immediately. The adapter then serially calls EvalRequestBodyChunk or
// EvalResponseBodyChunk on the same stream and result, ending with Complete=true
// (possibly empty). Every consumer sees the original chunk; the last non-nil
// body replacement wins, as in buffered evaluation. This is not a pipeline of
// transformed bytes or an independent release gate per consumer.
//
// Chunk callbacks can Continue with body mutations or Stop. Header, status,
// routing and Bypass changes are rejected. Output always includes unchanged
// bytes; an empty replacement withholds this call's output. Rejection cannot
// recall bytes already forwarded by the adapter.
// Filters retaining input must copy it and bound their storage. The engine does
// not buffer chunks through this low-level API; audit records aggregate per consumer, and its budget
// applies per call rather than bounding the whole stream lifetime.
//
// BodyStreamed is an engine contract, not an Envoy mode override. The transport
// adapter must handle header commitment, EOS/trailers, backpressure, stream
// deadlines, byte limits and late rejection before enabling it in production.
package engine
