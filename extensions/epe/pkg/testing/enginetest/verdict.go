// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package enginetest

import (
	"strconv"
	"strings"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extProcV3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	auditlog "github.com/openkruise/agentio/extensions/epe/pkg/audit/log"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

// VerdictKind is the wire-level classification of a response sequence.
// Bypass and passthrough are indistinguishable on the wire; use
// Verdict.AccessLog's outcome (see Verdict.outcome) to tell them apart.
type VerdictKind string

const (
	VerdictBlocked     VerdictKind = "blocked"
	VerdictMutated     VerdictKind = "mutated"
	VerdictPassthrough VerdictKind = "passthrough"
)

// HeaderOpKind names what a header operation does. It mirrors filter.HeaderOp's
// kinds but is a distinct type because it is derived from the wire proto: a
// verdict assertion therefore cannot be satisfied by an engine result that never
// reached a ProcessingResponse.
type HeaderOpKind string

const (
	// HeaderSet is OVERWRITE_IF_EXISTS_OR_ADD: it replaces every existing line
	// for the name.
	HeaderSet HeaderOpKind = "set"
	// HeaderAdd is APPEND_IF_EXISTS_OR_ADD: it adds one more line, which is
	// the only way to emit several set-cookie headers.
	HeaderAdd HeaderOpKind = "add"
	// HeaderRemove is a remove_headers entry.
	HeaderRemove HeaderOpKind = "remove"
)

// HeaderOp records one normalized header operation decoded from an ext_proc response.
type HeaderOp struct {
	Kind  HeaderOpKind
	Name  string
	Value string
}

// Verdict reduces the response sequence of one request to assertable facts.
type Verdict struct {
	Kind VerdictKind

	// ImmediateStatus and ImmediateBody are set when Kind is VerdictBlocked.
	ImmediateStatus int
	ImmediateBody   string
	// ImmediateDetails is the block's RESPONSE_CODE_DETAILS. It is the operator's
	// channel rather than the client's — the body reaches the caller, this reaches
	// the access log — so it is the only place a reason for the block, or the
	// framework's own fail-closed marker, is observable.
	ImmediateDetails string

	// RequestHeaderOps and ResponseHeaderOps record decoded wire operations by
	// direction and in protobuf order. RequestHeaderOps includes mutations from
	// both request-header and request-body responses.
	RequestHeaderOps    []HeaderOp
	ResponseHeaderOps   []HeaderOp
	RequestBodyChanged  bool
	RequestBody         []byte
	ResponseBodyChanged bool
	ResponseBody        []byte
	ResponseStatus      *int

	// ModeOverride is the ProcessingMode set on the first headers-phase
	// response; non-nil proves the NeedsBody signalling fired.
	ModeOverride *extProcV3.ProcessingMode
	// ResponseModeOverride is the dynamic override emitted from response
	// headers when a filter requests the buffered response body.
	ResponseModeOverride *extProcV3.ProcessingMode

	// Info is the authoritative StreamInfo observed by the harness
	// InfoProbe; nil when the probe was disabled or never invoked.
	Info *filter.StreamInfo

	// AccessLog holds the entries the harness audit logger captured for this
	// run alone; RunMessages resets the logger first, so earlier requests in
	// the same test do not leak in.
	AccessLog []auditlog.Entry

	// Raw preserves the full ordered response sequence (read-only: some
	// responses are shared package singletons).
	Raw []*extProcPb.ProcessingResponse

	// Err is the error returned by Process; nil on clean EOF shutdown.
	Err error
}

// ParseVerdict classifies a response sequence.
func ParseVerdict(responses []*extProcPb.ProcessingResponse, procErr error) *Verdict {
	v := &Verdict{
		Kind: VerdictPassthrough,
		Raw:  responses,
		Err:  procErr,
	}
	for _, resp := range responses {
		switch r := resp.GetResponse().(type) {
		case *extProcPb.ProcessingResponse_ImmediateResponse:
			v.Kind = VerdictBlocked
			v.ImmediateStatus = int(r.ImmediateResponse.GetStatus().GetCode())
			v.ImmediateBody = string(r.ImmediateResponse.GetBody())
			v.ImmediateDetails = r.ImmediateResponse.GetDetails()
			return v
		case *extProcPb.ProcessingResponse_RequestHeaders:
			if resp.ModeOverride != nil && v.ModeOverride == nil {
				v.ModeOverride = resp.ModeOverride
			}
			v.consumeCommon(r.RequestHeaders.GetResponse(), true)
		case *extProcPb.ProcessingResponse_RequestBody:
			v.consumeCommon(r.RequestBody.GetResponse(), true)
		case *extProcPb.ProcessingResponse_ResponseHeaders:
			if resp.ModeOverride != nil {
				v.ResponseModeOverride = resp.ModeOverride
			}
			v.consumeCommon(r.ResponseHeaders.GetResponse(), false)
		case *extProcPb.ProcessingResponse_ResponseBody:
			v.consumeCommon(r.ResponseBody.GetResponse(), false)
		}
	}
	// Kind describes the *request* verdict, so a response-only mutation leaves
	// it at passthrough: nothing about the forwarded request changed.
	if len(v.RequestHeaderOps) > 0 || v.RequestBodyChanged {
		v.Kind = VerdictMutated
	}
	return v
}

func (v *Verdict) consumeCommon(common *extProcPb.CommonResponse, request bool) {
	if common == nil {
		return
	}
	mutation := common.GetHeaderMutation()
	if request {
		v.RequestHeaderOps = appendOps(v.RequestHeaderOps, mutation)
	} else {
		v.ResponseHeaderOps = appendOps(v.ResponseHeaderOps, mutation)
		for _, h := range mutation.GetSetHeaders() {
			if !strings.EqualFold(h.GetHeader().GetKey(), ":status") {
				continue
			}
			value := string(h.GetHeader().GetRawValue())
			if value == "" {
				value = h.GetHeader().GetValue()
			}
			if code, err := strconv.Atoi(value); err == nil {
				v.ResponseStatus = &code
			}
		}
	}
	bodyMutation := common.GetBodyMutation()
	if bodyMutation == nil {
		return
	}
	body, ok := bodyMutation.GetMutation().(*extProcPb.BodyMutation_Body)
	if !ok {
		return
	}
	copyBody := make([]byte, len(body.Body))
	copy(copyBody, body.Body)
	if request {
		v.RequestBodyChanged = true
		v.RequestBody = copyBody
	} else {
		v.ResponseBodyChanged = true
		v.ResponseBody = copyBody
	}
}

// appendOps appends one HeaderMutation in protobuf field order.
func appendOps(ops []HeaderOp, hm *extProcPb.HeaderMutation) []HeaderOp {
	if hm == nil {
		return ops
	}
	for _, h := range hm.GetSetHeaders() {
		header := h.GetHeader()
		if header == nil {
			continue
		}
		value := string(header.GetRawValue())
		if value == "" {
			value = header.GetValue()
		}
		kind := HeaderSet
		if h.GetAppendAction() == corev3.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD {
			kind = HeaderAdd
		}
		ops = append(ops, HeaderOp{Kind: kind, Name: strings.ToLower(header.GetKey()), Value: value})
	}
	for _, name := range hm.GetRemoveHeaders() {
		ops = append(ops, HeaderOp{Kind: HeaderRemove, Name: strings.ToLower(name)})
	}
	return ops
}

// headerValues returns every value ops set or added for name, in wire order.
func headerValues(ops []HeaderOp, name string) []string {
	want := strings.ToLower(name)
	var out []string
	for _, op := range ops {
		if op.Name == want && op.Kind != HeaderRemove {
			out = append(out, op.Value)
		}
	}
	return out
}

// requireHeader asserts a single value and includes dir in failures.
func requireHeader(t *testing.T, ops []HeaderOp, dir, name, want string) {
	t.Helper()
	got := headerValues(ops, name)
	if len(got) != 1 {
		t.Fatalf("%s header %q values = %v, want exactly [%q] (ops=%+v)", dir, name, got, want, ops)
	}
	if got[0] != want {
		t.Fatalf("%s header %q = %q, want %q", dir, name, got[0], want)
	}
}

// headerRemoved reports whether ops removed name.
func headerRemoved(ops []HeaderOp, name string) bool {
	want := strings.ToLower(name)
	for _, op := range ops {
		if op.Kind == HeaderRemove && op.Name == want {
			return true
		}
	}
	return false
}

func requireHeaderRemoved(t *testing.T, ops []HeaderOp, dir, name string) {
	t.Helper()
	if !headerRemoved(ops, name) {
		t.Fatalf("%s header %q not removed (ops=%+v)", dir, name, ops)
	}
}

// RequestHeaderValues returns every value the request direction set or added
// for name, in wire order. Several values mean several header lines.
func (v *Verdict) RequestHeaderValues(name string) []string {
	return headerValues(v.RequestHeaderOps, name)
}

// ResponseHeaderValues returns every value the response phase set or added
// for name, in wire order. Several values mean several header lines, which is
// how multi-valued set-cookie is expressed.
func (v *Verdict) ResponseHeaderValues(name string) []string {
	return headerValues(v.ResponseHeaderOps, name)
}

// RequireHeader asserts the request direction produced exactly one value for
// name, equal to want.
func (v *Verdict) RequireHeader(t *testing.T, name, want string) {
	t.Helper()
	requireHeader(t, v.RequestHeaderOps, "request", name, want)
}

// RequireResponseHeader asserts the response phase produced exactly one value
// for name, equal to want.
func (v *Verdict) RequireResponseHeader(t *testing.T, name, want string) {
	t.Helper()
	requireHeader(t, v.ResponseHeaderOps, "response", name, want)
}

// RequireHeaderRemoved asserts the request direction removed name.
func (v *Verdict) RequireHeaderRemoved(t *testing.T, name string) {
	t.Helper()
	requireHeaderRemoved(t, v.RequestHeaderOps, "request", name)
}

// RequireResponseHeaderRemoved asserts the response phase removed name.
func (v *Verdict) RequireResponseHeaderRemoved(t *testing.T, name string) {
	t.Helper()
	requireHeaderRemoved(t, v.ResponseHeaderOps, "response", name)
}

// RequireBlocked asserts an ImmediateResponse with the given status.
func (v *Verdict) RequireBlocked(t *testing.T, wantStatus int) {
	t.Helper()
	v.requireNoErr(t)
	if v.Kind != VerdictBlocked {
		t.Fatalf("verdict = %s, want blocked (raw=%v)", v.Kind, v.Raw)
	}
	if v.ImmediateStatus != wantStatus {
		t.Fatalf("immediate status = %d, want %d (body=%q)", v.ImmediateStatus, wantStatus, v.ImmediateBody)
	}
}

// RequireBlockedBody additionally asserts the immediate response body.
func (v *Verdict) RequireBlockedBody(t *testing.T, wantStatus int, wantBodyContains string) {
	t.Helper()
	v.RequireBlocked(t, wantStatus)
	if !strings.Contains(v.ImmediateBody, wantBodyContains) {
		t.Fatalf("immediate body = %q, want it to contain %q", v.ImmediateBody, wantBodyContains)
	}
}

// singleEntry returns the one auditlog entry this run produced. AccessLog holds
// this run alone and one request audits exactly once, so any other count is a
// harness or server bug rather than an index to reach past.
func (v *Verdict) singleEntry(t *testing.T) auditlog.Entry {
	t.Helper()
	if len(v.AccessLog) != 1 {
		t.Fatalf("want exactly 1 auditlog entry, got %d: %+v", len(v.AccessLog), v.AccessLog)
	}
	return v.AccessLog[0]
}

// outcome returns the outcome the product logged for this stream. The auditlog
// is EPE's real output, so it is what assertions are worth making against.
func (v *Verdict) outcome(t *testing.T) string {
	t.Helper()
	return v.singleEntry(t).Outcome
}

// RequirePassthrough asserts the request passed through unmodified and that no
// policy unit matched it — which is what passthrough now means.
func (v *Verdict) RequirePassthrough(t *testing.T) {
	t.Helper()
	v.requireNoErr(t)
	if v.Kind != VerdictPassthrough {
		t.Fatalf("verdict = %s, want passthrough (raw=%v)", v.Kind, v.Raw)
	}
	if got := v.outcome(t); got != "passthrough" {
		t.Fatalf("outcome = %q, want passthrough", got)
	}
}

// RequireBypassed asserts the wire shape changed nothing while at least one
// policy unit matched. Note this no longer implies a bypass rule fired: under
// the derived outcome, "bypassed" means matched-but-unmodified. Assert
// RequireAction(t, ":bypass:") when the exemption itself is the subject.
func (v *Verdict) RequireBypassed(t *testing.T) {
	t.Helper()
	v.requireNoErr(t)
	if v.Kind != VerdictPassthrough {
		t.Fatalf("verdict = %s, want passthrough wire shape for bypass (raw=%v)", v.Kind, v.Raw)
	}
	if got := v.outcome(t); got != "bypassed" {
		t.Fatalf("outcome = %q, want bypassed", got)
	}
}

// RequireOutcome asserts the logged outcome string.
func (v *Verdict) RequireOutcome(t *testing.T, want string) {
	t.Helper()
	if got := v.outcome(t); got != want {
		t.Fatalf("outcome = %q, want %q", got, want)
	}
}

// RequireAction asserts some audited action contains want, e.g. ":bypass:" for
// an explicit exemption or "mcpacl:block:" for a named filter's verdict.
func (v *Verdict) RequireAction(t *testing.T, want string) {
	t.Helper()
	entry := v.singleEntry(t)
	for _, a := range entry.Actions {
		if strings.Contains(a, want) {
			return
		}
	}
	t.Fatalf("no audited action contains %q; actions = %v", want, entry.Actions)
}

// RequireGRPCCode asserts Process returned an error with the given code.
func (v *Verdict) RequireGRPCCode(t *testing.T, want codes.Code) {
	t.Helper()
	if got := status.Code(v.Err); got != want {
		t.Fatalf("Process error code = %v (err=%v), want %v", got, v.Err, want)
	}
}

func (v *Verdict) requireNoErr(t *testing.T) {
	t.Helper()
	if v.Err != nil {
		t.Fatalf("Process returned error: %v", v.Err)
	}
}
