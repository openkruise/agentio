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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	structpb "google.golang.org/protobuf/types/known/structpb"

	"github.com/openkruise/agentio/extensions/epe/pkg/extproc/attributes"
)

// RequestBuilder assembles the ProcessingRequest sequence Envoy would send
// for one HTTP request, including the ext_proc filter_state attributes that
// carry the caller's pod identity.
type RequestBuilder struct {
	method  string
	host    string
	path    string
	scheme  string
	headers [][2]string

	peerNamespace string
	peerName      string
	labels        map[string]string
	sandboxToken  string
	sourceAddress string
	dstAddress    string
	dstPort       int32

	bodyChunks       [][]byte
	streamingHeaders bool
	trailerFlushed   bool

	responseConfigured bool
	responseStatus     int
	responseHeaders    [][2]string
	responseBodySet    bool
	responseBody       []byte
}

// NewRequest starts a builder with GET semantics and no identity. Call Peer
// to attach a pod identity; without it the engine fails open.
func NewRequest(method, host, path string) *RequestBuilder {
	return &RequestBuilder{method: method, host: host, path: path}
}

func (b *RequestBuilder) Scheme(scheme string) *RequestBuilder {
	b.scheme = scheme
	return b
}

func (b *RequestBuilder) Header(key, value string) *RequestBuilder {
	b.headers = append(b.headers, [2]string{key, value})
	return b
}

func (b *RequestBuilder) RequestID(id string) *RequestBuilder {
	return b.Header("x-request-id", id)
}

// Peer sets the caller pod identity and its labels, delivered as the
// base64-encoded filter_state['agentio.workload.labels'] value.
func (b *RequestBuilder) Peer(namespace, name string, labels map[string]string) *RequestBuilder {
	b.peerNamespace = namespace
	b.peerName = name
	b.labels = labels
	return b
}

// SandboxToken sets filter_state['sandbox.token'] as base64(JSON).
func (b *RequestBuilder) SandboxToken(requestID, accessToken, clientID string) *RequestBuilder {
	token, err := json.Marshal(map[string]string{
		"requestId":       requestID,
		"accessToken":     accessToken,
		"sandboxClientId": clientID,
	})
	if err != nil {
		panic(fmt.Sprintf("marshal sandbox token: %v", err))
	}
	b.sandboxToken = base64.StdEncoding.EncodeToString(token)
	return b
}

// SourceAddress sets Envoy's source.address attribute ("<ip>:<port>").
func (b *RequestBuilder) SourceAddress(addr string) *RequestBuilder {
	b.sourceAddress = addr
	return b
}

// DestinationPort simulates the Envoy-authenticated TCP destination port.
// It is delivered as a NUMBER value — attributes.Extract ignores strings —
// and overrides the authority port for ordinary requests. CONNECT retains its
// authority port because that is the tunnel target and destination.port is the
// explicit proxy listener.
func (b *RequestBuilder) DestinationPort(port int32) *RequestBuilder {
	b.dstPort = port
	return b
}

// DestinationAddress sets Envoy's restored downstream destination.address.
func (b *RequestBuilder) DestinationAddress(address string) *RequestBuilder {
	b.dstAddress = address
	return b
}

// Body attaches a complete request body delivered as a single chunk with
// EndOfStream=true (Envoy's BUFFERED shape).
func (b *RequestBuilder) Body(body []byte) *RequestBuilder {
	b.bodyChunks = [][]byte{body}
	return b
}

// TrailerFlushedBody attaches a complete request body delivered the way
// Envoy delivers it in BUFFERED mode when the request carries HTTP trailers:
// one message with the whole body and EndOfStream=false, emitted from
// onTrailers ("sending data left over in the buffer"). Because
// request_trailer_mode defaults to SKIP, no RequestTrailers message follows
// and no further body message ever arrives — so this is the last chance to
// render a verdict.
func (b *RequestBuilder) TrailerFlushedBody(body []byte) *RequestBuilder {
	b.bodyChunks = [][]byte{body}
	b.trailerFlushed = true
	return b
}

// BodyChunks attaches a body split across several messages, only the last of
// which carries EndOfStream=true. Envoy never produces this in BUFFERED mode
// — it buffers internally and emits the whole body at once — so this models
// the STREAMED family and exists only to pin the extension's behaviour if a
// short message ever appears.
func (b *RequestBuilder) BodyChunks(chunks ...[]byte) *RequestBuilder {
	b.bodyChunks = chunks
	return b
}

// StreamingHeaders forces EndOfStream=false on the headers message without
// any body messages — the full-duplex "headers first, body later" shape.
func (b *RequestBuilder) StreamingHeaders() *RequestBuilder {
	b.streamingHeaders = true
	return b
}

// ResponseHeaders attaches the upstream response-headers message with status.
func (b *RequestBuilder) ResponseHeaders(status int) *RequestBuilder {
	b.responseConfigured = true
	b.responseStatus = status
	return b
}

// ResponseHeader adds one upstream response header.
func (b *RequestBuilder) ResponseHeader(key, value string) *RequestBuilder {
	b.responseConfigured = true
	b.responseHeaders = append(b.responseHeaders, [2]string{key, value})
	return b
}

// ResponseBody attaches one complete BUFFERED response-body message. Presence
// is tracked separately so an explicit empty replacement still emits a body.
func (b *RequestBuilder) ResponseBody(body []byte) *RequestBuilder {
	b.responseConfigured = true
	b.responseBodySet = true
	b.responseBody = body
	return b
}

// HeadersMsg returns just the HttpHeaders message, for tests that call
// HandleRequestHeaders directly.
func (b *RequestBuilder) HeadersMsg() *extProcPb.HttpHeaders {
	method := b.method
	if method == "" {
		method = "GET"
	}
	hdrs := []*corev3.HeaderValue{
		{Key: ":method", RawValue: []byte(method)},
		{Key: ":authority", RawValue: []byte(b.host)},
		{Key: ":path", RawValue: []byte(b.path)},
	}
	if b.scheme != "" {
		hdrs = append(hdrs, &corev3.HeaderValue{Key: ":scheme", RawValue: []byte(b.scheme)})
	}
	for _, h := range b.headers {
		hdrs = append(hdrs, &corev3.HeaderValue{Key: h[0], RawValue: []byte(h[1])})
	}
	return &extProcPb.HttpHeaders{
		Headers:     &corev3.HeaderMap{Headers: hdrs},
		EndOfStream: len(b.bodyChunks) == 0 && !b.streamingHeaders,
	}
}

// Attrs returns the ext_proc attribute map, for tests that call
// HandleRequestHeaders directly.
func (b *RequestBuilder) Attrs() map[string]*structpb.Struct {
	fields := map[string]*structpb.Value{}
	setString := func(key, value string) {
		if value != "" {
			fields[key] = structpb.NewStringValue(value)
		}
	}
	setString(attributes.FilterStateDownstreamPeerNamespace, b.peerNamespace)
	setString(attributes.FilterStateDownstreamPeerName, b.peerName)
	if len(b.labels) > 0 {
		encoded := base64.StdEncoding.EncodeToString([]byte(encodeLabelPairs(b.labels)))
		setString(attributes.FilterStateWorkloadLabels, encoded)
	}
	setString(attributes.FilterStateSandboxToken, b.sandboxToken)
	setString(attributes.AttrSourceAddress, b.sourceAddress)
	setString(attributes.AttrDestinationAddress, b.dstAddress)
	if b.dstPort > 0 {
		fields[attributes.AttrDestinationPort] = structpb.NewNumberValue(float64(b.dstPort))
	}
	if len(fields) == 0 {
		return nil
	}
	return map[string]*structpb.Struct{
		attributes.ExtProcAttrsKey: {Fields: fields},
	}
}

// Build assembles the full ProcessingRequest sequence.
func (b *RequestBuilder) Build() []*extProcPb.ProcessingRequest {
	msgs := []*extProcPb.ProcessingRequest{{
		Request: &extProcPb.ProcessingRequest_RequestHeaders{
			RequestHeaders: b.HeadersMsg(),
		},
		Attributes: b.Attrs(),
	}}
	for i, chunk := range b.bodyChunks {
		msgs = append(msgs, &extProcPb.ProcessingRequest{
			Request: &extProcPb.ProcessingRequest_RequestBody{
				RequestBody: &extProcPb.HttpBody{
					Body: chunk,
					// The trailer flush carries the complete body with
					// EndOfStream clear; every other shape ends on the last
					// chunk.
					EndOfStream: !b.trailerFlushed && i == len(b.bodyChunks)-1,
				},
			},
		})
	}
	if b.responseConfigured {
		status := b.responseStatus
		if status == 0 {
			status = 200
		}
		headers := []*corev3.HeaderValue{{Key: ":status", RawValue: []byte(fmt.Sprintf("%d", status))}}
		for _, h := range b.responseHeaders {
			headers = append(headers, &corev3.HeaderValue{Key: h[0], RawValue: []byte(h[1])})
		}
		msgs = append(msgs, &extProcPb.ProcessingRequest{
			Request: &extProcPb.ProcessingRequest_ResponseHeaders{
				ResponseHeaders: &extProcPb.HttpHeaders{
					Headers:     &corev3.HeaderMap{Headers: headers},
					EndOfStream: !b.responseBodySet,
				},
			},
		})
		if b.responseBodySet {
			msgs = append(msgs, &extProcPb.ProcessingRequest{
				Request: &extProcPb.ProcessingRequest_ResponseBody{
					ResponseBody: &extProcPb.HttpBody{Body: b.responseBody, EndOfStream: true},
				},
			})
		}
	}
	return msgs
}

// encodeLabelPairs renders labels in the "k1=v1,k2=v2" scalar form the
// proxy uses, with sorted keys for determinism.
func encodeLabelPairs(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		pairs = append(pairs, k+"="+labels[k])
	}
	return strings.Join(pairs, ",")
}
