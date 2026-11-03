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
package aliyun

import (
	"net/url"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
)

// The signature must cover the query Envoy forwards, byte for byte. Rebuilding
// it from the parsed url.Values drops whatever url.ParseQuery rejected — Go
// refuses ';' separators and invalid escapes since 1.17, keeping only a partial
// result — so the signed set would be smaller than the request the gateway
// receives, and the official OSS Go SDK signs RawQuery verbatim.
func TestSnapshotFromStream_CarriesWireQueryVerbatim(t *testing.T) {
	tests := []struct {
		name     string
		rawQuery string
	}{
		{"semicolon separator", "a=1;b=2&c=3"},
		{"invalid escape", "a=%zz&b=2"},
		{"lower-case hex", "prefix=a%2fb"},
		{"unescaped sub-delims", "x-oss-process=image/resize,w_100"},
		{"repeated key", "k=a&k=b"},
		{"plus in value", "q=a+b"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The adapter keeps whatever ParseQuery could extract, which for
			// these inputs is lossy or re-encoded; RawQuery must be untouched.
			parsed, _ := url.ParseQuery(tt.rawQuery)
			st := &filter.Stream{RequestContext: filter.RequestContext{Request: httpreq.HTTPRequest{
				Method:   "GET",
				Host:     "bucket.oss-cn-hangzhou.aliyuncs.com",
				Path:     "/obj",
				RawQuery: tt.rawQuery,
				Query:    parsed,
				Headers:  map[string]string{":authority": "bucket.oss-cn-hangzhou.aliyuncs.com"},
			}}}
			snap := snapshotFromStream(st)
			if snap.RawQuery != tt.rawQuery {
				t.Errorf("RawQuery = %q, want the wire form %q", snap.RawQuery, tt.rawQuery)
			}
		})
	}
}

// With no query at all there is nothing to carry.
func TestSnapshotFromStream_EmptyQuery(t *testing.T) {
	st := &filter.Stream{
		RequestContext: filter.RequestContext{Request: httpreq.HTTPRequest{Method: "GET", Path: "/obj"}},
	}
	if snap := snapshotFromStream(st); snap.RawQuery != "" {
		t.Errorf("RawQuery = %q, want empty", snap.RawQuery)
	}
}
