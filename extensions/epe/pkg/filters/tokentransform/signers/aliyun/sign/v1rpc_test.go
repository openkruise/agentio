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
package sign

import (
	"net/url"
	"slices"
	"strings"
	"testing"
)

func TestSignV1RPC_GETGolden(t *testing.T) {
	req := &RequestSnapshot{
		Method:   "GET",
		Scheme:   "https",
		Host:     "ecs.aliyuncs.com",
		Path:     "/",
		RawQuery: "Action=DescribeRegions&Format=JSON&Version=2014-05-26&AccessKeyId=OLDAK&SignatureMethod=HMAC-SHA1&SignatureNonce=nonce&SignatureVersion=1.0&SecurityToken=OLDSTS&Signature=stale&Timestamp=2026-05-24T10%3A00%3A00Z",
		Headers:  map[string]string{"host": "ecs.aliyuncs.com"},
	}
	tr := Triplet{AccessKeyID: "STS.NEWAK", AccessKeySecret: "NEWSECRET", SecurityToken: "NEWTOKEN"}

	res, err := SignV1RPC(req, tr)
	if err != nil {
		t.Fatalf("SignV1RPC: %v", err)
	}
	if res.NewPath == nil {
		t.Fatalf("expected NewPath to be set for v1rpc")
	}

	parsed, err := url.Parse(*res.NewPath)
	if err != nil {
		t.Fatalf("parse NewPath: %v", err)
	}
	q := parsed.Query()
	if q.Get("AccessKeyId") != "STS.NEWAK" {
		t.Fatalf("AccessKeyId = %q", q.Get("AccessKeyId"))
	}
	if q.Get("SecurityToken") != "NEWTOKEN" {
		t.Fatalf("SecurityToken = %q", q.Get("SecurityToken"))
	}
	if q.Get("Signature") == "stale" || q.Get("Signature") == "" {
		t.Fatalf("Signature not refreshed: %q", q.Get("Signature"))
	}
	// Re-verify by reproducing the expected signature from the rewritten params.
	wantSig, err := computeV1RPCSignatureFromParams(req.Method, q, tr.AccessKeySecret)
	if err != nil {
		t.Fatalf("compute reference: %v", err)
	}
	if q.Get("Signature") != wantSig {
		t.Fatalf("Signature mismatch: got %q want %q", q.Get("Signature"), wantSig)
	}
}

func TestSignV1RPC_POSTFormBody(t *testing.T) {
	body := []byte("Action=RunInstances&InstanceType=ecs.g6.large")
	req := &RequestSnapshot{
		Method:   "POST",
		Scheme:   "https",
		Host:     "ecs.aliyuncs.com",
		Path:     "/",
		RawQuery: "AccessKeyId=OLDAK&SignatureMethod=HMAC-SHA1&SignatureNonce=n&SignatureVersion=1.0&SecurityToken=OLDSTS&Signature=stale&Timestamp=2026-05-24T10%3A00%3A00Z&Version=2014-05-26&Format=JSON",
		Headers: map[string]string{
			"host":         "ecs.aliyuncs.com",
			"content-type": "application/x-www-form-urlencoded",
		},
		Body: body,
	}
	tr := Triplet{AccessKeyID: "STS.NEWAK", AccessKeySecret: "NEWSECRET", SecurityToken: "NEWTOKEN"}

	res, err := SignV1RPC(req, tr)
	if err != nil {
		t.Fatalf("SignV1RPC: %v", err)
	}
	parsed, _ := url.Parse(*res.NewPath)
	q := parsed.Query()
	wantSig, err := computeV1RPCSignatureFromMerged(req.Method, q, tr.AccessKeySecret, body)
	if err != nil {
		t.Fatalf("reference: %v", err)
	}
	if q.Get("Signature") != wantSig {
		t.Fatalf("Signature mismatch: got %q want %q", q.Get("Signature"), wantSig)
	}
}

func TestSignV1RPC_InvalidInput(t *testing.T) {
	tests := []struct {
		name    string
		req     *RequestSnapshot
		triplet Triplet
		wantErr string
	}{
		{
			name: "empty AccessKeySecret",
			req: &RequestSnapshot{
				Method:   "GET",
				Path:     "/",
				RawQuery: "AccessKeyId=AK&SignatureMethod=HMAC-SHA1&SecurityToken=ST&Signature=s",
			},
			triplet: Triplet{AccessKeyID: "AK"},
			wantErr: "AccessKeySecret",
		},
		{
			name:    "nil request",
			req:     nil,
			triplet: Triplet{AccessKeyID: "AK", AccessKeySecret: "SK"},
			wantErr: "nil request snapshot",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := SignV1RPC(tc.req, tc.triplet)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestSignV1RPC_EmptySecurityTokenRemoves(t *testing.T) {
	req := &RequestSnapshot{
		Method:   "GET",
		Path:     "/",
		RawQuery: "AccessKeyId=OLDAK&SignatureMethod=HMAC-SHA1&SecurityToken=OLDST&Signature=stale&SignatureVersion=1.0",
		Headers:  map[string]string{"host": "ecs.aliyuncs.com"},
	}
	tr := Triplet{AccessKeyID: "NEWAK", AccessKeySecret: "SK"}
	res, err := SignV1RPC(req, tr)
	if err != nil {
		t.Fatalf("SignV1RPC: %v", err)
	}
	if res.NewPath == nil {
		t.Fatalf("expected NewPath to be set")
	}

	parsed, err := url.Parse(*res.NewPath)
	if err != nil {
		t.Fatalf("parse NewPath: %v", err)
	}
	q := parsed.Query()
	if got := q.Get("AccessKeyId"); got != "NEWAK" {
		t.Errorf("AccessKeyId = %q, want NEWAK", got)
	}
	if got := q.Get("SecurityToken"); got != "" {
		t.Errorf("SecurityToken = %q, should be removed when empty", got)
	}
}

func TestSignV1RPC_POSTBodyEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        []byte
	}{
		{
			// POST with non-form content type should not merge body params.
			name:        "non-form content type skips body merge",
			contentType: "application/json",
			body:        []byte(`{"foo":"bar"}`),
		},
		{
			// POST with form content-type but empty body should not error.
			name:        "form content type with empty body",
			contentType: "application/x-www-form-urlencoded",
			body:        nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := &RequestSnapshot{
				Method:   "POST",
				Path:     "/",
				RawQuery: "AccessKeyId=AK&SignatureMethod=HMAC-SHA1&SecurityToken=ST&Signature=stale&SignatureVersion=1.0",
				Headers: map[string]string{
					"host":         "ecs.aliyuncs.com",
					"content-type": tc.contentType,
				},
				Body: tc.body,
			}
			tr := Triplet{AccessKeyID: "AK", AccessKeySecret: "SK", SecurityToken: "ST"}
			res, err := SignV1RPC(req, tr)
			if err != nil {
				t.Fatalf("SignV1RPC: %v", err)
			}
			if res.NewPath == nil {
				t.Errorf("expected NewPath to be set")
			}
		})
	}
}

func TestIsFormContentType(t *testing.T) {
	tests := []struct {
		name string
		ct   string
		want bool
	}{
		{
			name: "empty content-type",
			ct:   "",
			want: false,
		},
		{
			name: "exact match",
			ct:   "application/x-www-form-urlencoded",
			want: true,
		},
		{
			name: "with charset parameter",
			ct:   "application/x-www-form-urlencoded; charset=utf-8",
			want: true,
		},
		{
			name: "case insensitive",
			ct:   "Application/X-WWW-Form-Urlencoded",
			want: true,
		},
		{
			name: "with whitespace",
			ct:   "  application/x-www-form-urlencoded  ",
			want: true,
		},
		{
			name: "json content type",
			ct:   "application/json",
			want: false,
		},
		{
			name: "multipart form-data",
			ct:   "multipart/form-data; boundary=---",
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isFormContentType(tc.ct); got != tc.want {
				t.Errorf("isFormContentType(%q) = %v, want %v", tc.ct, got, tc.want)
			}
		})
	}
}

func TestMergeValues(t *testing.T) {
	tests := []struct {
		name    string
		dst     url.Values
		src     url.Values
		wantKey string
		wantVal []string
	}{
		{
			name:    "merge disjoint keys",
			dst:     url.Values{"a": {"1"}},
			src:     url.Values{"b": {"2"}},
			wantKey: "b",
			wantVal: []string{"2"},
		},
		{
			name:    "merge overlapping keys appends",
			dst:     url.Values{"a": {"1"}},
			src:     url.Values{"a": {"2", "3"}},
			wantKey: "a",
			wantVal: []string{"1", "2", "3"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mergeValues(tc.dst, tc.src)
			if !slices.Equal(tc.dst[tc.wantKey], tc.wantVal) {
				t.Errorf("dst[%q] = %v, want %v", tc.wantKey, tc.dst[tc.wantKey], tc.wantVal)
			}
		})
	}
}

func TestComputeV1RPCSignatureFromMerged(t *testing.T) {
	query := url.Values{
		"AccessKeyId":      {"AK"},
		"SignatureMethod":  {"HMAC-SHA1"},
		"SignatureVersion": {"1.0"},
	}
	body := []byte("Action=DescribeRegions&Format=JSON")
	sig, err := computeV1RPCSignatureFromMerged("GET", query, "SECRET", body)
	if err != nil {
		t.Fatalf("computeV1RPCSignatureFromMerged: %v", err)
	}
	if sig == "" {
		t.Fatalf("signature should be non-empty")
	}

	// The same signature should be produced via computeV1RPCSignatureFromParams
	// with manually merged params.
	merged := cloneValues(query)
	form, _ := url.ParseQuery(string(body))
	mergeValues(merged, form)
	wantSig, err := computeV1RPCSignatureFromParams("GET", merged, "SECRET")
	if err != nil {
		t.Fatalf("computeV1RPCSignatureFromParams: %v", err)
	}
	if sig != wantSig {
		t.Errorf("signature = %q, want %q", sig, wantSig)
	}
}
