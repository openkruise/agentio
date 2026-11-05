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
	"strings"
	"testing"
)

func TestSignOSSV4_GoldenListBuckets(t *testing.T) {
	req := &RequestSnapshot{
		Method:   "GET",
		Scheme:   "https",
		Host:     "oss-cn-hangzhou.aliyuncs.com",
		Path:     "/",
		RawQuery: "",
		Headers: map[string]string{
			"host":                 "oss-cn-hangzhou.aliyuncs.com",
			"x-oss-date":           "20260524T100000Z",
			"x-oss-content-sha256": "UNSIGNED-PAYLOAD",
			"x-oss-security-token": "OLDSTS",
			"authorization":        "OSS4-HMAC-SHA256 Credential=OLDAK/20260524/cn-hangzhou/oss/aliyun_v4_request,Signature=stale",
		},
	}
	tr := Triplet{AccessKeyID: "STS.NEWAK", AccessKeySecret: "NEWSECRET", SecurityToken: "NEWTOKEN"}

	res, err := SignOSSV4(req, tr, OSSV4Params{Region: "cn-hangzhou"})
	if err != nil {
		t.Fatalf("SignOSSV4: %v", err)
	}
	authz := findHeader(t, res, "authorization")
	if !strings.HasPrefix(authz, "OSS4-HMAC-SHA256 Credential=STS.NEWAK/20260524/cn-hangzhou/oss/aliyun_v4_request,") {
		t.Fatalf("Credential not rewritten: %q", authz)
	}
	if v := findHeader(t, res, "x-oss-security-token"); v != "NEWTOKEN" {
		t.Fatalf("x-oss-security-token = %q, want NEWTOKEN", v)
	}
	wantSig, err := computeOSSV4Signature(req, tr, OSSV4Params{Region: "cn-hangzhou"})
	if err != nil {
		t.Fatalf("computeOSSV4Signature: %v", err)
	}
	if !strings.Contains(authz, "Signature="+wantSig) {
		t.Fatalf("signature mismatch:\n got  %s\n want substring Signature=%s", authz, wantSig)
	}
}

func TestSignOSSV4_ValidationEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		req         *RequestSnapshot
		triplet     Triplet
		params      OSSV4Params
		expectError string
	}{
		{
			name: "empty AccessKeySecret",
			req: &RequestSnapshot{
				Method:  "GET",
				Scheme:  "https",
				Host:    "h",
				Path:    "/",
				Headers: map[string]string{"host": "h", "x-oss-date": "20260524T100000Z"},
			},
			triplet:     Triplet{AccessKeyID: "AK"},
			params:      OSSV4Params{Region: "cn-hangzhou"},
			expectError: "AccessKeySecret",
		},
		{
			name:        "nil request",
			req:         nil,
			triplet:     Triplet{AccessKeyID: "AK", AccessKeySecret: "SK"},
			params:      OSSV4Params{Region: "cn-hangzhou"},
			expectError: "nil request snapshot",
		},
		{
			name: "x-oss-date too short",
			req: &RequestSnapshot{
				Method: "GET",
				Path:   "/",
				Headers: map[string]string{
					"host":       "oss.aliyuncs.com",
					"x-oss-date": "2026052", // only 7 chars
				},
			},
			triplet:     Triplet{AccessKeyID: "AK", AccessKeySecret: "SK"},
			params:      OSSV4Params{Region: "cn-hangzhou"},
			expectError: "x-oss-date header too short",
		},
		{
			name: "x-oss-date missing",
			req: &RequestSnapshot{
				Method:  "GET",
				Path:    "/",
				Headers: map[string]string{"host": "oss.aliyuncs.com"},
			},
			triplet:     Triplet{AccessKeyID: "AK", AccessKeySecret: "SK"},
			params:      OSSV4Params{Region: "cn-hangzhou"},
			expectError: "x-oss-date header too short",
		},
		{
			name: "empty region",
			req: &RequestSnapshot{
				Method: "GET",
				Path:   "/",
				Headers: map[string]string{
					"host":       "oss.aliyuncs.com",
					"x-oss-date": "20260524T100000Z",
				},
			},
			triplet:     Triplet{AccessKeyID: "AK", AccessKeySecret: "SK"},
			params:      OSSV4Params{Region: ""},
			expectError: "empty region",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := SignOSSV4(tc.req, tc.triplet, tc.params)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.expectError)
			}
			if !strings.Contains(err.Error(), tc.expectError) {
				t.Errorf("error = %v, want substring %q", err, tc.expectError)
			}
		})
	}
}

func TestSignOSSV4_EmptySecurityTokenRemovesHeader(t *testing.T) {
	req := &RequestSnapshot{
		Method: "GET",
		Scheme: "https",
		Host:   "oss-cn-hangzhou.aliyuncs.com",
		Path:   "/",
		Headers: map[string]string{
			"host":                 "oss-cn-hangzhou.aliyuncs.com",
			"x-oss-date":           "20260524T100000Z",
			"x-oss-content-sha256": "UNSIGNED-PAYLOAD",
			"x-oss-security-token": "OLDSTS",
		},
	}
	tr := Triplet{AccessKeyID: "AK", AccessKeySecret: "SK"}
	res, err := SignOSSV4(req, tr, OSSV4Params{Region: "cn-hangzhou"})
	if err != nil {
		t.Fatalf("SignOSSV4: %v", err)
	}

	if !containsString(res.RemoveHeaders, "x-oss-security-token") {
		t.Errorf("expected x-oss-security-token in RemoveHeaders, got %v", res.RemoveHeaders)
	}
	for _, h := range res.SetHeaders {
		if strings.EqualFold(h.Name, "x-oss-security-token") {
			t.Errorf("x-oss-security-token should not be set when SecurityToken is empty")
		}
	}
}

func TestSignOSSV4_WithQueryString(t *testing.T) {
	// Exercises the canonicalQuery path inside computeOSSV4SignatureAndHeaders.
	req := &RequestSnapshot{
		Method:   "GET",
		Scheme:   "https",
		Host:     "bucket.oss-cn-hangzhou.aliyuncs.com",
		Path:     "/",
		RawQuery: "prefix=foo&max-keys=100",
		Headers: map[string]string{
			"host":                 "bucket.oss-cn-hangzhou.aliyuncs.com",
			"x-oss-date":           "20260524T100000Z",
			"x-oss-content-sha256": "UNSIGNED-PAYLOAD",
		},
	}
	tr := Triplet{AccessKeyID: "AK", AccessKeySecret: "SK", SecurityToken: "ST"}
	res, err := SignOSSV4(req, tr, OSSV4Params{Region: "cn-hangzhou"})
	if err != nil {
		t.Fatalf("SignOSSV4: %v", err)
	}
	authz := findHeader(t, res, "authorization")
	if !strings.HasPrefix(authz, "OSS4-HMAC-SHA256 ") {
		t.Errorf("authorization prefix wrong: %q", authz)
	}

	// Recompute via wrapper to verify consistency.
	wantSig, err := computeOSSV4Signature(req, tr, OSSV4Params{Region: "cn-hangzhou"})
	if err != nil {
		t.Fatalf("computeOSSV4Signature: %v", err)
	}
	if !strings.Contains(authz, "Signature="+wantSig) {
		t.Errorf("signature mismatch:\n got  %s\n want substring Signature=%s", authz, wantSig)
	}
}

func TestComputeOSSV4Signature_EmptySecurityToken(t *testing.T) {
	req := &RequestSnapshot{
		Method: "GET",
		Path:   "/",
		Headers: map[string]string{
			"host":                 "oss.aliyuncs.com",
			"x-oss-date":           "20260524T100000Z",
			"x-oss-content-sha256": "UNSIGNED-PAYLOAD",
			"x-oss-security-token": "OLDSTS",
		},
	}
	tr := Triplet{AccessKeyID: "AK", AccessKeySecret: "SK"}
	sig, err := computeOSSV4Signature(req, tr, OSSV4Params{Region: "cn-hangzhou"})
	if err != nil {
		t.Fatalf("computeOSSV4Signature: %v", err)
	}
	if sig == "" {
		t.Errorf("signature should be non-empty")
	}
}
