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

func TestSignV1ROA_Golden(t *testing.T) {
	req := &RequestSnapshot{
		Method:   "GET",
		Scheme:   "https",
		Host:     "cs.cn-hangzhou.aliyuncs.com",
		Path:     "/clusters",
		RawQuery: "",
		Headers: map[string]string{
			"host":                  "cs.cn-hangzhou.aliyuncs.com",
			"accept":                "application/json",
			"date":                  "Sun, 24 May 2026 10:00:00 GMT",
			"x-acs-version":         "2015-12-15",
			"x-acs-signature-nonce": "abcdef",
			"x-acs-security-token":  "OLDSTS",
			"authorization":         "acs OLDAK:oldsig=",
		},
	}
	tr := Triplet{AccessKeyID: "STS.NEWAK", AccessKeySecret: "NEWSECRET", SecurityToken: "NEWTOKEN"}

	res, err := SignV1ROA(req, tr)
	if err != nil {
		t.Fatalf("SignV1ROA: %v", err)
	}
	authz := findHeader(t, res, "authorization")
	if !strings.HasPrefix(authz, "acs STS.NEWAK:") || strings.Contains(authz, "oldsig") {
		t.Fatalf("authorization not rewritten: %q", authz)
	}
	if v := findHeader(t, res, "x-acs-security-token"); v != "NEWTOKEN" {
		t.Fatalf("x-acs-security-token = %q, want NEWTOKEN", v)
	}
	// Signature is deterministic; recompute and compare.
	wantSig, err := computeV1ROASignature(req, tr)
	if err != nil {
		t.Fatalf("computeV1ROASignature: %v", err)
	}
	if !strings.HasSuffix(authz, ":"+wantSig) {
		t.Fatalf("signature mismatch:\n got  %s\n want suffix :%s", authz, wantSig)
	}
}

func TestSignV1ROA_InvalidInput(t *testing.T) {
	tests := []struct {
		name    string
		req     *RequestSnapshot
		triplet Triplet
		wantErr string
	}{
		{
			name: "empty AccessKeySecret",
			req: &RequestSnapshot{
				Method:  "GET",
				Scheme:  "https",
				Host:    "h",
				Path:    "/",
				Headers: map[string]string{"host": "h"},
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
			_, err := SignV1ROA(tc.req, tc.triplet)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestSignV1ROA_EmptySecurityTokenRemovesHeader(t *testing.T) {
	req := &RequestSnapshot{
		Method: "GET",
		Scheme: "https",
		Host:   "cs.cn-hangzhou.aliyuncs.com",
		Path:   "/clusters",
		Headers: map[string]string{
			"host":                 "cs.cn-hangzhou.aliyuncs.com",
			"accept":               "application/json",
			"date":                 "Sun, 24 May 2026 10:00:00 GMT",
			"x-acs-version":        "2015-12-15",
			"x-acs-security-token": "OLDSTS",
			"authorization":        "acs OLDAK:oldsig=",
		},
	}
	tr := Triplet{AccessKeyID: "AK", AccessKeySecret: "SK"}
	res, err := SignV1ROA(req, tr)
	if err != nil {
		t.Fatalf("SignV1ROA: %v", err)
	}
	if !containsString(res.RemoveHeaders, "x-acs-security-token") {
		t.Errorf("expected x-acs-security-token in RemoveHeaders, got %v", res.RemoveHeaders)
	}
	for _, h := range res.SetHeaders {
		if strings.EqualFold(h.Name, "x-acs-security-token") {
			t.Errorf("x-acs-security-token should not be set when SecurityToken is empty")
		}
	}
}

// TestSignV1ROA_QueryCanonicalization exercises the query canonicalization
// path in computeV1ROASignatureRaw across the query shapes it must handle.
func TestSignV1ROA_QueryCanonicalization(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		path       string
		rawQuery   string
		headers    map[string]string
		triplet    Triplet
		wantPrefix string
	}{
		{
			name:     "simple key=value pairs",
			method:   "GET",
			path:     "/clusters",
			rawQuery: "page=1&size=10",
			headers: map[string]string{
				"host":                  "cs.cn-hangzhou.aliyuncs.com",
				"accept":                "application/json",
				"date":                  "Sun, 24 May 2026 10:00:00 GMT",
				"x-acs-version":         "2015-12-15",
				"x-acs-signature-nonce": "abcdef",
				"x-acs-security-token":  "OLDSTS",
				"authorization":         "acs OLDAK:oldsig=",
			},
			triplet:    Triplet{AccessKeyID: "STS.NEWAK", AccessKeySecret: "NEWSECRET", SecurityToken: "NEWTOKEN"},
			wantPrefix: "acs STS.NEWAK:",
		},
		{
			// Multi-value query path (repeated key with multiple values).
			name:     "multi-value repeated key",
			method:   "GET",
			path:     "/clusters",
			rawQuery: "tag=alpha&tag=beta&page=1",
			headers: map[string]string{
				"host":          "cs.cn-hangzhou.aliyuncs.com",
				"accept":        "application/json",
				"date":          "Sun, 24 May 2026 10:00:00 GMT",
				"x-acs-version": "2015-12-15",
				"authorization": "acs OLDAK:oldsig=",
			},
			triplet:    Triplet{AccessKeyID: "AK", AccessKeySecret: "SK", SecurityToken: "ST"},
			wantPrefix: "acs AK:",
		},
		{
			// Query param with empty value (e.g. "force" flag).
			name:     "valueless query param",
			method:   "DELETE",
			path:     "/clusters/abc",
			rawQuery: "force",
			headers: map[string]string{
				"host":          "cs.cn-hangzhou.aliyuncs.com",
				"accept":        "application/json",
				"date":          "Sun, 24 May 2026 10:00:00 GMT",
				"x-acs-version": "2015-12-15",
				"authorization": "acs OLDAK:oldsig=",
			},
			triplet:    Triplet{AccessKeyID: "AK", AccessKeySecret: "SK", SecurityToken: "ST"},
			wantPrefix: "acs AK:",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := &RequestSnapshot{
				Method:   tc.method,
				Scheme:   "https",
				Host:     "cs.cn-hangzhou.aliyuncs.com",
				Path:     tc.path,
				RawQuery: tc.rawQuery,
				Headers:  tc.headers,
			}
			res, err := SignV1ROA(req, tc.triplet)
			if err != nil {
				t.Fatalf("SignV1ROA: %v", err)
			}
			authz := findHeader(t, res, "authorization")
			if !strings.HasPrefix(authz, tc.wantPrefix) {
				t.Errorf("authorization = %q, want prefix %q", authz, tc.wantPrefix)
			}

			// Recompute to verify consistency.
			wantSig, err := computeV1ROASignature(req, tc.triplet)
			if err != nil {
				t.Fatalf("computeV1ROASignature: %v", err)
			}
			if !strings.HasSuffix(authz, ":"+wantSig) {
				t.Errorf("signature mismatch:\n got  %s\n want suffix :%s", authz, wantSig)
			}
		})
	}
}
