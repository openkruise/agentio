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

func TestSignerResign_DispatchesByVersion(t *testing.T) {
	s := New()
	tr := Triplet{AccessKeyID: "AK", AccessKeySecret: "SK", SecurityToken: "ST"}

	v3Req := &RequestSnapshot{
		Method: "POST",
		Scheme: "https",
		Host:   "ecs.aliyuncs.com",
		Path:   "/",
		Headers: map[string]string{
			"host":                 "ecs.aliyuncs.com",
			"x-acs-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
	}
	if _, err := s.Resign(SignatureV3, v3Req, tr); err != nil {
		t.Fatalf("V3 dispatch: %v", err)
	}

	rpcReq := &RequestSnapshot{
		Method:   "GET",
		Path:     "/",
		RawQuery: "AccessKeyId=AK&SignatureMethod=HMAC-SHA1&SecurityToken=ST&Signature=stale",
	}
	res, err := s.Resign(SignatureV1RPC, rpcReq, tr)
	if err != nil {
		t.Fatalf("V1RPC dispatch: %v", err)
	}
	if res.NewPath == nil {
		t.Fatalf("V1RPC should set NewPath")
	}

	if _, err := s.Resign(SignatureUnknown, v3Req, tr); err == nil ||
		!strings.Contains(err.Error(), "unknown") {
		t.Fatalf("expected unknown-version error, got %v", err)
	}
	if _, err := s.Resign(SignatureOSSV4, v3Req, tr); err == nil ||
		!strings.Contains(err.Error(), "region") {
		// OSS V4 requires region; without OSSV4Params context, dispatcher
		// derives region from the existing Authorization header. Here
		// the request has no OSS-V4 authz, so an error is expected.
		t.Fatalf("expected OSSV4 region-derivation error, got %v", err)
	}
}

func TestSignerResign_DispatchRewritesAuthorization(t *testing.T) {
	tests := []struct {
		name       string
		version    SignatureVersion
		req        *RequestSnapshot
		wantPrefix string
	}{
		{
			name:    "V1ROA",
			version: SignatureV1ROA,
			req: &RequestSnapshot{
				Method: "GET",
				Scheme: "https",
				Host:   "cs.cn-hangzhou.aliyuncs.com",
				Path:   "/clusters",
				Headers: map[string]string{
					"host":                  "cs.cn-hangzhou.aliyuncs.com",
					"accept":                "application/json",
					"date":                  "Sun, 24 May 2026 10:00:00 GMT",
					"x-acs-version":         "2015-12-15",
					"x-acs-signature-nonce": "abcdef",
					"x-acs-security-token":  "OLDSTS",
					"authorization":         "acs OLDAK:oldsig=",
				},
			},
			wantPrefix: "acs STS.NEWAK:",
		},
		{
			name:    "OSSV4",
			version: SignatureOSSV4,
			req: &RequestSnapshot{
				Method: "GET",
				Scheme: "https",
				Host:   "oss-cn-hangzhou.aliyuncs.com",
				Path:   "/",
				Headers: map[string]string{
					"host":                 "oss-cn-hangzhou.aliyuncs.com",
					"x-oss-date":           "20260524T100000Z",
					"x-oss-content-sha256": "UNSIGNED-PAYLOAD",
					"authorization":        "OSS4-HMAC-SHA256 Credential=OLDAK/20260524/cn-hangzhou/oss/aliyun_v4_request,Signature=stale",
				},
			},
			wantPrefix: "OSS4-HMAC-SHA256 ",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := New()
			tr := Triplet{AccessKeyID: "STS.NEWAK", AccessKeySecret: "NEWSECRET", SecurityToken: "NEWTOKEN"}
			res, err := s.Resign(tc.version, tc.req, tr)
			if err != nil {
				t.Fatalf("%s dispatch: %v", tc.name, err)
			}
			authz := findHeader(t, res, "authorization")
			if !strings.HasPrefix(authz, tc.wantPrefix) {
				t.Fatalf("%s authorization not rewritten: %q", tc.name, authz)
			}
		})
	}
}

func TestExtractOSSV4Region(t *testing.T) {
	tests := []struct {
		name        string
		req         *RequestSnapshot
		wantRegion  string
		expectError string
	}{
		{
			name:        "nil request",
			req:         nil,
			expectError: "nil request snapshot",
		},
		{
			name: "no Credential in Authorization",
			req: &RequestSnapshot{
				Headers: map[string]string{
					"authorization": "OSS4-HMAC-SHA256 Signature=abc",
				},
			},
			expectError: "no Credential=",
		},
		{
			name: "Credential with fewer than 5 segments",
			req: &RequestSnapshot{
				Headers: map[string]string{
					"authorization": "OSS4-HMAC-SHA256 Credential=AK/20260524/cn-hangzhou,Signature=abc",
				},
			},
			expectError: "has 3 segments, want 5",
		},
		{
			name: "Credential with empty region segment",
			req: &RequestSnapshot{
				Headers: map[string]string{
					"authorization": "OSS4-HMAC-SHA256 Credential=AK/20260524//oss/aliyun_v4_request,Signature=abc",
				},
			},
			expectError: "empty region segment",
		},
		{
			name: "valid Credential extracts region",
			req: &RequestSnapshot{
				Headers: map[string]string{
					"authorization": "OSS4-HMAC-SHA256 Credential=AK/20260524/cn-hangzhou/oss/aliyun_v4_request,Signature=abc",
				},
			},
			wantRegion: "cn-hangzhou",
		},
		{
			name: "valid Credential without trailing comma",
			req: &RequestSnapshot{
				Headers: map[string]string{
					"authorization": "OSS4-HMAC-SHA256 Credential=AK/20260524/us-west-1/oss/aliyun_v4_request",
				},
			},
			wantRegion: "us-west-1",
		},
		{
			name: "empty authorization header",
			req: &RequestSnapshot{
				Headers: map[string]string{},
			},
			expectError: "no Credential=",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			region, err := extractOSSV4Region(tc.req)
			if tc.expectError != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.expectError)
				}
				if !strings.Contains(err.Error(), tc.expectError) {
					t.Errorf("error = %v, want substring %q", err, tc.expectError)
				}
				return
			}
			if err != nil {
				t.Fatalf("extractOSSV4Region: %v", err)
			}
			if region != tc.wantRegion {
				t.Errorf("region = %q, want %q", region, tc.wantRegion)
			}
		})
	}
}

func TestSignatureVersion_String(t *testing.T) {
	tests := []struct {
		name string
		v    SignatureVersion
		want string
	}{
		{name: "V3", v: SignatureV3, want: "v3"},
		{name: "V1RPC", v: SignatureV1RPC, want: "v1rpc"},
		{name: "V1ROA", v: SignatureV1ROA, want: "v1roa"},
		{name: "OSSV4", v: SignatureOSSV4, want: "ossv4"},
		{name: "Unknown", v: SignatureUnknown, want: "unknown"},
		{name: "out of range", v: SignatureVersion(99), want: "unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.v.String(); got != tc.want {
				t.Errorf("String() = %q, want %q", got, tc.want)
			}
		})
	}
}
