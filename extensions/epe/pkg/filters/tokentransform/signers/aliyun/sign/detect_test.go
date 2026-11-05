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
	"testing"
)

func TestNeedsBody(t *testing.T) {
	formHeaders := map[string]string{
		"content-type":   "application/x-www-form-urlencoded",
		"content-length": "42",
	}

	tests := []struct {
		name    string
		v       SignatureVersion
		method  string
		headers map[string]string
		want    bool
	}{
		{
			name:    "V1RPC POST with form body and content-length needs body",
			v:       SignatureV1RPC,
			method:  "POST",
			headers: formHeaders,
			want:    true,
		},
		{
			name:    "V1RPC post lowercase with form body needs body",
			v:       SignatureV1RPC,
			method:  "post",
			headers: formHeaders,
			want:    true,
		},
		{
			name:    "V1RPC POST with content-length whitespace still needs body",
			v:       SignatureV1RPC,
			method:  "POST",
			headers: map[string]string{"content-type": "application/x-www-form-urlencoded", "content-length": "  42  "},
			want:    true,
		},
		{
			name:    "V1RPC POST with form body and content-type charset suffix needs body",
			v:       SignatureV1RPC,
			method:  "POST",
			headers: map[string]string{"content-type": "application/x-www-form-urlencoded; charset=utf-8", "content-length": "7"},
			want:    true,
		},
		{
			name:    "V1RPC POST without any body headers does not need body (aliyun CLI query-only)",
			v:       SignatureV1RPC,
			method:  "POST",
			headers: nil,
			want:    false,
		},
		{
			name:    "V1RPC POST with explicit content-length 0 does not need body",
			v:       SignatureV1RPC,
			method:  "POST",
			headers: map[string]string{"content-type": "application/x-www-form-urlencoded", "content-length": "0"},
			want:    false,
		},
		{
			name:    "V1RPC POST with form content-type but no content-length does not need body",
			v:       SignatureV1RPC,
			method:  "POST",
			headers: map[string]string{"content-type": "application/x-www-form-urlencoded"},
			want:    false,
		},
		{
			name:    "V1RPC POST with content-length but non-form content-type does not need body",
			v:       SignatureV1RPC,
			method:  "POST",
			headers: map[string]string{"content-type": "application/json", "content-length": "42"},
			want:    false,
		},
		{
			name:    "V1RPC GET with form body does not need body (non-POST)",
			v:       SignatureV1RPC,
			method:  "GET",
			headers: formHeaders,
			want:    false,
		},
		{
			name:    "V3 POST with form body does not need body (non-V1RPC)",
			v:       SignatureV3,
			method:  "POST",
			headers: formHeaders,
			want:    false,
		},
		{
			name:    "V1ROA POST with form body does not need body (non-V1RPC)",
			v:       SignatureV1ROA,
			method:  "POST",
			headers: formHeaders,
			want:    false,
		},
		{
			name:    "OSSV4 POST with form body does not need body (non-V1RPC)",
			v:       SignatureOSSV4,
			method:  "POST",
			headers: formHeaders,
			want:    false,
		},
		{
			name:    "unknown POST with form body does not need body",
			v:       SignatureUnknown,
			method:  "POST",
			headers: formHeaders,
			want:    false,
		},
		{
			name:    "V1RPC empty method with form body does not need body",
			v:       SignatureV1RPC,
			method:  "",
			headers: formHeaders,
			want:    false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := NeedsBody(tc.v, tc.method, tc.headers); got != tc.want {
				t.Fatalf("NeedsBody(%v, %q, %v) = %v, want %v", tc.v, tc.method, tc.headers, got, tc.want)
			}
		})
	}
}

func TestDetect(t *testing.T) {
	tests := []struct {
		name string
		req  *RequestSnapshot
		want SignatureVersion
	}{
		{
			name: "v3 by Authorization prefix",
			req: &RequestSnapshot{
				Headers: map[string]string{
					"authorization": "ACS3-HMAC-SHA256 Credential=AK,SignedHeaders=h,Signature=abc",
				},
			},
			want: SignatureV3,
		},
		{
			name: "ossv4 by Authorization prefix",
			req: &RequestSnapshot{
				Headers: map[string]string{
					"authorization": "OSS4-HMAC-SHA256 Credential=AK,Signature=abc",
				},
			},
			want: SignatureOSSV4,
		},
		{
			name: "v1roa by acs prefix",
			req: &RequestSnapshot{
				Headers: map[string]string{
					"authorization": "acs AK:Base64Signature==",
				},
			},
			want: SignatureV1ROA,
		},
		{
			name: "v1rpc by query params",
			req: &RequestSnapshot{
				RawQuery: "Action=DescribeRegions&AccessKeyId=AK&SecurityToken=ST&Signature=abc&SignatureMethod=HMAC-SHA1&SignatureVersion=1.0",
			},
			want: SignatureV1RPC,
		},
		{
			name: "unknown when nothing matches",
			req: &RequestSnapshot{
				Headers: map[string]string{"authorization": "Bearer abc"},
			},
			want: SignatureUnknown,
		},
		{
			name: "v1rpc query without SecurityToken still detected",
			req: &RequestSnapshot{
				RawQuery: "Action=X&AccessKeyId=AK&Signature=s&SignatureMethod=HMAC-SHA1",
			},
			want: SignatureV1RPC,
		},
		{
			name: "unknown on nil snapshot",
			req:  nil,
			want: SignatureUnknown,
		},
		{
			name: "empty headers and empty query",
			req:  &RequestSnapshot{Headers: map[string]string{}},
			want: SignatureUnknown,
		},
		{
			name: "v1rpc query missing Signature",
			req: &RequestSnapshot{
				RawQuery: "AccessKeyId=AK&SecurityToken=ST&SignatureMethod=HMAC-SHA1",
			},
			want: SignatureUnknown,
		},
		{
			name: "v1rpc query missing AccessKeyId",
			req: &RequestSnapshot{
				RawQuery: "Signature=s&SecurityToken=ST&SignatureMethod=HMAC-SHA1",
			},
			want: SignatureUnknown,
		},
		{
			name: "v1rpc query missing SignatureMethod",
			req: &RequestSnapshot{
				RawQuery: "Signature=s&AccessKeyId=AK&SecurityToken=ST",
			},
			want: SignatureUnknown,
		},
		{
			name: "v1rpc query wrong SignatureMethod",
			req: &RequestSnapshot{
				RawQuery: "Signature=s&AccessKeyId=AK&SecurityToken=ST&SignatureMethod=HMAC-SHA256",
			},
			want: SignatureUnknown,
		},
		{
			name: "authorization with acs prefix but no colon",
			req: &RequestSnapshot{
				Headers: map[string]string{"authorization": "acs AK-no-colon"},
			},
			want: SignatureUnknown,
		},
		{
			name: "authorization with leading whitespace v3",
			req: &RequestSnapshot{
				Headers: map[string]string{
					"authorization": "  ACS3-HMAC-SHA256 Credential=AK,SignedHeaders=h,Signature=abc",
				},
			},
			want: SignatureV3,
		},
		{
			name: "nil headers map with raw query",
			req: &RequestSnapshot{
				RawQuery: "AccessKeyId=AK&SecurityToken=ST&Signature=s&SignatureMethod=HMAC-SHA1",
			},
			want: SignatureV1RPC,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Detect(tc.req); got != tc.want {
				t.Fatalf("Detect = %v, want %v", got, tc.want)
			}
		})
	}
}
