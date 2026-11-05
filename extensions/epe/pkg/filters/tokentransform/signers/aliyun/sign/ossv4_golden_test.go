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
	"maps"
	"slices"
	"strings"
	"testing"
)

// The signatures below are an INDEPENDENT oracle: they were produced by the
// official Alibaba OSS Python SDK (oss2==2.19.1, ProviderAuthV4) driving its
// real _sign_request path against a pinned UTC clock (2026-05-24T10:00:00Z).
// They are hard-coded here so the assertion never calls back into the
// implementation under test; a bug in our canonicalization cannot make the
// expected value drift to match.
//
// Reproduce with oss2==2.19.1:
//
//	from oss2.auth import ProviderAuthV4
//	from oss2.credentials import StaticCredentialsProvider
//	from oss2.http import Request
//	# freeze datetime.utcnow() to 2026-05-24T10:00:00Z, then:
//	auth = ProviderAuthV4(StaticCredentialsProvider("STS.NEWAK","NEWSECRET","NEWTOKEN"))
//	req  = Request("GET", "https://mybucket.oss-cn-beijing-internal.aliyuncs.com/path/to/object.txt",
//	               headers={"host": "mybucket.oss-cn-beijing-internal.aliyuncs.com"})
//	req.region="cn-beijing"; req.product="oss"; req.cloudbox_id=None
//	auth._sign_request(req, "mybucket", "path/to/object.txt")  # -> Authorization Signature=...
//
// Key oss2 V4 rules these vectors pin down:
//   - Canonical URI is the bucket-qualified resource "/<bucket>/<key>", even
//     for virtual-hosted-style where the wire :path is only "/<key>".
//   - host is NOT a signed header (only x-oss-*, content-type, content-md5,
//     and explicit AdditionalHeaders participate); there is no host: line.
//   - x-oss-security-token, when present, is a signed x-oss-* header.
const (
	goldenHost   = "mybucket.oss-cn-beijing-internal.aliyuncs.com"
	goldenRegion = "cn-beijing"
	goldenAK     = "STS.NEWAK"
	goldenSK     = "NEWSECRET"
	goldenToken  = "NEWTOKEN"
	goldenDate   = "20260524T100000Z"
)

func TestSignOSSV4_Oss2GoldenSignatures(t *testing.T) {
	tests := []struct {
		name    string
		req     *RequestSnapshot
		triplet Triplet
		// wantSig is the oss2-produced signature hex (independent oracle).
		wantSig string
		// wantToken is the value the mutation must forward in
		// x-oss-security-token (empty => header must be removed).
		wantToken string
	}{
		{
			name: "GET object, virtual-hosted-style, UNSIGNED-PAYLOAD",
			req: &RequestSnapshot{
				Method: "GET",
				Host:   goldenHost,
				Path:   "/path/to/object.txt",
				Headers: map[string]string{
					"host":                 goldenHost,
					"x-oss-date":           goldenDate,
					"x-oss-content-sha256": "UNSIGNED-PAYLOAD",
				},
			},
			triplet:   Triplet{AccessKeyID: goldenAK, AccessKeySecret: goldenSK, SecurityToken: goldenToken},
			wantSig:   "02d1ed3aa2d4e4323db260483f44a9bae2d4f69b22aae4493cba73244e7a1245",
			wantToken: goldenToken,
		},
		{
			name: "PUT object with content-type",
			req: &RequestSnapshot{
				Method: "PUT",
				Host:   goldenHost,
				Path:   "/path/to/object.txt",
				Headers: map[string]string{
					"host":                 goldenHost,
					"content-type":         "text/plain",
					"x-oss-date":           goldenDate,
					"x-oss-content-sha256": "UNSIGNED-PAYLOAD",
				},
			},
			triplet:   Triplet{AccessKeyID: goldenAK, AccessKeySecret: goldenSK, SecurityToken: goldenToken},
			wantSig:   "e1ed3025a63175fe4d4e0127576c8df1de814f3d66f86aab29ffa4e09253c5ef",
			wantToken: goldenToken,
		},
		{
			name: "GET bucket with query string (list objects)",
			req: &RequestSnapshot{
				Method:   "GET",
				Host:     goldenHost,
				Path:     "/",
				RawQuery: "max-keys=100&prefix=foo%2F",
				Headers: map[string]string{
					"host":                 goldenHost,
					"x-oss-date":           goldenDate,
					"x-oss-content-sha256": "UNSIGNED-PAYLOAD",
				},
			},
			triplet:   Triplet{AccessKeyID: goldenAK, AccessKeySecret: goldenSK, SecurityToken: goldenToken},
			wantSig:   "9db5c9d7883356aaa9f9406d82f6f1c5e65fb4623b118e9073294cf98cad29fe",
			wantToken: goldenToken,
		},
		{
			name: "stale x-oss-security-token on request is replaced by triplet token",
			req: &RequestSnapshot{
				Method: "GET",
				Host:   goldenHost,
				Path:   "/path/to/object.txt",
				Headers: map[string]string{
					"host":                 goldenHost,
					"x-oss-date":           goldenDate,
					"x-oss-content-sha256": "UNSIGNED-PAYLOAD",
					"x-oss-security-token": "OLDSTS", // must not leak into the signature
				},
			},
			triplet: Triplet{AccessKeyID: goldenAK, AccessKeySecret: goldenSK, SecurityToken: goldenToken},
			// Identical to the plain GET object vector: proves the OLD token was
			// dropped from both the signing input and the forwarded header.
			wantSig:   "02d1ed3aa2d4e4323db260483f44a9bae2d4f69b22aae4493cba73244e7a1245",
			wantToken: goldenToken,
		},
		{
			name: "empty triplet token removes header and excludes it from signature",
			req: &RequestSnapshot{
				Method: "GET",
				Host:   goldenHost,
				Path:   "/path/to/object.txt",
				Headers: map[string]string{
					"host":                 goldenHost,
					"x-oss-date":           goldenDate,
					"x-oss-content-sha256": "UNSIGNED-PAYLOAD",
					"x-oss-security-token": "OLDSTS", // present on the wire, must be stripped
				},
			},
			triplet:   Triplet{AccessKeyID: goldenAK, AccessKeySecret: goldenSK}, // no SecurityToken
			wantSig:   "6575f2b4788869ae039cf5e38aa6fb6b933a993ef1ac25f5900bde83b6f910d4",
			wantToken: "", // => RemoveHeaders
		},
		{
			// oss2 puts '/' on the wire as %2F but signs with '/' preserved.
			// The signer must url-decode then re-encode; the expected signature
			// is identical to the plain "GET object" vector above.
			name: "wire path with %2F-encoded slashes decodes to same signature",
			req: &RequestSnapshot{
				Method: "GET",
				Host:   goldenHost,
				Path:   "/path%2Fto%2Fobject.txt",
				Headers: map[string]string{
					"host":                 goldenHost,
					"x-oss-date":           goldenDate,
					"x-oss-content-sha256": "UNSIGNED-PAYLOAD",
				},
			},
			triplet:   Triplet{AccessKeyID: goldenAK, AccessKeySecret: goldenSK, SecurityToken: goldenToken},
			wantSig:   "02d1ed3aa2d4e4323db260483f44a9bae2d4f69b22aae4493cba73244e7a1245",
			wantToken: goldenToken,
		},
		{
			// Key "dir one/obj a.txt": wire form percent-encodes space and slash.
			name: "wire path with encoded space and slash",
			req: &RequestSnapshot{
				Method: "GET",
				Host:   goldenHost,
				Path:   "/dir%20one%2Fobj%20a.txt",
				Headers: map[string]string{
					"host":                 goldenHost,
					"x-oss-date":           goldenDate,
					"x-oss-content-sha256": "UNSIGNED-PAYLOAD",
				},
			},
			triplet:   Triplet{AccessKeyID: goldenAK, AccessKeySecret: goldenSK, SecurityToken: goldenToken},
			wantSig:   "f7c69837e3e07dba486c3baa0d8cbd3292a1a54a75acaa0a3f9c98fecf7a73a4",
			wantToken: goldenToken,
		},
		{
			// Key "a+b/c.txt": '+' must stay '+' through decode (path semantics),
			// then re-encode to %2B; the slash was %2F on the wire.
			name: "wire path with plus sign preserved",
			req: &RequestSnapshot{
				Method: "GET",
				Host:   goldenHost,
				Path:   "/a%2Bb%2Fc.txt",
				Headers: map[string]string{
					"host":                 goldenHost,
					"x-oss-date":           goldenDate,
					"x-oss-content-sha256": "UNSIGNED-PAYLOAD",
				},
			},
			triplet:   Triplet{AccessKeyID: goldenAK, AccessKeySecret: goldenSK, SecurityToken: goldenToken},
			wantSig:   "7d2e5766346d049bff2a1cb46a39427a4e566aef185908dcc964fa6feabd6b21",
			wantToken: goldenToken,
		},
		{
			// Mixed-case header names are the point of this vector: production
			// Envoy lower-cases them, but the signer must not depend on that.
			//
			// The x-oss-content-sha256 value here is a real SHA256 rather than
			// UNSIGNED-PAYLOAD, which OSS does NOT accept (see
			// TestSignOSSV4_NeverRewritesPayloadHashHeader). It is used only to
			// show the value is taken from the header verbatim; such a request
			// gets a 400 from the service regardless of signing.
			name: "PUT, mixed-case header names, payload hash taken verbatim",
			req: &RequestSnapshot{
				Method: "PUT",
				Host:   goldenHost,
				Path:   "/data.bin",
				Headers: map[string]string{
					"Host":                 goldenHost,
					"Content-Type":         "application/octet-stream",
					"X-Oss-Date":           goldenDate,
					"X-Oss-Content-Sha256": "b94f6f125c79e3a5ffaa826f584c10d52ada669e6762051b826b55776d05aed2",
				},
			},
			triplet:   Triplet{AccessKeyID: goldenAK, AccessKeySecret: goldenSK, SecurityToken: goldenToken},
			wantSig:   "813ee82b51b50988ab0c775c9a2cd438e6fac4280594d04b8c2838407842a267",
			wantToken: goldenToken,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := SignOSSV4(tc.req, tc.triplet, OSSV4Params{Region: goldenRegion})
			if err != nil {
				t.Fatalf("SignOSSV4: %v", err)
			}
			authz := findHeader(t, res, "authorization")
			wantSub := "Signature=" + tc.wantSig
			if !strings.Contains(authz, wantSub) {
				t.Fatalf("signature mismatch vs oss2 oracle\n got  Authorization: %s\n want substring: %s", authz, wantSub)
			}
			// Credential must carry the new AK and the region-scoped path.
			wantCred := "Credential=" + goldenAK + "/" + goldenDate[:8] + "/" + goldenRegion + "/oss/aliyun_v4_request"
			if !strings.Contains(authz, wantCred) {
				t.Fatalf("credential mismatch\n got  %s\n want substring %s", authz, wantCred)
			}
			// The forwarded x-oss-security-token must byte-for-byte match the
			// token that participated in the signature.
			if tc.wantToken == "" {
				if !containsString(res.RemoveHeaders, "x-oss-security-token") {
					t.Fatalf("expected x-oss-security-token in RemoveHeaders, got %+v", res)
				}
				for _, h := range res.SetHeaders {
					if strings.EqualFold(h.Name, "x-oss-security-token") {
						t.Fatalf("x-oss-security-token must not be set when triplet token is empty")
					}
				}
			} else {
				got := findHeader(t, res, "x-oss-security-token")
				if got != tc.wantToken {
					t.Fatalf("forwarded x-oss-security-token = %q, want %q", got, tc.wantToken)
				}
			}
		})
	}
}

// TestSignOSSV4_Oss2GoldenSubresourceQuery pins OSS V4's query rule that a
// valueless parameter is rendered as bare "k", not "k=". Every OSS
// sub-resource API (?acl, ?uploads, ?delete, ?append, ?restore, …) depends on
// it. Signatures come from oss2==2.19.1 ProviderAuthV4 (independent oracle).
func TestSignOSSV4_Oss2GoldenSubresourceQuery(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		path     string
		rawQuery string
		wantSig  string
	}{
		{
			name:     "GetObjectACL ?acl",
			method:   "GET",
			path:     "/path/to/object.txt",
			rawQuery: "acl",
			wantSig:  "851a80701781e932946ffb87831593fea3d5b24c9417aab01ca1822a1d9e4ed7",
		},
		{
			// "?acl=" must canonicalize identically to "?acl": the SDK treats
			// an empty value as no value.
			name:     "?acl= equals ?acl",
			method:   "GET",
			path:     "/path/to/object.txt",
			rawQuery: "acl=",
			wantSig:  "851a80701781e932946ffb87831593fea3d5b24c9417aab01ca1822a1d9e4ed7",
		},
		{
			name:     "InitiateMultipartUpload ?uploads",
			method:   "POST",
			path:     "/path/to/object.txt",
			rawQuery: "uploads",
			wantSig:  "54384045449683be57c58730e625fb39d944f74084190b195cd5028f9020bf7a",
		},
		{
			name:     "valueless mixed with valued",
			method:   "GET",
			path:     "/path/to/object.txt",
			rawQuery: "acl&versionId=v1",
			wantSig:  "b48aed2712ee1a48d7fff1d8f88250c410ea7cd58eb49185ab0f5dd76f053525",
		},
		{
			// Sorting is by encoded key: "append" precedes "position".
			name:     "AppendObject ?append&position=0",
			method:   "POST",
			path:     "/path/to/object.txt",
			rawQuery: "position=0&append",
			wantSig:  "67b1351866cded4b241169863456976f6081ac27ed8043a3b47d17a9c5fd6dc1",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := &RequestSnapshot{
				Method:   tc.method,
				Host:     goldenHost,
				Path:     tc.path,
				RawQuery: tc.rawQuery,
				Headers: map[string]string{
					"host":                 goldenHost,
					"x-oss-date":           goldenDate,
					"x-oss-content-sha256": "UNSIGNED-PAYLOAD",
				},
			}
			tr := Triplet{AccessKeyID: goldenAK, AccessKeySecret: goldenSK, SecurityToken: goldenToken}
			res, err := SignOSSV4(req, tr, OSSV4Params{Region: goldenRegion})
			if err != nil {
				t.Fatalf("SignOSSV4: %v", err)
			}
			authz := findHeader(t, res, "authorization")
			if !strings.Contains(authz, "Signature="+tc.wantSig) {
				t.Fatalf("signature mismatch vs oss2 oracle (canonicalQuery=%q)\n got  %s\n want substring Signature=%s",
					ossV4CanonicalQuery(tc.rawQuery), authz, tc.wantSig)
			}
			// No AdditionalHeaders were declared, so the segment must be absent.
			if strings.Contains(authz, "AdditionalHeaders=") {
				t.Fatalf("unexpected AdditionalHeaders= segment: %s", authz)
			}
		})
	}
}

// TestSignOSSV4_GoSDKGoldenVerbatimQuery pins that the client's chosen
// percent-encoding in the query string is signed VERBATIM, not normalized.
//
// The oracle here is the official Alibaba Go SDK
// (github.com/aliyun/alibabacloud-oss-go-sdk-v2 v1.5.3,
// oss/signer.SignerV4.calcCanonicalRequest), which takes key/value text
// straight from Request.URL.RawQuery with only "+" folded to "%20". oss2 cannot
// produce these vectors because it always emits upper-case hex.
//
// Signing a normalized form would mismatch: the server signs what it received.
func TestSignOSSV4_GoSDKGoldenVerbatimQuery(t *testing.T) {
	tests := []struct {
		name     string
		rawQuery string
		wantSig  string
	}{
		{
			// Lower-case %2f must NOT be rewritten to %2F.
			name:     "lower-case percent-encoding preserved",
			rawQuery: "prefix=a%2fb",
			wantSig:  "339a628aa4fef368584b71cfb39060b68b3fdd928a71e669339fde39e7f9d5f8",
		},
		{
			// "+" is an encoded space and folds to %20.
			name:     "plus folds to %20",
			rawQuery: "prefix=a+b",
			wantSig:  "113a1287d4f2b2399da9b3f54aba95879491232ba3e7317ad1edcd026f0454f5",
		},
		{
			// Same signature as the "+" case above, proving the fold is correct
			// rather than merely self-consistent.
			name:     "explicit %20 equals folded plus",
			rawQuery: "prefix=a%20b",
			wantSig:  "113a1287d4f2b2399da9b3f54aba95879491232ba3e7317ad1edcd026f0454f5",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := &RequestSnapshot{
				Method:   "GET",
				Host:     goldenHost,
				Path:     "/",
				RawQuery: tc.rawQuery,
				Headers: map[string]string{
					"host":                 goldenHost,
					"x-oss-date":           goldenDate,
					"x-oss-content-sha256": "UNSIGNED-PAYLOAD",
				},
			}
			tr := Triplet{AccessKeyID: goldenAK, AccessKeySecret: goldenSK, SecurityToken: goldenToken}
			res, err := SignOSSV4(req, tr, OSSV4Params{Region: goldenRegion})
			if err != nil {
				t.Fatalf("SignOSSV4: %v", err)
			}
			authz := findHeader(t, res, "authorization")
			if !strings.Contains(authz, "Signature="+tc.wantSig) {
				t.Fatalf("signature mismatch vs Go SDK oracle (canonicalQuery=%q)\n got  %s\n want substring Signature=%s",
					ossV4CanonicalQuery(tc.rawQuery), authz, tc.wantSig)
			}
		})
	}
}

// TestSignOSSV4_Oss2GoldenAdditionalHeaders pins the AdditionalHeaders
// behaviour: the client-declared extra headers must (a) participate in
// CanonicalHeaders when present on the request, (b) be listed in the canonical
// request's AdditionalHeaders line even when absent from the request, and
// (c) be echoed in the re-signed Authorization. Signatures from oss2==2.19.1.
func TestSignOSSV4_Oss2GoldenAdditionalHeaders(t *testing.T) {
	tests := []struct {
		name string
		// declared is the AdditionalHeaders= value on the INCOMING request.
		declared string
		method   string
		extra    map[string]string
		wantSig  string
		// wantSegment is the AdditionalHeaders= value expected on the way out
		// ("" => segment must be omitted).
		wantSegment string
	}{
		{
			name:        "single additional header (range)",
			declared:    "range",
			method:      "GET",
			extra:       map[string]string{"range": "bytes=0-99"},
			wantSig:     "fdb79f648019901415f594c6442d5398e3efb3902c67fafae90890b325ad3d65",
			wantSegment: "range",
		},
		{
			// Mixed case + unsorted input must normalize to "if-match;range".
			name:     "multiple, mixed case, unsorted",
			declared: "Range;If-Match",
			method:   "PUT",
			extra: map[string]string{
				"range": "bytes=0-99", "if-match": `"etag123"`, "content-type": "text/plain",
			},
			wantSig:     "8d59e6d6329b04dac6b9777bf9014e0c8bd1e7a3ba8b44ddcbbbd5fb2ed51073",
			wantSegment: "if-match;range",
		},
		{
			// Declared but not present on the request: still listed, but must
			// not appear as a canonical header line.
			name:        "declared but absent",
			declared:    "range;x-not-present",
			method:      "GET",
			extra:       map[string]string{"range": "bytes=0-99"},
			wantSig:     "e45ea70784c91f25c733ee6ce981343dbf4e2740f7c5ebc0706084b90bdfb580",
			wantSegment: "range;x-not-present",
		},
		{
			// content-type and x-oss-* are signed by default, so the SDK drops
			// them from the additional list.
			name:        "default-signed names filtered out",
			declared:    "content-type;x-oss-foo;range",
			method:      "GET",
			extra:       map[string]string{"content-type": "text/plain", "range": "bytes=0-99"},
			wantSig:     "1567a811e634d8ce99ea7459973051cf95aacc5f75bede0dca4e15779a897405",
			wantSegment: "range",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			headers := map[string]string{
				"host":                 goldenHost,
				"x-oss-date":           goldenDate,
				"x-oss-content-sha256": "UNSIGNED-PAYLOAD",
				"authorization": "OSS4-HMAC-SHA256 Credential=OLDAK/" + goldenDate[:8] +
					"/" + goldenRegion + "/oss/aliyun_v4_request,Signature=stale,AdditionalHeaders=" + tc.declared,
			}
			maps.Copy(headers, tc.extra)
			req := &RequestSnapshot{
				Method:  tc.method,
				Host:    goldenHost,
				Path:    "/path/to/object.txt",
				Headers: headers,
			}
			tr := Triplet{AccessKeyID: goldenAK, AccessKeySecret: goldenSK, SecurityToken: goldenToken}

			// Drive the real dispatcher so the AdditionalHeaders parse from the
			// incoming Authorization header is exercised too.
			res, err := New().Resign(SignatureOSSV4, req, tr)
			if err != nil {
				t.Fatalf("Resign: %v", err)
			}
			authz := findHeader(t, res, "authorization")
			if !strings.Contains(authz, "Signature="+tc.wantSig) {
				t.Fatalf("signature mismatch vs oss2 oracle\n got  %s\n want substring Signature=%s", authz, tc.wantSig)
			}
			if tc.wantSegment == "" {
				if strings.Contains(authz, "AdditionalHeaders=") {
					t.Fatalf("expected no AdditionalHeaders= segment, got %s", authz)
				}
				return
			}
			if !strings.Contains(authz, "AdditionalHeaders="+tc.wantSegment) {
				t.Fatalf("AdditionalHeaders segment mismatch\n got  %s\n want substring AdditionalHeaders=%s", authz, tc.wantSegment)
			}
		})
	}
}

// TestOSSCanonicalResource_EndpointMatrix pins the canonical resource for every
// OSS endpoint family in the official reference ("通过Endpoint和Bucket域名访问OSS").
//
// The two dual-stack rows are why this test exists: that family puts the region
// first and a bare "oss" label second, which a prefix-based host test gets wrong
// in both directions — fabricating bucket=<region> for the service endpoint, and
// dropping the real bucket for the virtual-hosted one.
func TestOSSCanonicalResource_EndpointMatrix(t *testing.T) {
	tests := []struct {
		name       string
		host       string
		wirePath   string
		wantBucket string
		wantResult string
	}{
		{
			name:       "public, virtual-hosted",
			host:       "mybucket.oss-cn-beijing.aliyuncs.com",
			wirePath:   "/probe%2Fa.txt",
			wantBucket: "mybucket",
			wantResult: "/mybucket/probe/a.txt",
		},
		{
			name:       "internal, virtual-hosted",
			host:       "mybucket.oss-cn-beijing-internal.aliyuncs.com",
			wirePath:   "/probe%2Fa.txt",
			wantBucket: "mybucket",
			wantResult: "/mybucket/probe/a.txt",
		},
		{
			name:       "accelerate, virtual-hosted",
			host:       "mybucket.oss-accelerate.aliyuncs.com",
			wirePath:   "/probe%2Fa.txt",
			wantBucket: "mybucket",
			wantResult: "/mybucket/probe/a.txt",
		},
		{
			name:       "accelerate overseas, virtual-hosted",
			host:       "mybucket.oss-accelerate-overseas.aliyuncs.com",
			wirePath:   "/probe%2Fa.txt",
			wantBucket: "mybucket",
			wantResult: "/mybucket/probe/a.txt",
		},
		{
			// Path-style: the bucket already leads the path, must not be added twice.
			name:       "internal, path-style",
			host:       "oss-cn-beijing-internal.aliyuncs.com",
			wirePath:   "/mybucket/probe%2Fa.txt",
			wantBucket: "",
			wantResult: "/mybucket/probe/a.txt",
		},
		{
			name:       "service endpoint (list buckets)",
			host:       "oss-cn-beijing.aliyuncs.com",
			wirePath:   "/",
			wantBucket: "",
			wantResult: "/",
		},
		{
			name:       "dual-stack, virtual-hosted",
			host:       "mybucket.cn-beijing.oss.aliyuncs.com",
			wirePath:   "/probe%2Fa.txt",
			wantBucket: "mybucket",
			wantResult: "/mybucket/probe/a.txt",
		},
		{
			// Must NOT read the region as a bucket.
			name:       "dual-stack, path-style",
			host:       "cn-beijing.oss.aliyuncs.com",
			wirePath:   "/mybucket/probe%2Fa.txt",
			wantBucket: "",
			wantResult: "/mybucket/probe/a.txt",
		},
		{
			// Known gap: a custom domain carries no bucket, so none is recovered.
			name:       "custom domain (CNAME, known gap)",
			host:       "img.example.com",
			wirePath:   "/probe%2Fa.txt",
			wantBucket: "",
			wantResult: "/probe/a.txt",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := virtualHostedBucket(tc.host); got != tc.wantBucket {
				t.Errorf("virtualHostedBucket(%q) = %q, want %q", tc.host, got, tc.wantBucket)
			}
			if got := ossCanonicalResource(tc.host, tc.wirePath); got != tc.wantResult {
				t.Errorf("ossCanonicalResource(%q, %q) = %q, want %q",
					tc.host, tc.wirePath, got, tc.wantResult)
			}
		})
	}
}

// TestSignOSSV4_DualStackMatchesGolden checks the dual-stack endpoint end to end
// against the oss2 oracle. host is not a signed header and the canonical resource
// depends only on bucket+key, so a dual-stack request for the same bucket and key
// must yield exactly the same signature as the plain virtual-hosted "GET object"
// vector in TestSignOSSV4_Oss2GoldenSignatures.
func TestSignOSSV4_DualStackMatchesGolden(t *testing.T) {
	const wantSig = "02d1ed3aa2d4e4323db260483f44a9bae2d4f69b22aae4493cba73244e7a1245"
	dualStackHost := "mybucket.cn-beijing.oss.aliyuncs.com"
	req := &RequestSnapshot{
		Method: "GET",
		Host:   dualStackHost,
		Path:   "/path%2Fto%2Fobject.txt",
		Headers: map[string]string{
			"host":                 dualStackHost,
			"x-oss-date":           goldenDate,
			"x-oss-content-sha256": "UNSIGNED-PAYLOAD",
		},
	}
	res, err := SignOSSV4(req, Triplet{
		AccessKeyID:     goldenAK,
		AccessKeySecret: goldenSK,
		SecurityToken:   goldenToken,
	}, OSSV4Params{Region: goldenRegion})
	if err != nil {
		t.Fatalf("SignOSSV4: %v", err)
	}
	authz := findHeader(t, res, "authorization")
	if !strings.Contains(authz, "Signature="+wantSig) {
		t.Fatalf("dual-stack signature mismatch vs oss2 oracle\n got  %s\n want substring Signature=%s\n canonical resource = %q",
			authz, wantSig, ossCanonicalResource(dualStackHost, req.Path))
	}
}

// TestSignOSSV4_NeverRewritesPayloadHashHeader pins that the signer treats
// x-oss-content-sha256 as read-only: it is signed as found and never appears in
// the mutation set, whatever the client sent.
//
// Context (measured against the live service): OSS V4 header-mode
// signing accepts exactly one value for this header.
//
//	HTTP 400 InvalidArgument, EC 0002-00000214
//	"The x-oss-content-sha256 only supports UNSIGNED-PAYLOAD."
//	ArgumentName=x-oss-content-sha256
//
// Two consequences worth recording, both easy to get wrong:
//
//   - There is no request-body protection in this header to preserve or lose.
//     The canonical request's last line is a fixed sentinel, not a digest of the
//     body. Body integrity in OSS V4 comes from Content-MD5, which this signer
//     already covers because it is in the default signed header set (verified
//     live: matching MD5 -> 200; MD5 vs tampered body -> 400 InvalidDigest,
//     EC 0017-00000503).
//   - The official SDKs overwrite this header because they are first-signers
//     constructing the request. This signer re-signs someone else's request, so
//     it does not "correct" an illegal value on the client's behalf: such a
//     request earns the service's own 400 with or without the gateway. Silently
//     rewriting it would mask a client bug and would break if OSS ever accepts
//     further values.
func TestSignOSSV4_NeverRewritesPayloadHashHeader(t *testing.T) {
	tests := []struct {
		name        string
		payloadHash string
	}{
		{name: "UNSIGNED-PAYLOAD (the only value OSS accepts)", payloadHash: "UNSIGNED-PAYLOAD"},
		{
			name:        "illegal explicit hash is passed through untouched",
			payloadHash: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := &RequestSnapshot{
				Method: "PUT",
				Host:   goldenHost,
				Path:   "/data.bin",
				Headers: map[string]string{
					"host":                 goldenHost,
					"x-oss-date":           goldenDate,
					"x-oss-content-sha256": tc.payloadHash,
				},
			}
			res, err := SignOSSV4(req, Triplet{
				AccessKeyID:     goldenAK,
				AccessKeySecret: goldenSK,
				SecurityToken:   goldenToken,
			}, OSSV4Params{Region: goldenRegion})
			if err != nil {
				t.Fatalf("SignOSSV4: %v", err)
			}
			for _, h := range res.SetHeaders {
				if strings.EqualFold(h.Name, "x-oss-content-sha256") {
					t.Fatalf("signer must not set x-oss-content-sha256, got %q", h.Value)
				}
			}
			if containsString(res.RemoveHeaders, "x-oss-content-sha256") {
				t.Fatal("signer must not remove x-oss-content-sha256")
			}
			// The caller's map must be left alone as well.
			if got := req.Headers["x-oss-content-sha256"]; got != tc.payloadHash {
				t.Fatalf("caller's header map mutated: %q, want %q", got, tc.payloadHash)
			}
		})
	}
}

func containsString(ss []string, want string) bool {
	return slices.Contains(ss, want)
}
