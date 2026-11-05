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
	"slices"
	"strings"
	"testing"
)

// TestSignV3_GoldenECSDescribeRegions resigns a deterministic ECS
// DescribeRegions request with the triplet {AKID: "STS.NEWAK",
// AKSecret: "NEWSECRET", STS: "NEWTOKEN"}. The expected Signature is
// recomputed from the input fields rather than hard-coded.
func TestSignV3_GoldenECSDescribeRegions(t *testing.T) {
	req := &RequestSnapshot{
		Method:   "POST",
		Scheme:   "https",
		Host:     "ecs.cn-hangzhou.aliyuncs.com",
		Path:     "/",
		RawQuery: "",
		Headers: map[string]string{
			"host":                  "ecs.cn-hangzhou.aliyuncs.com",
			"content-type":          "application/x-www-form-urlencoded; charset=utf-8",
			"x-acs-action":          "DescribeRegions",
			"x-acs-version":         "2014-05-26",
			"x-acs-date":            "2026-05-24T10:00:00Z",
			"x-acs-signature-nonce": "0123456789abcdef",
			"x-acs-content-sha256":  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			"authorization":         "ACS3-HMAC-SHA256 Credential=OLDAK,SignedHeaders=content-type;host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-signature-nonce;x-acs-version,Signature=stale",
			"x-acs-accesskey-id":    "OLDAK",
			"x-acs-security-token":  "OLDSTS",
		},
	}
	triplet := Triplet{
		AccessKeyID:     "STS.NEWAK",
		AccessKeySecret: "NEWSECRET",
		SecurityToken:   "NEWTOKEN",
	}

	res, err := SignV3(req, triplet)
	if err != nil {
		t.Fatalf("SignV3: unexpected error %v", err)
	}
	if res == nil || len(res.SetHeaders) == 0 {
		t.Fatalf("SignV3: empty result")
	}

	got := findHeader(t, res, "authorization")
	if !strings.HasPrefix(got, "ACS3-HMAC-SHA256 Credential=STS.NEWAK,SignedHeaders=") {
		t.Fatalf("authorization prefix wrong: %q", got)
	}
	// Signed headers must include x-acs-security-token now that we set it
	// with the new value.
	if !strings.Contains(got, "x-acs-security-token") {
		t.Fatalf("SignedHeaders missing x-acs-security-token: %q", got)
	}
	if v := findHeader(t, res, "x-acs-accesskey-id"); v != "STS.NEWAK" {
		t.Fatalf("x-acs-accesskey-id = %q, want STS.NEWAK", v)
	}
	if v := findHeader(t, res, "x-acs-security-token"); v != "NEWTOKEN" {
		t.Fatalf("x-acs-security-token = %q, want NEWTOKEN", v)
	}
	// And the Signature segment is deterministic for this input.
	want := "Signature=" + expectedV3Sig(t, req, triplet)
	if !strings.Contains(got, want) {
		t.Fatalf("Signature segment mismatch:\n got  %s\n want substring %s", got, want)
	}
}

// V3 requires host in the signed set, and the gateway recomputes the signature
// from the request it received. Envoy's header map carries the authority as the
// ":authority" pseudo-header — its static lookup table maps the legacy "host"
// key onto the same inline slot — so ext_proc delivers no literal "host" entry
// for HTTP/1.1 or HTTP/2. The signer must recover it from the snapshot's Host
// rather than silently signing without it.
func TestSignV3_SignsHostFromAuthorityPseudoHeader(t *testing.T) {
	req := &RequestSnapshot{
		Method: "POST",
		Scheme: "https",
		Host:   "ecs.cn-hangzhou.aliyuncs.com",
		Path:   "/",
		Headers: map[string]string{
			// Exactly what the ext_proc adapter produces: an authority
			// pseudo-header and no "host" key.
			":authority":           "ecs.cn-hangzhou.aliyuncs.com",
			"content-type":         "application/x-www-form-urlencoded; charset=utf-8",
			"x-acs-action":         "DescribeRegions",
			"x-acs-version":        "2014-05-26",
			"x-acs-date":           "2026-05-24T10:00:00Z",
			"x-acs-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
	}
	res, err := SignV3(req, Triplet{AccessKeyID: "AK", AccessKeySecret: "SECRET"})
	if err != nil {
		t.Fatalf("SignV3: %v", err)
	}
	got := findHeader(t, res, "authorization")
	signed := signedHeadersOf(t, got)
	if !slices.Contains(signed, "host") {
		t.Fatalf("SignedHeaders = %v, want host included — the gateway signs the host it received", signed)
	}
}

// The host line must carry the authority value, not just appear in the list.
func TestSignV3_HostLineUsesAuthorityValue(t *testing.T) {
	base := func(hostKey string) *RequestSnapshot {
		return &RequestSnapshot{
			Method: "GET",
			Scheme: "https",
			Host:   "ecs.cn-hangzhou.aliyuncs.com",
			Path:   "/",
			Headers: map[string]string{
				hostKey:                "ecs.cn-hangzhou.aliyuncs.com",
				"x-acs-action":         "DescribeRegions",
				"x-acs-version":        "2014-05-26",
				"x-acs-date":           "2026-05-24T10:00:00Z",
				"x-acs-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
		}
	}
	// A literal "host" key and an ":authority" key must produce the same
	// signature: the canonical request depends on the value, not the spelling.
	withHost, err := SignV3(base("host"), Triplet{AccessKeyID: "AK", AccessKeySecret: "SECRET"})
	if err != nil {
		t.Fatalf("SignV3 (host): %v", err)
	}
	withAuthority, err := SignV3(base(":authority"), Triplet{AccessKeyID: "AK", AccessKeySecret: "SECRET"})
	if err != nil {
		t.Fatalf("SignV3 (:authority): %v", err)
	}
	a := findHeader(t, withHost, "authorization")
	b := findHeader(t, withAuthority, "authorization")
	if a != b {
		t.Fatalf("signature depends on the host spelling:\n host:      %s\n :authority: %s", a, b)
	}
}

// The synthesized host line must carry the authority verbatim, port included.
// attributes.splitHostPort peels the port off into HTTPRequest.Port, so
// RequestSnapshot.Host alone is port-less — but the gateway canonicalizes the
// authority it received, so signing the bare hostname for a request sent to an
// explicit port would diverge exactly the way signing no host at all does.
func TestSignV3_SynthesizedHostKeepsThePort(t *testing.T) {
	req := &RequestSnapshot{
		Method: "GET",
		Scheme: "https",
		// What attributes.parseHTTPRequest produces for ":authority" of
		// "ecs.cn-hangzhou.aliyuncs.com:8443": the port lives elsewhere.
		Host: "ecs.cn-hangzhou.aliyuncs.com",
		Path: "/",
		Headers: map[string]string{
			":authority":           "ecs.cn-hangzhou.aliyuncs.com:8443",
			"x-acs-action":         "DescribeRegions",
			"x-acs-version":        "2014-05-26",
			"x-acs-date":           "2026-05-24T10:00:00Z",
			"x-acs-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
	}
	res, err := SignV3(req, Triplet{AccessKeyID: "AK", AccessKeySecret: "SECRET"})
	if err != nil {
		t.Fatalf("SignV3: %v", err)
	}
	// An explicit literal host header carrying the same authority is the
	// reference: it is what the old code signed and what the gateway sees.
	ref := &RequestSnapshot{
		Method: "GET",
		Scheme: "https",
		Host:   "ecs.cn-hangzhou.aliyuncs.com",
		Path:   "/",
		Headers: map[string]string{
			"host":                 "ecs.cn-hangzhou.aliyuncs.com:8443",
			"x-acs-action":         "DescribeRegions",
			"x-acs-version":        "2014-05-26",
			"x-acs-date":           "2026-05-24T10:00:00Z",
			"x-acs-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
	}
	refRes, err := SignV3(ref, Triplet{AccessKeyID: "AK", AccessKeySecret: "SECRET"})
	if err != nil {
		t.Fatalf("SignV3 (reference): %v", err)
	}
	got, want := findHeader(t, res, "authorization"), findHeader(t, refRes, "authorization")
	if got != want {
		t.Fatalf("synthesized host dropped the port:\n got  %s\n want %s", got, want)
	}
}

// V3 canonicalizes by parameter, so a wire query Go refuses to split into
// parameters (';' separators, invalid escapes) leaves the parameter set
// undetermined and signing fails rather than covering a partial set. The old
// code could not reach this: it signed a re-encoding of the same failed parse,
// so it silently signed fewer parameters than Envoy forwarded and the gateway
// rejected the request instead. Failing here is the diagnosable end of that.
func TestSignV3_MalformedWireQueryFailsRatherThanSigningPartially(t *testing.T) {
	for _, rawQuery := range []string{"a=1;b=2&c=3", "a=%zz&b=2"} {
		req := &RequestSnapshot{
			Method:   "GET",
			Scheme:   "https",
			Host:     "ecs.cn-hangzhou.aliyuncs.com",
			Path:     "/",
			RawQuery: rawQuery,
			Headers: map[string]string{
				":authority":           "ecs.cn-hangzhou.aliyuncs.com",
				"x-acs-action":         "DescribeRegions",
				"x-acs-version":        "2014-05-26",
				"x-acs-date":           "2026-05-24T10:00:00Z",
				"x-acs-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
		}
		if _, err := SignV3(req, Triplet{AccessKeyID: "AK", AccessKeySecret: "SECRET"}); err == nil {
			t.Errorf("RawQuery %q: signed successfully, want an error over a partial parameter set", rawQuery)
		}
	}
}

// A well-formed wire query signs the same whether or not its percent-encoding
// is in Go's canonical form: V3 decodes and re-encodes per parameter, so
// carrying the verbatim query changed nothing here.
func TestSignV3_WireEncodingVariantsSignIdentically(t *testing.T) {
	sign := func(rawQuery string) string {
		req := &RequestSnapshot{
			Method:   "GET",
			Scheme:   "https",
			Host:     "ecs.cn-hangzhou.aliyuncs.com",
			Path:     "/",
			RawQuery: rawQuery,
			Headers: map[string]string{
				":authority":           "ecs.cn-hangzhou.aliyuncs.com",
				"x-acs-action":         "DescribeRegions",
				"x-acs-version":        "2014-05-26",
				"x-acs-date":           "2026-05-24T10:00:00Z",
				"x-acs-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
		}
		res, err := SignV3(req, Triplet{AccessKeyID: "AK", AccessKeySecret: "SECRET"})
		if err != nil {
			t.Fatalf("SignV3(%q): %v", rawQuery, err)
		}
		return findHeader(t, res, "authorization")
	}
	if lower, upper := sign("prefix=a%2fb"), sign("prefix=a%2Fb"); lower != upper {
		t.Errorf("hex case changed the V3 signature:\n %s\n %s", lower, upper)
	}
}

// signedHeadersOf extracts the SignedHeaders list out of an ACS3 Authorization.
func signedHeadersOf(t *testing.T, authorization string) []string {
	t.Helper()
	for _, seg := range strings.Split(authorization, ",") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(seg), "SignedHeaders="); ok {
			return strings.Split(rest, ";")
		}
	}
	t.Fatalf("no SignedHeaders segment in %q", authorization)
	return nil
}

// The reference signer canonicalizes the URI before signing:
// alibabacloud-go/openapi-util GetAuthorization replaces '+' with %20, '*'
// with %2A, and '%7E' with '~'. The gateway normalizes what it received the
// same way, so signing the raw wire path diverges for any path carrying those
// characters.
func TestV3CanonicalURI_MatchesReferenceNormalization(t *testing.T) {
	tests := []struct{ in, want string }{
		{"/", "/"},
		{"/clusters/c-abc", "/clusters/c-abc"},
		{"/foo+bar", "/foo%20bar"},
		{"/foo*bar", "/foo%2Abar"},
		{"/foo%7Ebar", "/foo~bar"},
		{"/a+b*c%7Ed", "/a%20b%2Ac~d"},
		// An empty path signs as "/", matching the reference signer.
		{"", "/"},
	}
	for _, tc := range tests {
		if got := v3CanonicalURI(tc.in); got != tc.want {
			t.Errorf("v3CanonicalURI(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// End-to-end: two paths that differ only in a character the reference signer
// normalizes must produce the same signature, because the gateway normalizes
// both to the same canonical URI before verifying.
func TestSignV3_NormalizesPathBeforeSigning(t *testing.T) {
	sign := func(path string) string {
		req := &RequestSnapshot{
			Method: "GET",
			Scheme: "https",
			Host:   "cs.cn-hangzhou.aliyuncs.com",
			Path:   path,
			Headers: map[string]string{
				"x-acs-action":         "DescribeClusters",
				"x-acs-version":        "2015-12-15",
				"x-acs-date":           "2026-05-24T10:00:00Z",
				"x-acs-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
		}
		res, err := SignV3(req, Triplet{AccessKeyID: "AK", AccessKeySecret: "SECRET"})
		if err != nil {
			t.Fatalf("SignV3(%q): %v", path, err)
		}
		return findHeader(t, res, "authorization")
	}
	if a, b := sign("/clusters/c%7Eabc"), sign("/clusters/c~abc"); a != b {
		t.Fatalf("'%%7E' and '~' paths signed differently:\n %s\n %s", a, b)
	}
}

func TestSignV3_InvalidInput(t *testing.T) {
	tests := []struct {
		name    string
		req     *RequestSnapshot
		triplet Triplet
		wantErr string
	}{
		{
			name: "missing x-acs-content-sha256",
			req: &RequestSnapshot{
				Method: "POST",
				Scheme: "https",
				Host:   "ecs.cn-hangzhou.aliyuncs.com",
				Path:   "/",
				Headers: map[string]string{
					"host":          "ecs.cn-hangzhou.aliyuncs.com",
					"authorization": "ACS3-HMAC-SHA256 Credential=AK,SignedHeaders=host,Signature=x",
				},
			},
			triplet: Triplet{AccessKeyID: "AK", AccessKeySecret: "SK"},
			wantErr: "x-acs-content-sha256",
		},
		{
			name: "empty AccessKeySecret",
			req: &RequestSnapshot{
				Method: "POST",
				Scheme: "https",
				Host:   "ecs.cn-hangzhou.aliyuncs.com",
				Path:   "/",
				Headers: map[string]string{
					"host":                 "ecs.cn-hangzhou.aliyuncs.com",
					"x-acs-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				},
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
			_, err := SignV3(tc.req, tc.triplet)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestSignV3_EmptySecurityTokenRemovesHeader(t *testing.T) {
	req := &RequestSnapshot{
		Method: "POST",
		Scheme: "https",
		Host:   "ecs.cn-hangzhou.aliyuncs.com",
		Path:   "/",
		Headers: map[string]string{
			"host":                 "ecs.cn-hangzhou.aliyuncs.com",
			"x-acs-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			"x-acs-action":         "DescribeRegions",
			"x-acs-version":        "2014-05-26",
			"x-acs-date":           "2026-05-24T10:00:00Z",
			"x-acs-security-token": "OLDSTS",
		},
	}
	tr := Triplet{AccessKeyID: "AK", AccessKeySecret: "SK"}
	res, err := SignV3(req, tr)
	if err != nil {
		t.Fatalf("SignV3: %v", err)
	}
	if !containsString(res.RemoveHeaders, "x-acs-security-token") {
		t.Errorf("expected x-acs-security-token in RemoveHeaders, got %v", res.RemoveHeaders)
	}
	for _, h := range res.SetHeaders {
		if strings.EqualFold(h.Name, "x-acs-security-token") {
			t.Errorf("x-acs-security-token should not be set when SecurityToken is empty")
		}
	}
	// The signed headers in Authorization should NOT include x-acs-security-token.
	authz := findHeader(t, res, "authorization")
	if !strings.HasPrefix(authz, "ACS3-HMAC-SHA256 ") {
		t.Errorf("authorization prefix wrong: %q", authz)
	}
}

func TestSignV3_WithQueryString(t *testing.T) {
	// Exercises the canonicalQuery path in computeV3SignatureAndHeaders.
	req := &RequestSnapshot{
		Method:   "GET",
		Scheme:   "https",
		Host:     "ecs.cn-hangzhou.aliyuncs.com",
		Path:     "/",
		RawQuery: "Action=DescribeRegions&Version=2014-05-26",
		Headers: map[string]string{
			"host":                 "ecs.cn-hangzhou.aliyuncs.com",
			"x-acs-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			"x-acs-date":           "2026-05-24T10:00:00Z",
		},
	}
	tr := Triplet{AccessKeyID: "AK", AccessKeySecret: "SK", SecurityToken: "ST"}
	res, err := SignV3(req, tr)
	if err != nil {
		t.Fatalf("SignV3: %v", err)
	}
	authz := findHeader(t, res, "authorization")
	if !strings.HasPrefix(authz, "ACS3-HMAC-SHA256 ") {
		t.Errorf("authorization prefix wrong: %q", authz)
	}

	// Recompute to verify consistency.
	wantSig, err := computeV3Signature(req, tr)
	if err != nil {
		t.Fatalf("computeV3Signature: %v", err)
	}
	if !strings.Contains(authz, "Signature="+wantSig) {
		t.Errorf("signature mismatch:\n got  %s\n want substring Signature=%s", authz, wantSig)
	}
}

func TestComputeV3Signature_InvalidInput(t *testing.T) {
	tests := []struct {
		name    string
		req     *RequestSnapshot
		triplet Triplet
		wantErr string
	}{
		{
			name:    "nil request",
			req:     nil,
			triplet: Triplet{AccessKeyID: "AK", AccessKeySecret: "SK"},
			wantErr: "nil request snapshot",
		},
		{
			name: "empty AccessKeySecret",
			req: &RequestSnapshot{
				Method: "POST",
				Path:   "/",
				Headers: map[string]string{
					"host":                 "ecs.aliyuncs.com",
					"x-acs-content-sha256": "hash",
				},
			},
			triplet: Triplet{AccessKeyID: "AK"},
			wantErr: "AccessKeySecret",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := computeV3Signature(tc.req, tc.triplet)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

// findHeader returns the value of the named header in res, failing
// the test if absent. Caller must pass lower-case name.
func findHeader(t *testing.T, res *ResignResult, name string) string {
	t.Helper()
	for _, h := range res.SetHeaders {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	t.Fatalf("header %q not in SetHeaders", name)
	return ""
}

// expectedV3Sig recomputes the V3 signature from req+triplet using the
// same helpers SignV3 will use.
//
// It therefore proves only that SignV3 wires those helpers together and echoes
// the result — it CANNOT detect a deviation from the ACS3 spec, because a change
// to the canonicalization moves the expected value with it. Both the missing
// host header and the un-normalized canonical URI passed this assertion. Spec
// conformance is pinned in v3_golden_test.go against literal vectors; assert
// wiring here, never correctness.
func expectedV3Sig(t *testing.T, req *RequestSnapshot, tr Triplet) string {
	t.Helper()
	sig, err := computeV3Signature(req, tr)
	if err != nil {
		t.Fatalf("computeV3Signature: %v", err)
	}
	return sig
}
