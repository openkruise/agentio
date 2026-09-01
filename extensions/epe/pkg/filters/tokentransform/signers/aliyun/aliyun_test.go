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
	"context"
	"net/url"
	"strings"
	"testing"

	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/filters/tokentransform"
)

func stsCred() tokentransform.Credential {
	return tokentransform.Credential{AccessKeyID: "newAK", AccessKeySecret: "newSK", SecurityToken: "newTok"}
}

func TestSignerKindAndRegistration(t *testing.T) {
	if (New()).Kind() != tokentransform.CredentialKindSTS {
		t.Fatal("aliyun signer must declare CredentialKindSTS")
	}
	if !tokentransform.HasSigner(tokentransform.TypeAliyunSTS) {
		t.Fatal("init() must register the AliyunSTS signer")
	}
}

func TestWantsBodyUnknownSchemeErrors(t *testing.T) {
	st := &filter.Stream{}
	st.Request.Headers = map[string]string{}
	if _, err := (New()).WantsBody(st, nil); err == nil {
		t.Fatal("undetectable scheme must error (pre-claim FailStrategy path)")
	}
}

func TestWantsBodyV1RPCPostNeedsBody(t *testing.T) {
	if needs, err := (New()).WantsBody(v1rpcPostStream(), nil); err != nil || !needs {
		t.Fatalf("WantsBody = %v, %v; want true, nil", needs, err)
	}
	if needs, err := (New()).WantsBody(v3Stream(), nil); err != nil || needs {
		t.Fatalf("WantsBody(v3) = %v, %v; want false, nil", needs, err)
	}
}

func TestSignRequiresBodyForV1RPCPost(t *testing.T) {
	_, err := (New()).Sign(context.Background(), v1rpcPostStream(), nil, nil, stsCred(), nil)
	if err == nil || !strings.Contains(err.Error(), "requires request body") {
		t.Fatalf("err = %v, want body-required error", err)
	}
}

func TestSignResignsV3Request(t *testing.T) {
	muts, err := (New()).Sign(context.Background(), v3Stream(), nil, nil, stsCred(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(muts) == 0 {
		t.Fatal("no mutations")
	}
	found := false
	for _, op := range muts[0].HeaderOps {
		// The sign package emits the canonical "Authorization" spelling;
		// the signer passes header names through verbatim.
		if strings.EqualFold(op.Name, "authorization") && op.Kind == filter.HeaderSet && strings.Contains(op.Value, "newAK") {
			found = true
		}
	}
	if !found {
		t.Fatalf("authorization not re-signed with the new AK: %+v", muts)
	}
}

func TestSignV1RPCPostRewritesPathWithSignature(t *testing.T) {
	muts, err := (New()).Sign(context.Background(), v1rpcPostStream(), []byte("Action=DescribeRegions"), nil, stsCred(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(muts) < 2 {
		t.Fatalf("muts = %+v, want header ops + path rewrite", muts)
	}
	pathMut := muts[len(muts)-1]
	if !pathMut.ClearRouteCache || len(pathMut.HeaderOps) != 1 ||
		pathMut.HeaderOps[0].Name != ":path" || !strings.Contains(pathMut.HeaderOps[0].Value, "Signature=") {
		t.Fatalf("path mutation = %+v, want :path set with Signature and ClearRouteCache", pathMut)
	}
}

// v3Stream builds a request carrying an ACS3-HMAC-SHA256 Authorization
// header, i.e. the V3 detect case.
func v3Stream() *filter.Stream {
	st := &filter.Stream{}
	st.Request.Method = "GET"
	st.Request.Host = "ecs.aliyuncs.com"
	st.Request.Path = "/"
	st.Request.Headers = map[string]string{
		"authorization":        "ACS3-HMAC-SHA256 Credential=OLDAK,SignedHeaders=host,Signature=stale",
		"host":                 "ecs.aliyuncs.com",
		"x-acs-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"x-acs-accesskey-id":   "OLDAK",
		"x-acs-security-token": "OLDSTS",
	}
	return st
}

func v1rpcPostStream() *filter.Stream {
	q := url.Values{}
	q.Set("Signature", "sig")
	q.Set("SignatureMethod", "HMAC-SHA1")
	q.Set("AccessKeyId", "ak")
	st := &filter.Stream{}
	st.Request.Method = "POST"
	st.Request.Host = "ecs.aliyuncs.com"
	st.Request.Path = "/"
	st.Request.Query = q
	// The signer reads the wire query, so RawQuery is what matters; Query is
	// kept in sync because matching uses it.
	st.Request.RawQuery = q.Encode()
	st.Request.Headers = map[string]string{
		"content-length": "42",
		"content-type":   "application/x-www-form-urlencoded",
	}
	return st
}
