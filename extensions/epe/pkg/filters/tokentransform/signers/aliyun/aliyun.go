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

// Package aliyun re-signs intercepted Aliyun-SDK egress requests with
// credentials the sandbox is entitled to. It plugs into the tokentransform
// filter through the signer registry (registered by init) and is paired
// with the credential-provider client wired in pkg/wiring.
package aliyun

import (
	"context"
	"fmt"

	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/filters/tokentransform"
	"istio.io/istio/extensions/epe/pkg/filters/tokentransform/signers/aliyun/sign"
	"istio.io/istio/extensions/epe/pkg/inputs"
)

func init() { tokentransform.RegisterSigner(tokentransform.TypeAliyunSTS, New()) }

// Signer detects the Aliyun signature scheme on the intercepted request
// and recomputes it with the fetched triplet.
type Signer struct {
	resigner *sign.Signer
}

// New returns the Aliyun re-signing signer.
func New() *Signer { return &Signer{resigner: sign.New()} }

// Kind declares that this signer needs the AK/SK/security-token triplet.
func (s *Signer) Kind() tokentransform.CredentialKind { return tokentransform.CredentialKindSTS }

// WantsBody is the pre-claim probe: an undetectable scheme makes the
// request ineligible (resolved through FailStrategy by the filter); a
// body-consuming scheme (V1-RPC POST) defers signing to the body phase.
func (s *Signer) WantsBody(st *filter.Stream, _ any) (bool, error) {
	snap := snapshotFromStream(st)
	version := sign.Detect(snap)
	if version == sign.SignatureUnknown {
		return false, fmt.Errorf("aliyunsts: cannot detect Aliyun signature version on this request")
	}
	return sign.NeedsBody(version, snap.Method, snap.Headers), nil
}

// Sign re-detects the scheme (the body may have arrived since the
// headers phase) and re-signs the request.
func (s *Signer) Sign(_ context.Context, st *filter.Stream, body []byte, _ *inputs.Scope, cred tokentransform.Credential, _ any) ([]filter.Mutation, error) {
	snap := snapshotFromStream(st)
	version := sign.Detect(snap)
	if version == sign.SignatureUnknown {
		return nil, fmt.Errorf("aliyunsts: cannot detect Aliyun signature version on this request")
	}
	if sign.NeedsBody(version, snap.Method, snap.Headers) {
		if len(body) == 0 {
			return nil, fmt.Errorf("aliyunsts: V1-RPC POST requires request body, but body was not delivered")
		}
		snap.Body = body
	}
	res, err := s.resigner.Resign(version, snap, sign.Triplet{
		AccessKeyID:     cred.AccessKeyID,
		AccessKeySecret: cred.AccessKeySecret,
		SecurityToken:   cred.SecurityToken,
	})
	if err != nil {
		return nil, fmt.Errorf("aliyunsts: resign: %w", err)
	}
	return buildMutations(res), nil
}

func snapshotFromStream(st *filter.Stream) *sign.RequestSnapshot {
	return &sign.RequestSnapshot{
		Method: st.Request.Method,
		Host:   st.Request.Host,
		Path:   st.Request.Path,
		// The wire query, verbatim. Re-encoding st.Request.Query here would
		// drop whatever url.ParseQuery rejected (';' separators, invalid
		// escapes) and normalize percent-encoding, so the signature would
		// cover a different query than the one Envoy forwards — and OSS V4
		// signs the query it received byte for byte.
		RawQuery: st.Request.RawQuery,
		Headers:  st.Request.Headers, // already lower-cased per attributes.parseHTTPRequest
	}
}

// buildMutations converts a resign result into plain mutations. A :path
// rewrite goes through SetPath so ClearRouteCache is forced.
func buildMutations(res *sign.ResignResult) []filter.Mutation {
	var m filter.Mutation
	for _, h := range res.SetHeaders {
		m.HeaderOps = append(m.HeaderOps, filter.HeaderOp{Kind: filter.HeaderSet, Name: h.Name, Value: h.Value})
	}
	for _, name := range res.RemoveHeaders {
		m.HeaderOps = append(m.HeaderOps, filter.HeaderOp{Kind: filter.HeaderRemove, Name: name})
	}
	muts := []filter.Mutation{m}
	if res.NewPath != nil {
		muts = append(muts, filter.SetPath(*res.NewPath))
	}
	return muts
}
