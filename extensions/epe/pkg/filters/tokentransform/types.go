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

// Package tokentransform is a filter with two pluggable layers:
// CredentialSource decides where credentials come from (Kubernetes Secret,
// credential-provider service, ...), Signer decides how they are applied
// (direct header injection, Aliyun request re-signing, ...).
//
// TokenTransformation.Type is a signer-registry key, not a discriminator
// inside a claiming function: project claims every TokenTransformation
// rule, and a type with no registered signer fails closed at projection
// time. Silent fail-open is structurally impossible.
package tokentransform

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"text/template"

	"github.com/google/cel-go/cel"
	"k8s.io/client-go/kubernetes"

	"istio.io/istio/extensions/epe/pkg/credential"
	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/inputs"
)

// FilterName is the chain attribution used by metrics and accesslog.
const FilterName = "tokentransform"

// Signer-registry keys. These are plain strings on purpose: the filter
// package never sees the CRD enum; fromcrd maps it onto these keys.
const (
	TypeAPIKey    = "ApiKey"
	TypeAliyunSTS = "AliyunSTS"
)

// CredentialKind tells a CredentialSource which credential form the
// signer needs.
type CredentialKind string

const (
	// CredentialKindToken is a single secret string (ApiKey injection).
	CredentialKindToken CredentialKind = "token"
	// CredentialKindSTS is an access-key/secret/security-token triplet (signing).
	CredentialKindSTS CredentialKind = "sts"
)

// SourceKind selects which CredentialSource serves a SourceSpec. It is a
// distinct type from CredentialKind so the two vocabularies cannot be
// assigned to each other by accident.
type SourceKind string

const (
	SourceKindSecret   SourceKind = "secret"
	SourceKindProvider SourceKind = "provider"
)

// ErrNoPermission is returned by a CredentialSource when the read is
// denied for lack of RBAC permission. The filter treats it as "warn
// (rate-limited) and pass through" regardless of FailStrategy.
var ErrNoPermission = errors.New("tokentransform: no permission to read credential")

// Ref is one fully-resolved credential fetch. The filter fills every
// field (including the effective namespace and rendered provider
// parameters); sources do no policy interpretation.
//
// The source kind is deliberately absent: the filter dispatches on
// SourceSpec.Kind to pick the CredentialSource, so by the time a Ref
// reaches Fetch the receiver already encodes where the credential lives.
type Ref struct {
	// Kind is the credential form the signer asked for; a source reads it
	// to decide which fields of Credential to populate.
	Kind            CredentialKind
	Name            string
	Namespace       string         // effective, fallback already applied
	AccessToken     string         // provider only: sandbox identity
	SandboxClientID string         // provider only
	ExtraMetadata   map[string]any // provider only, rendered
}

// Credential is what a source returns; signers read the fields their
// kind populates.
type Credential struct {
	Token                                       string // CredentialKindToken
	AccessKeyID, AccessKeySecret, SecurityToken string // CredentialKindSTS
}

// sanitized trims surrounding whitespace from every field and rejects values
// that still carry a byte unusable in a header value.
//
// Credentials become HTTP header values, and Envoy validates the values of the
// header mutations an external processor returns: a CR or LF makes it reject
// the whole mutation set and answer with its status_on_error local reply — 500
// by default — for every request the rule matches. A trailing newline is not
// exotic; it is what `kubectl create secret --from-file` yields from any
// ordinary text file, so it is trimmed rather than treated as fatal. An
// interior control byte cannot be trimmed away and would be a header
// injection, so it becomes an error the rule's failStrategy resolves.
func (c Credential) sanitized() (Credential, error) {
	for _, f := range []struct {
		name string
		val  *string
	}{
		{"token", &c.Token},
		{"accessKeyId", &c.AccessKeyID},
		{"accessKeySecret", &c.AccessKeySecret},
		{"securityToken", &c.SecurityToken},
	} {
		*f.val = strings.TrimSpace(*f.val)
		if i := strings.IndexFunc(*f.val, unusableInHeaderValue); i >= 0 {
			return Credential{}, fmt.Errorf(
				"credential %s contains byte %q at offset %d, which cannot be sent as a header value",
				f.name, (*f.val)[i], i)
		}
	}
	return c, nil
}

// unusableInHeaderValue reports whether r cannot appear in an HTTP header
// value. Envoy accepts HTAB, space, and 0x21-0x7E plus obs-text; C0 controls
// (CR, LF, NUL, ...) and DEL are rejected. Interior HTAB and space are legal,
// hence the explicit allowance.
func unusableInHeaderValue(r rune) bool {
	if r == '\t' || r == ' ' {
		return false
	}
	return r < 0x20 || r == 0x7F
}

// CredentialSource fetches one credential. Implementations: SecretSource
// (Kubernetes Secrets) and ProviderSource (external credential service).
type CredentialSource interface {
	Fetch(ctx context.Context, ref Ref) (Credential, error)
}

// Signer applies one credential to the request. body is nil in the
// headers phase; signers that consume the body also implement BodyWanter.
// scope is the claiming unit's evaluation scope (templates, CEL); cfg is
// the signer-specific value stored in Config.SignerCfg.
type Signer interface {
	Kind() CredentialKind
	Sign(ctx context.Context, st *filter.Stream, body []byte, scope *inputs.Scope, cred Credential, cfg any) ([]filter.Mutation, error)
}

// SignerPreparer resolves request-dependent signer configuration before any
// credential access. empty is a successful no-op; errors use FailStrategy.
type SignerPreparer interface {
	Prepare(st *filter.Stream, scope *inputs.Scope, cfg any) (prepared any, empty bool, err error)
}

// BodyWanter is the optional pre-claim probe of signers whose signature may
// consume the request body. cfg is the request-prepared signer config when the
// signer implements SignerPreparer, otherwise Config.SignerCfg. An error means
// the request is ineligible and resolves through FailStrategy.
type BodyWanter interface {
	WantsBody(st *filter.Stream, cfg any) (bool, error)
}

// When gates signing on the existing value of one request header.
type When struct {
	Header string
	Re     *regexp.Regexp
}

// Met reports whether the condition holds. Header lookup is lower-cased:
// Envoy normalizes header names. A nil When always holds.
func (w *When) Met(headers map[string]string) bool {
	if w == nil {
		return true
	}
	v := headers[strings.ToLower(w.Header)]
	return v != "" && w.Re.MatchString(v)
}

// ParamSource is one credentialProvider parameter, compiled at projection
// time and rendered per request against the unit scope.
type ParamSource struct {
	Value    *string
	Template *template.Template
	Cel      cel.Program
}

// SourceSpec is the projected credentialRef: where the credential lives.
// Namespace is the raw CRD value; the filter applies the ref -> profile
// -> pod fallback per request.
type SourceSpec struct {
	Kind       SourceKind
	Name       string
	Namespace  string
	Parameters map[string]ParamSource // provider only
}

// Config is the filter's own, CRD-free per-unit config.
type Config struct {
	// Type is the signer-registry key; projection guarantees a signer
	// exists for it.
	Type string
	// FailBlock mirrors the rule's FailStrategy (Block = true).
	FailBlock bool
	// Source is where the credential comes from.
	Source SourceSpec
	// SignerCfg is opaque per-signer config.
	SignerCfg any
}

// TokenProvider and STSProvider are the consumer-side views of the
// credential client; *credential.Client satisfies both unchanged.
type TokenProvider interface {
	GetTokenWithExtraMetadata(ctx context.Context, accessToken, sandboxClientID, providerName string, extraMetadata map[string]any) (string, error)
}

// STSProvider returns the credential client's STS credential type directly;
// pkg/credential is agents-api-free, so this does not breach layering.
type STSProvider interface {
	GetSTSCredentialWithExtraMetadata(ctx context.Context, accessToken, sandboxClientID, providerName string, extraMetadata map[string]any) (credential.STSCredential, error)
}

// Deps bundles the filter's external dependencies. Tokens/STS may be nil
// (no credential client configured); the provider source then
// errors, resolved through FailStrategy.
type Deps struct {
	Kube    kubernetes.Interface
	Tokens  TokenProvider
	STS     STSProvider
	Limiter *Limiter
}
