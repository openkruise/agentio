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
package tokentransform

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"k8s.io/utils/ptr"
)

// parseSpec exercises the JSON boundary using the filter-owned wire type.
// Compatibility with concrete policy APIs is tested in testing/securityprofile.
func parseSpec(t *testing.T, tt *spec) (Config, error) {
	t.Helper()
	raw, err := json.Marshal(tt)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return parse(raw)
}

func apiKeyTT() *spec {
	template := "Bearer {{ .Token }}"
	return &spec{
		CredentialRef: credentialRefSpec{
			Secret: &secretRefSpec{Name: "s", Namespace: "ns"},
		},
		ApiKey: &apiKeySpec{
			TargetHeaders: &headerSelectorSpec{Names: []string{"authorization"}},
			Value:         &valueSourceSpec{Template: &template},
		},
	}
}

func TestParseClaimsApiKeyAction(t *testing.T) {
	cfg, err := parseSpec(t, apiKeyTT())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Type != TypeAPIKey {
		t.Errorf("Type = %q, want %q", cfg.Type, TypeAPIKey)
	}
	want := SourceSpec{Kind: SourceKindSecret, Name: "s", Namespace: "ns"}
	if cfg.Source.Kind != want.Kind || cfg.Source.Name != want.Name || cfg.Source.Namespace != want.Namespace {
		t.Errorf("Source = %+v, want %+v", cfg.Source, want)
	}
	ac, ok := cfg.SignerCfg.(ApiKeyConfig)
	if !ok || len(ac.Headers) != 1 {
		t.Errorf("SignerCfg = %+v, want a compiled ApiKeyConfig", cfg.SignerCfg)
	}
}

func TestParseExplicitAPIKeyTargets(t *testing.T) {
	const secret = `"credentialRef":{"secret":{"name":"backend"}}`
	t.Run("header target normalizes through current header config", func(t *testing.T) {
		cfg, err := parse(json.RawMessage(`{` + secret + `,"apiKey":{
			"target":{"header":{"name":"X-API-Key"}},
			"value":{"template":"Bearer {{ .Token }}"}
		}}`))
		if err != nil {
			t.Fatal(err)
		}
		apiKey := cfg.SignerCfg.(ApiKeyConfig)
		if apiKey.Body != nil || len(apiKey.Headers) != 1 ||
			!reflect.DeepEqual(apiKey.Headers[0].Names, []string{"x-api-key"}) {
			t.Fatalf("SignerCfg = %#v, want normalized x-api-key header target", apiKey)
		}
	})

	t.Run("body target compiles CEL and legacy value template", func(t *testing.T) {
		cfg, err := parse(json.RawMessage(`{` + secret + `,"apiKey":{
			"target":{"body":{"cel":"json(request.body).merge({'api_key': value})"}},
			"valueTemplate":"{{ .Token }}"
		}}`))
		if err != nil {
			t.Fatal(err)
		}
		apiKey := cfg.SignerCfg.(ApiKeyConfig)
		if len(apiKey.Headers) != 0 || apiKey.Body == nil ||
			apiKey.Body.Program == nil || apiKey.Body.Value.Template == nil {
			t.Fatalf("SignerCfg = %#v, want compiled body target", apiKey)
		}
	})

	for _, tc := range []struct {
		name   string
		apiKey string
		want   string
	}{
		{
			name: "invalid body CEL",
			apiKey: `{"target":{"body":{"cel":"json(request.body).merge("}},
				"value":{"value":"x"}}`,
			want: "compile apiKey.target.body.cel",
		},
		{
			name:   "empty target union",
			apiKey: `{"target":{},"value":{"value":"x"}}`,
			want:   "exactly one of header or body",
		},
		{
			name: "both target branches",
			apiKey: `{"target":{"header":{"name":"x-api-key"},"body":{"cel":"request.body"}},
				"value":{"value":"x"}}`,
			want: "exactly one of header or body",
		},
		{
			name: "target conflicts with targetHeaders",
			apiKey: `{"target":{"body":{"cel":"request.body"}},
				"targetHeaders":{"names":["x-api-key"]},"value":{"value":"x"}}`,
			want: "must not be combined",
		},
		{
			name: "invalid explicit header name",
			apiKey: `{"target":{"header":{"name":"host"}},
				"value":{"value":"x"}}`,
			want: "cannot modify Host",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parse(json.RawMessage(`{` + secret + `,"apiKey":` + tc.apiKey + `}`))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("parse() error = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestParseCanonicalHeaderRules(t *testing.T) {
	restore := swapSigners()
	defer restore()
	RegisterSigner(TypeAPIKey, apiKeySigner{})
	RegisterSigner(TypeAliyunSTS, stubSigner{shape: CredentialKindSTS})

	secret := `"credentialRef":{"secret":{"name":"backend"}}`
	t.Run("targetHeaders and value override legacy apiKey fields", func(t *testing.T) {
		cfg, err := parse(json.RawMessage(`{` + secret + `,"apiKey":{
			"when":{"header":"x-legacy","pattern":"("},
			"targetHeader":"x-legacy",
			"valueTemplate":"{{",
			"targetHeaders":{"names":["Authorization","X-Backend-Authorization"]},
			"value":{"template":"Bearer {{ .Token }}"}
		}}`))
		if err != nil {
			t.Fatal(err)
		}
		ac, ok := cfg.SignerCfg.(ApiKeyConfig)
		if !ok || len(ac.Headers) != 1 {
			t.Fatalf("SignerCfg = %#v, want one compiled header rule", cfg.SignerCfg)
		}
		if got, want := ac.Headers[0].Names, []string{"authorization", "x-backend-authorization"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("Names = %q, want %q", got, want)
		}
		if ac.Headers[0].Value.Template == nil {
			t.Fatal("Value.Template is nil")
		}
		if ac.Headers[0].Condition != nil {
			t.Fatalf("Condition = %#v, want targetHeaders to ignore legacy when", ac.Headers[0].Condition)
		}
	})

	t.Run("static names and template with omitted type", func(t *testing.T) {
		cfg, err := parse(json.RawMessage(`{` + secret + `,
			"apiKey":{"targetHeaders":{"names":["Authorization","X-Backend-Authorization"]},
			"value":{"template":"Bearer {{ .Token }}"}}}`))
		if err != nil {
			t.Fatal(err)
		}
		ac, ok := cfg.SignerCfg.(ApiKeyConfig)
		if !ok || len(ac.Headers) != 1 {
			t.Fatalf("SignerCfg = %#v, want one compiled header rule", cfg.SignerCfg)
		}
		names := ac.Headers[0].Names
		if !reflect.DeepEqual(names, []string{"authorization", "x-backend-authorization"}) {
			t.Fatalf("Names = %q, want canonical static names", names)
		}
		if ac.Headers[0].Selector != nil {
			t.Fatal("Selector is non-nil for a static names rule")
		}
		if ac.Headers[0].Value.Template == nil {
			t.Fatal("Value.Template is nil")
		}
	})

	t.Run("dynamic selector and CEL value", func(t *testing.T) {
		cfg, err := parse(json.RawMessage(`{` + secret + `,
			"apiKey":{"targetHeaders":{"cel":"request.headers.filter(name, name.startsWith('x-'))"},
			"value":{"cel":"token + ':' + header.name + ':' + header.value"}}}`))
		if err != nil {
			t.Fatal(err)
		}
		ac := cfg.SignerCfg.(ApiKeyConfig)
		if len(ac.Headers) != 1 || ac.Headers[0].Selector == nil {
			t.Fatalf("SignerCfg = %#v, want a compiled selector", cfg.SignerCfg)
		}
		if ac.Headers[0].Value.CEL == nil {
			t.Fatal("Value.CEL is nil")
		}
	})

	for _, tc := range []struct {
		name string
		raw  string
		want string
	}{
		{"both selector branches", `{"targetHeaders":{"names":["authorization"],"cel":"['x-api-key']"},"value":{"value":"x"}}`, "exactly one of names or cel"},
		{"neither selector branch", `{"targetHeaders":{},"value":{"value":"x"}}`, "exactly one of names or cel"},
		{"zero value branches", `{"targetHeaders":{"names":["authorization"]},"value":{}}`, "exactly one of value, template or cel"},
		{"two value branches", `{"targetHeaders":{"names":["authorization"]},"value":{"value":"x","template":"{{ .Token }}"}}`, "exactly one of value, template or cel"},
		{"known non-list selector", `{"targetHeaders":{"cel":"'authorization'"},"value":{"value":"x"}}`, "must return list(string)"},
		{"known non-string CEL value", `{"targetHeaders":{"names":["authorization"]},"value":{"cel":"1"}}`, "must return string"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parse(json.RawMessage(`{` + secret + `,"apiKey":` + tc.raw + `}`))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("parse() error = %v, want it to contain %q", err, tc.want)
			}
		})
	}

	t.Run("superseded root headers are rejected", func(t *testing.T) {
		_, err := parse(json.RawMessage(`{` + secret + `,
			"headers":[{"names":["authorization"],"value":{"value":"x"}}],
			"apiKey":{"valueTemplate":"{{ .Token }}"}}`))
		if err == nil || !strings.Contains(err.Error(), "root headers is not supported") {
			t.Fatalf("parse() error = %v, want superseded root spelling rejected", err)
		}
	})

	t.Run("unreleased nested apiKey headers spelling is rejected", func(t *testing.T) {
		_, err := parse(json.RawMessage(`{` + secret + `,"apiKey":{"headers":[
			{"name":"Authorization","valueTemplate":"Bearer {{ .Token }}"}]}}`))
		if err == nil || !strings.Contains(err.Error(), "apiKey.headers is not supported") {
			t.Fatalf("parse() error = %v, want nested-spelling rejection", err)
		}
	})

	t.Run("AliyunSTS ignores apiKey targetHeaders", func(t *testing.T) {
		cfg, err := parse(json.RawMessage(`{` + secret + `,"type":"AliyunSTS","apiKey":{
			"targetHeaders":{"names":["authorization"]},"value":{"value":"x"}}}`))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Type != TypeAliyunSTS || cfg.SignerCfg != nil {
			t.Fatalf("cfg = %#v, want transport-only AliyunSTS", cfg)
		}
	})

	t.Run("more than sixty-four static targets", func(t *testing.T) {
		names := make([]string, 65)
		for i := range names {
			names[i] = fmt.Sprintf("x-token-%d", i)
		}
		raw, err := json.Marshal(map[string]any{
			"credentialRef": map[string]any{"secret": map[string]string{"name": "backend"}},
			"apiKey": map[string]any{
				"targetHeaders": map[string]any{"names": names},
				"value":         map[string]any{"value": "x"},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = parse(raw)
		if err == nil || !strings.Contains(err.Error(), "more than 64 static targets") {
			t.Fatalf("parse() error = %v, want static target bound rejection", err)
		}
	})

	t.Run("released legacy fields normalize", func(t *testing.T) {
		cfg, err := parse(json.RawMessage(`{` + secret + `,"apiKey":{
			"targetHeader":"X-API-Key","valueTemplate":"Bearer {{ .Token }}",
			"when":{"header":"X-Guard","pattern":"^v.*"}}}`))
		if err != nil {
			t.Fatal(err)
		}
		ac := cfg.SignerCfg.(ApiKeyConfig)
		if len(ac.Headers) != 1 || !reflect.DeepEqual(ac.Headers[0].Names, []string{"x-api-key"}) {
			t.Fatalf("SignerCfg = %#v, want one normalized legacy rule", cfg.SignerCfg)
		}
		condition := ac.Headers[0].Condition
		if condition == nil || condition.Header != "X-Guard" || !condition.Re.MatchString("v1") {
			t.Fatalf("Condition = %#v, want normalized legacy condition", condition)
		}
	})

	t.Run("AliyunSTS payload stays transport-only", func(t *testing.T) {
		cfg, err := parse(json.RawMessage(`{` + secret + `,"type":"AliyunSTS"}`))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Type != TypeAliyunSTS || cfg.SignerCfg != nil {
			t.Fatalf("cfg = %#v, want unchanged AliyunSTS signer payload", cfg)
		}
	})
}

func TestParseRejectsUnboundedTokenHeaderCEL(t *testing.T) {
	const secret = `"credentialRef":{"secret":{"name":"backend"}}`
	for _, tc := range []struct {
		name   string
		apiKey string
	}{
		{
			name: "selector",
			apiKey: `{"targetHeaders":{"cel":"lists.range(int(request.port)).map(i, 'x-' + string(i))"},
				"value":{"value":"x"}}`,
		},
		{
			name: "value",
			apiKey: `{"targetHeaders":{"names":["authorization"]},
				"value":{"cel":"string(lists.range(int(request.port)).size())"}}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parse(json.RawMessage(`{` + secret + `,"apiKey":` + tc.apiKey + `}`))
			if err == nil || !strings.Contains(err.Error(), "lists.range") {
				t.Fatalf("parse() error = %v, want lists.range compile rejection", err)
			}
		})
	}
}

func TestParseRejectsDuplicateStaticHeaderTargets(t *testing.T) {
	_, err := parseSpec(t, &spec{
		CredentialRef: credentialRefSpec{Secret: &secretRefSpec{Name: "backend"}},
		ApiKey: &apiKeySpec{
			TargetHeaders: &headerSelectorSpec{Names: []string{"X-API-Key", "x-api-key"}},
			Value:         &valueSourceSpec{Value: ptr.To("value")},
		},
	})
	if err == nil || !strings.Contains(err.Error(), `duplicates static header "x-api-key"`) {
		t.Fatalf("parse() error = %v, want canonical static-duplicate rejection", err)
	}
}

// An absent legacy targetHeader must normalize to Authorization rather than
// compile an output with an empty name. This filter-side fallback preserves
// the released behavior after the API stops materializing a CRD default.
func TestParseDefaultsLegacyTargetHeader(t *testing.T) {
	cfg, err := parse(json.RawMessage(`{
		"credentialRef":{"secret":{"name":"s","namespace":"ns"}},
		"apiKey":{"valueTemplate":"Bearer {{ .Token }}"}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	ac, ok := cfg.SignerCfg.(ApiKeyConfig)
	if !ok || len(ac.Headers) != 1 {
		t.Fatalf("SignerCfg = %+v, want one normalized header", cfg.SignerCfg)
	}
	names := ac.Headers[0].Names
	if !reflect.DeepEqual(names, []string{DefaultTargetHeader}) {
		t.Errorf("header names = %q, want %q", names, DefaultTargetHeader)
	}
}

// An empty type is the un-defaulted case; the CRD defaults it to ApiKey and
// so does the filter, so a config that never went through API-server
// defaulting still resolves to a real signer instead of failing.
func TestParseDefaultsEmptyTypeToApiKey(t *testing.T) {
	tt := apiKeyTT()
	tt.Type = ""
	cfg, err := parseSpec(t, tt)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Type != TypeAPIKey {
		t.Errorf("Type = %q, want %q", cfg.Type, TypeAPIKey)
	}
}

func TestParseUnregisteredTypeFailsClosed(t *testing.T) {
	tt := apiKeyTT()
	tt.Type = "NoSuchType"
	_, err := parseSpec(t, tt)
	if err == nil || !strings.Contains(err.Error(), "no signer") {
		t.Fatalf("err = %v, want unregistered-signer error", err)
	}
}

func TestParseAliyunSTSClaimsWhenRegistered(t *testing.T) {
	if !HasSigner(TypeAliyunSTS) {
		t.Skip("AliyunSTS signer not registered in this build")
	}
	tt := apiKeyTT()
	tt.Type = TypeAliyunSTS
	tt.ApiKey = nil
	cfg, err := parseSpec(t, tt)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Type != TypeAliyunSTS || cfg.SignerCfg != nil {
		t.Fatalf("cfg = %+v, want AliyunSTS with no signer cfg", cfg)
	}
}

func TestParseAliyunSTSRejectsOnlyNestedAPIKeyHeaders(t *testing.T) {
	restore := swapSigners()
	defer restore()
	RegisterSigner(TypeAPIKey, apiKeySigner{})
	RegisterSigner(TypeAliyunSTS, stubSigner{shape: CredentialKindSTS})

	const prefix = `{"type":"AliyunSTS","credentialRef":{"secret":{"name":"sts"}},"apiKey":`
	t.Run("unreleased nested spelling is rejected", func(t *testing.T) {
		_, err := parse(json.RawMessage(prefix + `{"headers":[{"name":"authorization"}]}}`))
		if err == nil || !strings.Contains(err.Error(), "apiKey.headers is not supported") {
			t.Fatalf("parse() error = %v, want nested-spelling rejection", err)
		}
	})

	t.Run("released legacy fields remain ignored", func(t *testing.T) {
		cfg, err := parse(json.RawMessage(prefix + `{
			"targetHeader":"X-API-Key",
			"valueTemplate":"Bearer {{ .Token }}",
			"when":{"header":"X-Guard","pattern":"^go$"}
		}}`))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Type != TypeAliyunSTS || cfg.SignerCfg != nil {
			t.Fatalf("cfg = %#v, want transport-only AliyunSTS with released apiKey fields ignored", cfg)
		}
	})
}

// Types the build cannot serve fail at parse time even when the signer
// registry is empty.
func TestParseFailsClosedWithEmptySignerRegistry(t *testing.T) {
	restore := swapSigners()
	defer restore()
	_, err := parseSpec(t, apiKeyTT())
	if err == nil || !strings.Contains(err.Error(), "no signer") {
		t.Fatalf("err = %v, want unregistered-signer error", err)
	}
}

func TestParseFailStrategy(t *testing.T) {
	for _, tc := range []struct {
		strategy string
		want     bool
	}{
		{"Block", true},
		{"Allow", false},
		{"Ignore", false},
		// Only the two explicit open values open. An empty value means the
		// payload never went through API-server defaulting, and the CRD
		// defaults this field to Block — so blocking is what the operator
		// asked for. An unrecognized value is likewise resolved fail-closed,
		// matching block's status-0 and mcpacl's empty-defaultAction handling.
		{"", true},
		{"SomethingNobodyRegistered", true},
	} {
		t.Run(string(tc.strategy), func(t *testing.T) {
			tt := apiKeyTT()
			tt.FailStrategy = tc.strategy
			cfg, err := parseSpec(t, tt)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.FailBlock != tc.want {
				t.Errorf("FailBlock = %v, want %v", cfg.FailBlock, tc.want)
			}
		})
	}
}

func TestParseWhenCompiled(t *testing.T) {
	cfg, err := parse(json.RawMessage(`{
		"credentialRef":{"secret":{"name":"s","namespace":"ns"}},
		"apiKey":{
			"when":{"header":"X-Guard","pattern":"^v.*"},
			"valueTemplate":"Bearer {{ .Token }}"
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	condition := cfg.SignerCfg.(ApiKeyConfig).Headers[0].Condition
	if condition == nil || condition.Header != "X-Guard" || !condition.Re.MatchString("v1") {
		t.Fatalf("Condition = %+v, want a compiled ^v.* on X-Guard", condition)
	}
}

func TestParseLegacyWhenNormalizesIntoHeaderSelector(t *testing.T) {
	cfg, err := parse(json.RawMessage(`{
		"credentialRef":{"secret":{"name":"s","namespace":"ns"}},
		"apiKey":{
			"when":{"header":"X-Guard","pattern":"^enabled$"},
			"targetHeader":"X-API-Key",
			"valueTemplate":"Bearer {{ .Token }}"
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}

	st, scope := testRequest(map[string]string{"x-guard": "disabled"})
	prepared, empty, err := prepareAPIKey(t, st, scope, cfg.SignerCfg.(ApiKeyConfig))
	if err != nil {
		t.Fatal(err)
	}
	if !empty || len(prepared.Headers) != 0 {
		t.Fatalf("Prepare() = (%#v, %v), want legacy when to select no headers", prepared, empty)
	}
}

func TestParseProviderParametersCompiled(t *testing.T) {
	tt := apiKeyTT()
	tt.CredentialRef = credentialRefSpec{
		CredentialProvider: &providerRefSpec{
			Name: "prov",
			Parameters: map[string]valueSourceSpec{
				"static":   {Value: ptr.To("x")},
				"template": {Template: ptr.To("{{ .Pod.Name }}")},
				"cel":      {Cel: ptr.To("pod.name")},
			},
		},
	}
	cfg, err := parseSpec(t, tt)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Source.Kind != SourceKindProvider || cfg.Source.Name != "prov" {
		t.Fatalf("Source = %+v, want the provider ref", cfg.Source)
	}
	p := cfg.Source.Parameters
	if len(p) != 3 || p["static"].Value == nil || p["template"].Template == nil || p["cel"].Cel == nil {
		t.Fatalf("compiled params = %+v, want all three branches compiled", p)
	}
}

func TestParseRejectsAuditOnlyResultInProviderParameter(t *testing.T) {
	tt := apiKeyTT()
	tt.CredentialRef = credentialRefSpec{
		CredentialProvider: &providerRefSpec{
			Name: "prov",
			Parameters: map[string]valueSourceSpec{
				"audit-only": {Cel: ptr.To("result")},
			},
		},
	}
	_, err := parseSpec(t, tt)
	if err == nil || !strings.Contains(err.Error(), "undeclared reference to 'result'") {
		t.Fatalf("parseSpec() error = %v, want undeclared-reference error", err)
	}
}

// Every malformed payload must fail closed at parse time: the binder turns
// these into a denied request, so none of them can degrade into a silently
// unenforced rule.
func TestParseFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		want string
		mut  func(*spec)
	}{
		{"nil apiKey while type is ApiKey", "defines no apiKey config", func(tt *spec) {
			tt.ApiKey = nil
		}},
		{"bad value template", "compile apiKey.value.template", func(tt *spec) {
			tt.ApiKey.Value.Template = ptr.To("Bearer {{ .Token")
		}},
		{"empty value template", "apiKey.value.template is empty", func(tt *spec) {
			tt.ApiKey.Value.Template = ptr.To("")
		}},
		{"credentialRef with neither branch", "neither secret nor credentialProvider", func(tt *spec) {
			tt.CredentialRef = credentialRefSpec{}
		}},
		{"credentialRef with both branches", "must not set both", func(tt *spec) {
			tt.CredentialRef = credentialRefSpec{
				Secret:             &secretRefSpec{Name: "s"},
				CredentialProvider: &providerRefSpec{Name: "p"},
			}
		}},
		{"empty secret name", "secret.name is empty", func(tt *spec) {
			tt.CredentialRef = credentialRefSpec{Secret: &secretRefSpec{}}
		}},
		{"empty provider name", "credentialProvider.name is empty", func(tt *spec) {
			tt.CredentialRef = credentialRefSpec{CredentialProvider: &providerRefSpec{}}
		}},
		{"ambiguous provider parameter", "exactly one of value, cel or template", func(tt *spec) {
			tt.CredentialRef = credentialRefSpec{CredentialProvider: &providerRefSpec{
				Name:       "prov",
				Parameters: map[string]valueSourceSpec{"both": {Value: ptr.To("x"), Cel: ptr.To("pod.name")}},
			}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tt := apiKeyTT()
			tc.mut(tt)
			_, err := parseSpec(t, tt)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}

	for _, tc := range []struct {
		name   string
		apiKey string
		want   string
	}{
		{"empty legacy valueTemplate", `{"valueTemplate":""}`, "apiKey.value.template is empty"},
		{"bad legacy when pattern", `{
			"when":{"header":"X-Guard","pattern":"("},
			"valueTemplate":"Bearer {{ .Token }}"
		}`, "compile when pattern"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parse(json.RawMessage(`{
				"credentialRef":{"secret":{"name":"s","namespace":"ns"}},
				"apiKey":` + tc.apiKey + `
			}`))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestParseRejectsMalformedPayload(t *testing.T) {
	if _, err := parse([]byte(`{"type":123}`)); err == nil {
		t.Fatal("parse accepted a non-string type")
	}
}
