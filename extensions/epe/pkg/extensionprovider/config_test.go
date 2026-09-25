// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package extensionprovider

import (
	"testing"

	"google.golang.org/protobuf/proto"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/config"
)

func TestApplyConfigLayers(t *testing.T) {
	const baseYAML = `extensionProviders:
- name: inherited
  credentialProvider:
    url: https://credentials.example
    timeout: 10s
    tls:
      optional: true
      caSecretRef: {name: roots}
defaultProviders: {credentialProvider: inherited}
`
	base, err := config.Apply(baseYAML, &configv1.EPEConfig{})
	if err != nil {
		t.Fatal(err)
	}
	original := proto.Clone(base)
	for _, tt := range []struct {
		name    string
		raw     string
		want    string
		invalid bool
	}{
		{name: "omitted", raw: "{}", want: baseYAML},
		{name: "null document", raw: "null", want: baseYAML},
		{name: "null fields", raw: "extensionProviders: null\ndefaultProviders: null", want: baseYAML},
		{
			name: "add callout",
			raw:  "extensionProviders: [{name: scanner, httpCallout: {url: https://scanner.example}}]",
			want: `extensionProviders:
- name: inherited
  credentialProvider:
    url: https://credentials.example
    timeout: 10s
    tls:
      optional: true
      caSecretRef: {name: roots}
- name: scanner
  httpCallout: {url: https://scanner.example}
defaultProviders: {credentialProvider: inherited}`,
		},
		{
			name: "same name replaces all connection fields",
			raw:  "extensionProviders: [{name: inherited, credentialProvider: {url: https://new.example}}]",
			want: `extensionProviders: [{name: inherited, credentialProvider: {url: https://new.example}}]
defaultProviders: {credentialProvider: inherited}`,
		},
		{
			name: "same name replaces provider type",
			raw:  "extensionProviders: [{name: inherited, httpCallout: {url: https://scanner.example}}]",
			want: `extensionProviders: [{name: inherited, httpCallout: {url: https://scanner.example}}]
defaultProviders: {credentialProvider: inherited}`,
		},
		{name: "clear list", raw: "extensionProviders: []", want: "defaultProviders: {credentialProvider: inherited}"},
		{name: "protobuf field name", raw: "extension_providers: []", want: "defaultProviders: {credentialProvider: inherited}"},
		{
			name: "clear default selection",
			raw:  `defaultProviders: {credentialProvider: ""}`,
			want: `extensionProviders:
- name: inherited
  credentialProvider:
    url: https://credentials.example
    timeout: 10s
    tls:
      optional: true
      caSecretRef: {name: roots}
defaultProviders: {credentialProvider: ""}`,
		},
		{
			name: "reject duplicate names before merging",
			raw: `extensionProviders:
- name: inherited
  credentialProvider: {url: https://one.example}
- name: inherited
  credentialProvider: {url: https://two.example}`,
			invalid: true,
		},
		{name: "reject unknown field", raw: "unknown: true", invalid: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ApplyConfig(tt.raw, base)
			if (err != nil) != tt.invalid {
				t.Fatalf("ApplyConfig() error = %v, want invalid=%v", err, tt.invalid)
			}
			if !proto.Equal(base, original) {
				t.Fatal("overlay mutated the lower layer")
			}
			if tt.invalid {
				return
			}
			want, err := config.Apply(tt.want, &configv1.EPEConfig{})
			if err != nil {
				t.Fatal(err)
			}
			if !proto.Equal(got, want) {
				t.Fatalf("configuration = %v, want %v", got, want)
			}
			if err := Validate(got); err != nil {
				t.Fatal(err)
			}
		})
	}
}
