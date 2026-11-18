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

package wiring

import (
	"strings"
	"testing"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/testing/testsupport"
)

func TestDefaultProviderConfig(t *testing.T) {
	for _, tc := range []struct {
		name     string
		endpoint string
		source   string
	}{
		{name: "without credential provider", source: "invalid"},
		{name: "HTTP credential provider", endpoint: "http://credentials.example", source: credProviderSourceNone},
		{name: "HTTPS credential provider", endpoint: "https://credentials.example", source: credProviderSourceNone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testsupport.SetForTest(t, &identityProviderURL, tc.endpoint)
			testsupport.SetForTest(t, &credProviderMTLSSource, tc.source)
			cfg, err := DefaultProviderConfig()
			if err != nil {
				t.Fatal(err)
			}

			if tc.endpoint == "" {
				if len(cfg.ExtensionProviders) != 0 || cfg.DefaultProviders != nil {
					t.Fatal("an unset endpoint must not create an unusable default provider")
				}
				return
			}
			if len(cfg.ExtensionProviders) != 1 ||
				cfg.ExtensionProviders[0].Name != configv1.EnvironmentCredentialProviderName ||
				cfg.GetDefaultProviders().GetCredentialProvider() != configv1.EnvironmentCredentialProviderName ||
				cfg.ExtensionProviders[0].GetCredentialProvider().GetUrl() != tc.endpoint {
				t.Fatalf("missing default credential provider registration: %v", cfg)
			}
		})
	}
}

func TestDefaultProviderConfigRejectsInvalidProvider(t *testing.T) {
	for _, tc := range []struct {
		name     string
		endpoint string
		source   string
		want     string
	}{
		{name: "invalid endpoint", endpoint: "not-a-url", source: credProviderSourceNone, want: "requires an absolute HTTP(S) URL"},
		{name: "invalid TLS source", endpoint: "https://credentials.example", source: "invalid", want: "not one of secret or none"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testsupport.SetForTest(t, &identityProviderURL, tc.endpoint)
			testsupport.SetForTest(t, &credProviderMTLSSource, tc.source)
			_, err := DefaultProviderConfig()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v, want %q", err, tc.want)
			}
		})
	}
}
