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

package oauth2

import (
	"encoding/json"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/credential"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

func TestPayloadRejectsUnsafeConfiguration(t *testing.T) {
	for _, payload := range []string{
		`{`,
		`null`,
		`{"operation":"Resource"}`,
		`{"credentialProviderName":"provider"}`,
		`{"credentialProviderName":"provider","operation":"Authorization"}`,
		`{"credentialProviderName":"provider","operation":"Resource","allowedGrantTypes":["refresh_token"]}`,
		`{"credentialProviderName":"provider","operation":"Token","allowAuthorizedSession":true}`,
		`{"credentialProviderName":"provider","operation":"Resource","customResponse":{"success":{"code":0}}}`,
		`{"credentialProviderName":"provider","operation":"Token","customResponse":{"error":[]}}`,
		`{"credentialProviderName":"provider","operation":"Token","customResponse":{"error":null}}`,
		`{"credentialProviderName":"provider","operation":"Token","customResponse":{"success":{"access_token":"private"}}}`,
		`{"credentialProviderName":"provider","operation":"Token","customResponse":{"authorizationRequired":{"error":"private"}}}`,
		`{"credentialProviderName":"provider","operation":"Token","allowedGrantTypes":["refresh_token","refresh_token"]}`,
		`{"credentialProviderName":"provider","operation":"Token","allowedGrantTypes":[""]}`,
		`{"credentialProviderName":"provider","operation":"Token","allowedGrantTypes":["password"]}`,
	} {
		t.Run(payload, func(t *testing.T) {
			if _, err := parse(json.RawMessage(payload)); err == nil {
				t.Fatalf("unsafe payload accepted: %s", payload)
			}
		})
	}
}

func TestDefinitionUsesNeutralPayloadAndFailsClosed(t *testing.T) {
	regs, err := filter.Build(Definition(&fakeSource{}))
	if err != nil {
		t.Fatal(err)
	}
	reg := regs[0]
	for _, operation := range []string{
		credential.OAuth2OperationDeviceAuthorization,
		credential.OAuth2OperationToken,
		credential.OAuth2OperationResource,
	} {
		raw, err := json.Marshal(Config{CredentialProviderName: "provider", Operation: operation})
		if err != nil {
			t.Fatal(err)
		}
		value, err := reg.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		cfg := value.(Config)
		if cfg.Operation != operation || cfg.AllowAuthorizedSession != nil || len(cfg.AllowedGrantTypes) != 0 ||
			reg.OnError(cfg) != filter.FailClosed || reg.Phases != filter.PhaseRequestHeaders|filter.PhaseRequestBody {
			t.Fatalf("incorrect definition or defaults: config=%+v, registration=%+v", cfg, reg)
		}
	}
}
