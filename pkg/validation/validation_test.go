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

package validation

import (
	"encoding/json"
	"testing"

	"github.com/openkruise/agentio/pkg/model"
)

func TestSecurityProfileStaticValidation(t *testing.T) {
	for _, tc := range []struct {
		name, spec string
		valid      bool
	}{
		{"HTTP domain wildcard", `{"rules":[{"name":"r","match":[{"domains":["api*.example.com"],"schemes":["http"]}]}]}`, false},
		{"HTTP port range", `{"rules":[{"name":"r","match":[{"domains":["example.com"],"schemes":["http"],"ports":[65536]}]}]}`, false},
		{"TLS and HTTP action union", `{"rules":[{"name":"r","match":[{"domains":["example.com"]}],"actions":{"tls":{"action":"Deny"},"bypass":true}}]}`, false},
		{"header regex", `{"rules":[{"name":"r","match":[{"headers":[{"name":"x-id","type":"Regex","value":"["}]}]}]}`, false},
		{"query regex", `{"rules":[{"name":"r","match":[{"queryParams":[{"name":"id","type":"Regex","value":"["}]}]}]}`, false},
		{"nested audit template", `{"audit":[{"name":"log","webhook":{"url":"http://audit","request":{"body":{"json":{"items":[{"value":"{{"}]}}}}}]}`, false},
		{"audit body union", `{"audit":[{"name":"log","webhook":{"url":"http://audit","request":{"body":{"json":{},"text":"body"}}}}]}`, false},
		{"audit webhook required", `{"audit":[{"name":"log"}]}`, false},
		{"audit header syntax", `{"audit":[{"name":"log","webhook":{"url":"http://audit","request":{"headers":[{"name":"x-id","value":"{{"}]}}}]}`, false},
		{"audit text syntax", `{"audit":[{"name":"log","webhook":{"url":"http://audit","request":{"body":{"text":"{{"}}}}]}`, false},
		{"consumer expression semantics", `{"audit":[{"name":"log","when":"consumerFunction(consumerVariable)","webhook":{"url":"http://audit/{{ consumerFunction .ConsumerField }}"}}]}`, true},
		{"callout header union", `{"rules":[{"name":"r","actions":{"httpCallout":{"provider":{"name":"scanner"},"request":{"headers":{"enabled":true,"filter":{"allowList":["a"],"denyList":["b"]}}}}}}]}`, false},
		{"disabled header filter ignored", `{"rules":[{"name":"r","actions":{"httpCallout":{"provider":{"name":"scanner"},"request":{"headers":{"filter":{}}}}}}]}`, true},
		{"provider value union", `{"rules":[{"name":"r","actions":{"tokenTransformation":{"credentialRef":{"credentialProvider":{"name":"provider","parameters":{"scope":{"value":"a","cel":"b"}}}}}}}]}`, false},
		{"provider CEL syntax", `{"rules":[{"name":"r","actions":{"tokenTransformation":{"credentialRef":{"credentialProvider":{"name":"provider","parameters":{"scope":{"cel":"request."}}}}}}}]}`, false},
		{"provider template syntax", `{"rules":[{"name":"r","actions":{"tokenTransformation":{"credentialRef":{"credentialProvider":{"name":"provider","parameters":{"scope":{"template":"{{"}}}}}}}]}`, false},
		{"provider consumer context", `{"rules":[{"name":"r","actions":{"tokenTransformation":{"credentialRef":{"credentialProvider":{"name":"provider","parameters":{"scope":{"cel":"consumerFunction(consumerVariable)"}}}}}}}]}`, true},
		{"header selector union", `{"rules":[{"name":"r","actions":{"tokenTransformation":{"credentialRef":{"secret":{"name":"cred"}},"apiKey":{"targetHeaders":{"names":["authorization"],"cel":"headers"},"value":{"value":"token"}}}}}]}`, false},
		{"header selector CEL syntax", `{"rules":[{"name":"r","actions":{"tokenTransformation":{"credentialRef":{"secret":{"name":"cred"}},"apiKey":{"targetHeaders":{"cel":"request."},"value":{"value":"token"}}}}}]}`, false},
		{"header value required", `{"rules":[{"name":"r","actions":{"tokenTransformation":{"credentialRef":{"secret":{"name":"cred"}},"apiKey":{"targetHeaders":{"names":["authorization"]}}}}}]}`, false},
		{"header value union", `{"rules":[{"name":"r","actions":{"tokenTransformation":{"credentialRef":{"secret":{"name":"cred"}},"apiKey":{"targetHeaders":{"names":["authorization"]},"value":{}}}}}]}`, false},
		{"header consumer context", `{"rules":[{"name":"r","actions":{"tokenTransformation":{"credentialRef":{"secret":{"name":"cred"}},"apiKey":{"targetHeaders":{"cel":"consumerHeaders()"},"value":{"template":"{{ consumerToken .Token }}"},"valueTemplate":"{{"}}}}]}`, true},
		{"legacy action regex", `{"rules":[{"name":"r","actions":{"tokenTransformation":{"credentialRef":{"secret":{"name":"cred"}},"apiKey":{"when":{"header":"authorization","pattern":"["}}}}}]}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profile := model.SecurityProfile{Name: "test", Namespace: "demo"}
			if err := json.Unmarshal([]byte(tc.spec), &profile.Spec); err != nil {
				t.Fatal(err)
			}
			err := ValidateSecurityProfile(profile)
			if (err == nil) != tc.valid {
				t.Fatalf("valid = %v, error = %v", tc.valid, err)
			}
		})
	}
}
