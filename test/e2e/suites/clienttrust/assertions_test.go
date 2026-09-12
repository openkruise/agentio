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

package clienttrust

import (
	"encoding/json"
	"testing"
)

func TestHTTPSAssertionsRejectTransportAndTrustFailures(t *testing.T) {
	var good probeResult
	if err := json.Unmarshal([]byte(`{
  "requests":{"status":200}, "httpx":{"status":200}, "custom_client":{"status":200},
  "tls":{"issuer":"Agentio MITM Root CA"},
  "node":{"exit":0,"stdout":"{\"status\":200,\"authorized\":true}"},
  "curl":{"exit":0,"stdout":"200"}
 }`), &good); err != nil {
		t.Fatal(err)
	}
	if err := checkHTTPS(good, "example.com", true); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*probeResult)
	}{
		{"python", func(p *probeResult) { p.Requests.Status = 0; p.Requests.Error = "connection refused" }},
		{"node", func(p *probeResult) { p.Node.Stdout = `{"status":200,"authorized":false}` }},
		{"curl", func(p *probeResult) { p.Curl.Exit = 60 }},
		{"custom", func(p *probeResult) { p.Custom.Status = 0 }},
		{"passthrough", func(p *probeResult) { p.TLS.Issuer = "public CA" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := good
			tc.mutate(&changed)
			if checkHTTPS(changed, "example.com", true) == nil {
				t.Fatal("accepted a failed client")
			}
		})
	}
	denied := probeResult{}
	denied.Requests.Error = "CERTIFICATE_VERIFY_FAILED"
	denied.HTTPX.Error = "CERTIFICATE_VERIFY_FAILED"
	denied.TLS.Error = "CERTIFICATE_VERIFY_FAILED"
	denied.Node.Exit = 1
	denied.Curl.Exit = 60
	if err := checkHTTPS(denied, "example.com", false); err != nil {
		t.Fatal(err)
	}
	denied.Requests.Error = "connection refused"
	if checkHTTPS(denied, "example.com", false) == nil {
		t.Fatal("transport failure passed the negative certificate control")
	}
	if checkHTTPS(probeResult{}, "example.org", false) == nil {
		t.Fatal("empty probe result passed public HTTPS")
	}
}
