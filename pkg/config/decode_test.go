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

package config_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/config"
)

func TestApplyConfigOverlay(t *testing.T) {
	base, err := config.Apply(`extensionProviders:
- name: base
  credentialProvider: {url: https://base.example}
defaultProviders: {credentialProvider: base}
`, &configv1.EPEConfig{})
	if err != nil {
		t.Fatal(err)
	}
	original := proto.Clone(base)
	for _, tc := range []struct {
		name            string
		raw             string
		provider        string
		defaultProvider string
		invalid         bool
	}{
		{name: "omitted", raw: "{}", provider: "base", defaultProvider: "base"},
		{name: "null document", raw: "null", provider: "base", defaultProvider: "base"},
		{name: "null", raw: "extensionProviders: null\ndefaultProviders: null", provider: "base", defaultProvider: "base"},
		{name: "select default", raw: "defaultProviders: {credentialProvider: default}", provider: "base", defaultProvider: "default"},
		{name: "reset message", raw: "defaultProviders: {}", provider: "base"},
		{name: "clear list", raw: "extensionProviders: []", defaultProvider: "base"},
		{
			name:            "replace list",
			raw:             "extensionProviders: [{name: primary, httpCallout: {url: https://primary.example}}]",
			provider:        "primary",
			defaultProvider: "base",
		},
		{name: "protobuf field name", raw: "extension_providers: []", defaultProvider: "base"},
		{
			name: "conflicting provider types",
			raw: "extensionProviders: [{name: primary, httpCallout: {url: https://example}, " +
				"credentialProvider: {url: https://example}}]\nfutureOption: true",
			invalid: true,
		},
		{name: "duplicate YAML key", raw: "defaultProviders: {}\ndefaultProviders: {}", invalid: true},
		{name: "unknown field", raw: "unknown: true", provider: "base", defaultProvider: "base"},
		{name: "unknown field in replacement", raw: "defaultProviders: {futureOption: true}", provider: "base"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := config.Apply(tc.raw, base)
			if (err != nil) != tc.invalid {
				t.Fatalf("Apply() error = %v, want invalid=%v", err, tc.invalid)
			}
			if !proto.Equal(base, original) {
				t.Fatal("overlay mutated the base configuration")
			}
			if tc.invalid {
				return
			}
			providers := got.GetExtensionProviders()
			if tc.provider == "" {
				if len(providers) != 0 {
					t.Fatalf("providers = %v, want empty", providers)
				}
			} else if len(providers) != 1 || providers[0].Name != tc.provider {
				t.Fatalf("providers = %v, want only %q", providers, tc.provider)
			}
			if got.GetDefaultProviders().GetCredentialProvider() != tc.defaultProvider {
				t.Fatalf(
					"default provider = %q, want %q",
					got.GetDefaultProviders().GetCredentialProvider(),
					tc.defaultProvider,
				)
			}
		})
	}
}

func TestApplyUnknownFieldsWarnWithPaths(t *testing.T) {
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	var output bytes.Buffer
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))

	got, err := config.Apply(`
sandboxExtProc:
  service: epe.system.svc
  port: 9002
  futureTargetRef: {name: epe, namespace: system, token: must-not-log}
additional_ext_procs:
- name: scanner
  service: scanner.system.svc
  future_target_ref: {name: scanner}
egressGateways:
- name: egress
  namespace: system
  extProc:
    service: override.system.svc
    futureTargetRef: {name: override}
  bandwidthLimit:
    descriptors:
    - bandwidthLimit: {uploadBytesPerSecond: 9007199254740993}
  accessLogFormat:
    json: {targetRef: {custom: true}, labels: [one, two]}
futureOption: true
`, &configv1.AgentioConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if got.GetSandboxExtProc().GetService() != "epe.system.svc" || got.GetSandboxExtProc().GetPort() != 9002 ||
		got.GetAdditionalExtProcs()[0].GetService() != "scanner.system.svc" ||
		got.GetEgressGateways()[0].GetExtProc().GetService() != "override.system.svc" {
		t.Fatalf("unknown fields changed known provider fields: %v", got)
	}
	gateway := got.GetEgressGateways()[0]
	if rate := gateway.GetBandwidthLimit().GetDescriptors()[0].GetBandwidthLimit().
		GetUploadBytesPerSecond(); rate != 9007199254740993 {
		t.Fatalf("uint64 rate lost precision: %d", rate)
	}
	if fields := gateway.GetAccessLogFormat().GetJson().GetFields(); len(fields) != 2 ||
		!fields["targetRef"].GetStructValue().GetFields()["custom"].GetBoolValue() ||
		len(fields["labels"].GetListValue().GetValues()) != 2 {
		t.Fatalf("arbitrary JSON fields were changed: %v", fields)
	}
	var entry struct {
		Level  string   `json:"level"`
		Fields []string `json:"fields"`
	}
	if err := json.Unmarshal(output.Bytes(), &entry); err != nil {
		t.Fatalf("decode warning: %v, output: %s", err, output.String())
	}
	want := []string{
		"additional_ext_procs[0].future_target_ref",
		"egressGateways[0].extProc.futureTargetRef",
		"futureOption",
		"sandboxExtProc.futureTargetRef",
	}
	if entry.Level != "WARN" || !reflect.DeepEqual(entry.Fields, want) {
		t.Fatalf("warning = %+v, want WARN with fields %v", entry, want)
	}
	if strings.Contains(output.String(), "must-not-log") {
		t.Fatal("warning exposed an unknown field's value")
	}
}

func TestApplyUnknownFieldsDoNotHideKnownErrors(t *testing.T) {
	base := &configv1.AgentioConfig{
		SandboxExtProc: &configv1.ExtProcProvider{Service: "previous.system.svc", Port: 9002},
	}
	original := proto.Clone(base)
	for _, raw := range []string{
		"sandboxExtProc: {port: invalid}",
		"sandboxExtProc: {port: -1}",
		"sandboxExtProc: {request: {headerMode: INVALID}}",
		"sandboxExtProc: {request: []}",
		"sandboxExtProc: {}\nsandbox_ext_proc: {}",
		"egressGateways: [{http: {streamIdleTimeout: invalid}}]",
	} {
		t.Run(raw, func(t *testing.T) {
			if _, err := config.Apply("futureOption: true\n"+raw, base); err == nil {
				t.Fatal("unknown field hid an invalid known field")
			}
			if !proto.Equal(base, original) {
				t.Fatal("failed overlay mutated the base")
			}
		})
	}
}
