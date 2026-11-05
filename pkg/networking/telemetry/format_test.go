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

package telemetry

import (
	"testing"

	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	fileaccesslogv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/file/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/model"
)

func TestBuildGatewayAccessLogFormat(t *testing.T) {
	customJSON, err := structpb.NewStruct(map[string]any{
		"scheme":           "%REQ(:SCHEME)%",
		"context":          map[string]any{"authority": "%REQ(:AUTHORITY)%"},
		"version":          1,
		"upstream_cluster": "%UPSTREAM_CLUSTER%",
		"filter_chain":     "%FILTER_CHAIN_NAME%",
	})
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := Build(Inputs{Gateway: testTelemetryGateway()})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		format *configv1.AccessLogFormat
		text   string
	}{
		{name: "default"},
		{name: "empty configuration", format: &configv1.AccessLogFormat{}},
		{name: "JSON replacement", format: &configv1.AccessLogFormat{Json: customJSON}},
		{name: "text adds newline", format: &configv1.AccessLogFormat{Text: proto.String("%PROTOCOL% %REQ(:SCHEME)%")}, text: "%PROTOCOL% %REQ(:SCHEME)%\n"},
		{name: "text preserves newline", format: &configv1.AccessLogFormat{Text: proto.String("%PROTOCOL%\n")}, text: "%PROTOCOL%\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gateway := testTelemetryGateway()
			gateway.Config.AccessLogFormat = tc.format
			for _, disabled := range []bool{false, true} {
				expression := "connection.requested_server_name != ''"
				policy := buildValue(t, nil, nil, []model.TelemetryAccessLogging{{
					Mode: model.TelemetryModeServer, Disabled: &disabled, Filter: &expression,
				}})
				output, err := Build(Inputs{Gateway: gateway, Telemetry: []model.Telemetry{policy}})
				if err != nil {
					t.Fatal(err)
				}
				for path, logs := range map[string][]*accesslogv3.AccessLog{
					"HTTP": output.HTTPAccessLogs, "TCP": output.TCPAccessLogs,
					"CONNECT": output.ConnectHTTPAccessLogs, "listener": output.ListenerAccessLogs,
				} {
					if disabled {
						if len(logs) != 0 {
							t.Fatalf("%s: disabled logs = %v", path, logs)
						}
						continue
					}
					if len(logs) != 1 {
						t.Fatalf("%s: log count = %d", path, len(logs))
					}
					fileLog := &fileaccesslogv3.FileAccessLog{}
					if err := logs[0].GetTypedConfig().UnmarshalTo(fileLog); err != nil {
						t.Fatal(err)
					}
					if err := fileLog.ValidateAll(); err != nil {
						t.Fatal(err)
					}
					if fileLog.GetPath() != "/dev/stdout" {
						t.Fatalf("%s: path = %q", path, fileLog.GetPath())
					}
					format := fileLog.GetLogFormat()
					switch {
					case tc.format.GetJson() != nil:
						if !proto.Equal(format.GetJsonFormat(), customJSON) || !format.GetOmitEmptyValues() {
							t.Fatalf("%s: JSON replacement = %v", path, format)
						}
					case tc.text != "":
						if format.GetTextFormatSource().GetInlineString() != tc.text || format.GetOmitEmptyValues() {
							t.Fatalf("%s: text replacement = %v", path, format)
						}
					default:
						if !proto.Equal(logs[0].GetTypedConfig(), baseline.HTTPAccessLogs[0].GetTypedConfig()) {
							t.Fatalf("%s: default format changed", path)
						}
					}
					if path == "HTTP" || path == "TCP" {
						assertCELFilter(t, logs[0], expression)
					} else {
						filters := logs[0].GetFilter().GetAndFilter().GetFilters()
						if len(filters) != 2 {
							t.Fatalf("%s: filters = %v", path, filters)
						}
						assertCELFilter(t, &accesslogv3.AccessLog{Filter: filters[1]}, expression)
						if path == "CONNECT" &&
							filters[0].GetStatusCodeFilter().GetComparison().GetValue().GetDefaultValue() != 400 {
							t.Fatal("CONNECT failure filter was lost")
						}
						if path == "listener" && filters[0].GetResponseFlagFilter().GetFlags()[0] != "NR" {
							t.Fatal("listener failure filter was lost")
						}
					}
				}
			}
			other, err := Build(Inputs{Gateway: testTelemetryGateway()})
			if err != nil {
				t.Fatal(err)
			}
			if !proto.Equal(other.HTTPAccessLogs[0], baseline.HTTPAccessLogs[0]) {
				t.Fatal("gateway format mutated the default provider")
			}
		})
	}
}

func TestGatewayFormatPreservesExplicitProviderOverride(t *testing.T) {
	gateway := testTelemetryGateway()
	gateway.Config.AccessLogFormat = &configv1.AccessLogFormat{Text: proto.String("custom")}
	replacement := defaultTelemetryProviders(nil, false).Provider("envoy").Clone()
	output, err := Build(Inputs{
		Gateway:           gateway,
		ProviderOverrides: &model.TelemetryProviderOverrides{Providers: []model.TelemetryProvider{replacement}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(output.HTTPAccessLogs[0], replacement.HTTPAccessLog) ||
		!proto.Equal(output.TCPAccessLogs[0], replacement.TCPAccessLog) {
		t.Fatal("gateway format replaced an explicitly configured provider")
	}
}
