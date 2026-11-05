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
	"slices"
	"strings"
	"testing"

	"github.com/google/cel-go/cel"
	celenv "github.com/google/cel-go/common/env"

	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	fileaccesslogv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/file/v3"
)

func TestLegacyDefaultLogsRetainFilterStateNames(t *testing.T) {
	fileLog := &fileaccesslogv3.FileAccessLog{}
	if err := defaultTelemetryProviders(
		nil,
		true,
	).Provider("envoy").
		HTTPAccessLog.GetTypedConfig().
		UnmarshalTo(fileLog); err != nil {
		t.Fatal(err)
	}
	fields := fileLog.GetLogFormat().GetJsonFormat().GetFields()
	if got := fields["denial_reason"].GetStringValue(); got != "%FILTER_STATE(io.kruise.egress_denial_reason:PLAIN)%" {
		t.Fatalf("legacy denial reason format changed: %s", got)
	}
	format := fields["requested_server_name"].GetStringValue()
	if !strings.Contains(format, "io.kruise.outer_sni") || strings.Contains(format, "agentio.tls.outer_sni") {
		t.Fatalf("legacy SNI format changed: %s", format)
	}
}

func TestDefaultProviders(t *testing.T) {
	defaults := defaultTelemetryProviders(nil, false)
	if !slices.Equal(defaults.DefaultMetrics, []string{"prometheus"}) {
		t.Fatalf("default metrics = %v", defaults.DefaultMetrics)
	}
	if !slices.Equal(defaults.DefaultAccessLogging, []string{"envoy"}) {
		t.Fatalf("default access logging = %v", defaults.DefaultAccessLogging)
	}
	if len(defaults.DefaultTracing) != 0 {
		t.Fatalf("default tracing = %v, want none", defaults.DefaultTracing)
	}
	prometheus := defaults.Provider("PROMETHEUS")
	if prometheus == nil || !prometheus.Prometheus {
		t.Fatalf("prometheus provider = %+v", prometheus)
	}
	envoy := defaults.Provider("envoy")
	if envoy == nil || envoy.HTTPAccessLog == nil || envoy.TCPAccessLog == nil {
		t.Fatalf("envoy provider = %+v", envoy)
	}
	for protocol, accessLog := range map[string]*accesslogv3.AccessLog{"http": envoy.HTTPAccessLog, "tcp": envoy.TCPAccessLog} {
		fileLog := &fileaccesslogv3.FileAccessLog{}
		if err := accessLog.GetTypedConfig().UnmarshalTo(fileLog); err != nil {
			t.Fatalf("decode %s file access log: %v", protocol, err)
		}
		if fileLog.GetPath() != "/dev/stdout" || !fileLog.GetLogFormat().GetOmitEmptyValues() {
			t.Fatalf(
				"%s file access log path/omit = %q/%v",
				protocol,
				fileLog.GetPath(),
				fileLog.GetLogFormat().GetOmitEmptyValues(),
			)
		}
		fields := fileLog.GetLogFormat().GetJsonFormat().GetFields()
		want := map[string]string{
			"scheme":                         "%REQ(:SCHEME)%",
			"original_destination":           "%DOWNSTREAM_LOCAL_ADDRESS%",
			"upstream_host":                  "%UPSTREAM_HOST%",
			"denial_reason":                  "%FILTER_STATE(agentio.egress.denial_reason:PLAIN)%",
			"response_code_details":          "%RESPONSE_CODE_DETAILS%",
			"connection_termination_details": "%CONNECTION_TERMINATION_DETAILS%",
			"log_type":                       "%ACCESS_LOG_TYPE%",
			"authority_for":                  "%REQ(:AUTHORITY)%",
			"bytes_received":                 "%BYTES_RECEIVED%",
			"bytes_sent":                     "%BYTES_SENT%",
			"downstream_address":             "%DOWNSTREAM_REMOTE_ADDRESS%",
			"duration":                       "%DURATION%",
			"method":                         "%REQ(:METHOD)%",
			"path":                           "%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%",
			"protocol":                       "%PROTOCOL%",
			"request_id":                     "%REQ(X-REQUEST-ID)%",
			"requested_server_name":          "%CEL('agentio.tls.outer_sni' in filter_state ? filter_state['agentio.tls.outer_sni'] : connection.requested_server_name)%",
			"response_code":                  "%RESPONSE_CODE%",
			"response_flags":                 "%RESPONSE_FLAGS%",
			"start_time":                     "%START_TIME%",
			"trace_id":                       "%TRACE_ID%",
			"upstream_address":               "%UPSTREAM_REMOTE_ADDRESS%",
			"transport_failure_reason":       "%UPSTREAM_TRANSPORT_FAILURE_REASON%",
			"user_agent":                     "%REQ(USER-AGENT)%",
			"workload_name":                  "%CEL('agentio.workload.name' in filter_state && size(filter_state['agentio.workload.name']) > 0 ? filter_state['agentio.workload.name'] : '')%",
			"workload_namespace":             "%CEL('agentio.workload.namespace' in filter_state && size(filter_state['agentio.workload.namespace']) > 0 ? filter_state['agentio.workload.namespace'] : '')%",
		}
		if len(fields) != len(want) {
			t.Fatalf("%s JSON label count = %d, want %d: %v", protocol, len(fields), len(want), fields)
		}
		for name, value := range want {
			if got := fields[name].GetStringValue(); got != value {
				t.Errorf("%s label %s = %q, want %q", protocol, name, got, value)
			}
		}
	}
}

func TestDefaultAccessLogPreservesOriginalSNI(t *testing.T) {
	fileLog := &fileaccesslogv3.FileAccessLog{}
	if err := defaultTelemetryProviders(
		nil, false,
	).Provider("envoy").
		HTTPAccessLog.GetTypedConfig().
		UnmarshalTo(fileLog); err != nil {
		t.Fatal(err)
	}
	format := fileLog.GetLogFormat().GetJsonFormat().GetFields()["requested_server_name"].GetStringValue()
	testAccessLogSNI(t, format)
}

func testAccessLogSNI(t *testing.T, format string) {
	t.Helper()
	if !strings.HasPrefix(format, "%CEL(") || !strings.HasSuffix(format, ")%") {
		t.Fatalf("SNI format = %q, want CEL", format)
	}
	// Envoy's default CEL builder disables string conversion. Its filter-state
	// map is dynamically typed and exposes unstructured objects as bytes.
	environment, err := cel.NewCustomEnv(
		cel.StdLib(cel.StdLibSubset(celenv.NewLibrarySubset().AddExcludedFunctions(celenv.NewFunction("string")))),
		cel.Variable("filter_state", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("connection", cel.MapType(cel.StringType, cel.StringType)),
	)
	if err != nil {
		t.Fatal(err)
	}
	ast, issues := environment.Compile(strings.TrimSuffix(strings.TrimPrefix(format, "%CEL("), ")%"))
	if issues.Err() != nil {
		t.Fatal(issues.Err())
	}
	program, err := environment.Program(ast)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		state     map[string][]byte
		socketSNI string
		want      string
	}{
		{name: "plaintext HTTP", state: map[string][]byte{}, want: ""},
		{name: "TLS passthrough", state: map[string][]byte{}, socketSNI: "passthrough.example.com", want: "passthrough.example.com"},
		{name: "TLS without SNI", state: map[string][]byte{}, want: ""},
		{name: "decrypted HTTPS", state: map[string][]byte{"agentio.tls.outer_sni": []byte("api.example.com")}, want: "api.example.com"},
		{name: "outer SNI wins over inner connection", state: map[string][]byte{"agentio.tls.outer_sni": []byte("proxy.example.com")}, socketSNI: "inner.example.com", want: "proxy.example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Envoy exposes an unstructured filter-state string as CEL bytes. No
			// request attributes exist for TCP logs, so do not supply them here.
			got, _, err := program.Eval(map[string]any{
				"filter_state": tc.state,
				"connection":   map[string]string{"requested_server_name": tc.socketSNI},
			})
			if err != nil {
				t.Fatal(err)
			}
			// Envoy's non-typed CEL formatter prints both bytes and strings
			// directly. TYPED_CEL has different byte serialization semantics.
			var printed string
			switch value := got.Value().(type) {
			case string:
				printed = value
			case []byte:
				printed = string(value)
			default:
				t.Fatalf("SNI result has unexpected type %T", value)
			}
			if printed != tc.want {
				t.Errorf("SNI = %q, want %q", printed, tc.want)
			}
		})
	}
}

func TestDefaultAccessLogWorkloadIdentity(t *testing.T) {
	// Match Envoy's CEL environment: filter-state strings are bytes and
	// string() conversion is unavailable. This also covers TCP access logs,
	// where request.headers does not exist.
	environment, err := cel.NewCustomEnv(
		cel.StdLib(cel.StdLibSubset(celenv.NewLibrarySubset().AddExcludedFunctions(celenv.NewFunction("string")))),
		cel.Variable("filter_state", cel.MapType(cel.StringType, cel.DynType)),
	)
	if err != nil {
		t.Fatal(err)
	}
	fileLog := &fileaccesslogv3.FileAccessLog{}
	if err := defaultTelemetryProviders(
		nil, false,
	).Provider("envoy").
		HTTPAccessLog.GetTypedConfig().
		UnmarshalTo(fileLog); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"name", "namespace"} {
		t.Run(field, func(t *testing.T) {
			format := fileLog.GetLogFormat().GetJsonFormat().GetFields()["workload_"+field].GetStringValue()
			ast, issues := environment.Compile(strings.TrimSuffix(strings.TrimPrefix(format, "%CEL("), ")%"))
			if issues.Err() != nil {
				t.Fatal(issues.Err())
			}
			program, err := environment.Program(ast)
			if err != nil {
				t.Fatal(err)
			}
			for _, tc := range []struct {
				name  string
				state map[string]any
				want  string
			}{
				{"header overrides peer", map[string]any{"agentio.workload." + field: []byte("source"), "downstream_peer": map[string]string{field: "peer"}}, "source"},
				{"header without peer", map[string]any{"agentio.workload." + field: []byte("source")}, "source"},
				{"missing header", map[string]any{"downstream_peer": map[string]string{field: "peer"}}, ""},
				{"empty header", map[string]any{"agentio.workload." + field: []byte{}, "downstream_peer": map[string]string{field: "peer"}}, ""},
				{"empty string header", map[string]any{"agentio.workload." + field: "", "downstream_peer": map[string]string{field: "peer"}}, ""},
				{"no identity", map[string]any{}, ""},
				{"empty header without peer", map[string]any{"agentio.workload." + field: []byte{}}, ""},
			} {
				t.Run(tc.name, func(t *testing.T) {
					got, _, err := program.Eval(map[string]any{"filter_state": tc.state})
					if err != nil {
						t.Fatal(err)
					}
					var printed string
					switch value := got.Value().(type) {
					case string:
						printed = value
					case []byte:
						printed = string(value)
					default:
						t.Fatalf("unexpected result type %T", value)
					}
					if printed != tc.want {
						t.Errorf("workload_%s = %q, want %q", field, printed, tc.want)
					}
				})
			}
		})
	}
}
