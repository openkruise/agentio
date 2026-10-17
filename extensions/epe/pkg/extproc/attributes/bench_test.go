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
package attributes

import (
	"context"
	"os"
	"strconv"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/go-logr/logr"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/openkruise/agentio/extensions/epe/pkg/logging"
)

// TestMain installs a logger so the hot path's log.FromContext resolves to a
// real sink rather than controller-runtime's unfulfilled root, which prints a
// stack trace into the benchmark output after 30s. Production installs a zap
// logger at INFO; a discard sink matches it in the part that actually costs,
// since either way the caller builds the key-value slice before the level
// check can drop it — see BenchmarkDebugLogArgs.
func TestMain(m *testing.M) {
	ctrllog.SetLogger(logr.Discard())
	os.Exit(m.Run())
}

// benchSink defeats dead-code elimination.
var benchSink any

// benchHeaders builds n request headers on top of the four pseudo-headers
// Envoy always sends. Names are lowercase, as Envoy normalizes them, so the
// strings.ToLower in extractHeaderMap hits its no-copy fast path — the same
// as production.
func benchHeaders(n int) *extProcPb.HttpHeaders {
	hm := &corev3.HeaderMap{}
	add := func(k, v string) {
		hm.Headers = append(hm.Headers, &corev3.HeaderValue{Key: k, RawValue: []byte(v)})
	}
	add(":authority", "api.example.com:8443")
	add(":path", "/v1/chat/completions?stream=true&model=gpt-4")
	add(":method", "POST")
	add(":scheme", "https")
	add("x-request-id", "3f2b8c1e-0d4a-4a7b-9c2f-1e5d8a6b4c30")
	add("content-type", "application/json")
	for i := 0; i < n; i++ {
		add("x-bench-"+strconv.Itoa(i), "value-"+strconv.Itoa(i))
	}
	return &extProcPb.HttpHeaders{Headers: hm}
}

// BenchmarkExtract covers the per-request attribute extraction. The
// identity-present arms differ only in whether sandbox.token and
// agentio.workload.labels are in the attributes map: every absent key costs
// extractFilterStateString a key concat plus a full map scan.
func BenchmarkExtract(b *testing.B) {
	base := map[string]any{
		FilterStateDownstreamPeerNamespace: "default",
		FilterStateDownstreamPeerName:      "agent-pod-abc123",
		FilterStateWorkloadLabels:          b64("app=agent,tier=web,version=v2"),
		AttrSourceAddress:                  "10.244.1.37:43210",
		AttrDestinationPort:                8443,
	}
	withSandbox := map[string]any{}
	for k, v := range base {
		withSandbox[k] = v
	}
	withSandbox[FilterStateSandboxToken] = b64(
		`{"requestId":"r1","accessToken":"tok","sandboxClientId":"c1"}`)

	// No pod identity: Extract returns early. This is the fail-open path a
	// misconfigured mesh takes on every single request.
	noIdentity := map[string]any{
		AttrSourceAddress: "10.244.1.37:43210",
	}

	for _, bc := range []struct {
		name   string
		fields map[string]any
	}{
		{"sandbox=absent", base},
		{"sandbox=present", withSandbox},
		{"identity=missing", noIdentity},
	} {
		attrs := makeAttrs(b, bc.fields)
		for _, nHeaders := range []int{0, 16} {
			headers := benchHeaders(nHeaders)
			name := bc.name + "/headers=" + strconv.Itoa(len(headers.GetHeaders().GetHeaders()))
			b.Run(name, func(b *testing.B) {
				ctx := context.Background()
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					peer, req := Extract(ctx, headers, attrs)
					benchSink = peer
					benchSink = req
				}
			})
		}
	}
}

// BenchmarkExtractHeaderMap isolates the header map build, so its share of
// Extract is attributable rather than inferred.
func BenchmarkExtractHeaderMap(b *testing.B) {
	for _, n := range []int{0, 16, 48} {
		headers := benchHeaders(n)
		b.Run("headers="+strconv.Itoa(len(headers.GetHeaders().GetHeaders())), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchSink = extractHeaderMap(headers)
			}
		})
	}
}

// BenchmarkDebugLogArgs prices what an unguarded debug log line costs when
// the level is disabled. Go evaluates variadic arguments at the call site, so
// the key-value slice and the boxing of every non-pointer value happen before
// Info can check Enabled and drop them. Extract does this on every request
// with a 6-argument line, and HandleRequestHeaders with a 14-argument one.
//
// The guarded arm is the same line behind an explicit Enabled check, which is
// the shape the codebase already uses for the body-chunk log in server.go.
func BenchmarkDebugLogArgs(b *testing.B) {
	loggerD := logr.Discard().V(logging.DEBUG)
	podName, podNamespace := "agent-pod-abc123", "default"
	podLabels := map[string]string{"app": "agent", "tier": "web", "version": "v2"}

	b.Run("unguarded", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			loggerD.Info("extracted pod info from attributes",
				"pod", podName, "namespace", podNamespace,
				"labels", podLabels)
		}
	})
	b.Run("guarded", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if loggerD.Enabled() {
				loggerD.Info("extracted pod info from attributes",
					"pod", podName, "namespace", podNamespace,
					"labels", podLabels)
			}
		}
	})
}

// BenchmarkExtractFilterStateString contrasts a key that is present against
// one that is absent. The absent arm is the cost this function pays twice
// per request for sandbox.token and agentio.workload.labels.
func BenchmarkExtractFilterStateString(b *testing.B) {
	attrs := makeAttrs(b, map[string]any{
		FilterStateDownstreamPeerNamespace: "default",
		FilterStateDownstreamPeerName:      "agent-pod-abc123",
		FilterStateWorkloadLabels:          b64("app=agent,tier=web,version=v2"),
		AttrSourceAddress:                  "10.244.1.37:43210",
		AttrDestinationPort:                8443,
	})
	for _, bc := range []struct {
		name string
		key  string
	}{
		{"hit", FilterStateDownstreamPeerName},
		{"miss", FilterStateSandboxToken},
	} {
		b.Run(bc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchSink = extractFilterStateString(attrs, bc.key)
			}
		})
	}
}
