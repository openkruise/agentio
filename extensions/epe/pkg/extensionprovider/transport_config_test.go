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

package extensionprovider

import (
	"fmt"
	"testing"
	"time"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/config"
)

func TestCalloutTransportValidation(t *testing.T) {
	for _, tc := range []struct {
		fields string
		valid  bool
	}{
		{"", true}, {"protocol: HTTP2", true}, {"protocol: AUTO, http2: {maxConcurrentStreams: 16}", true},
		{"protocol: HTTP1, http2: {}", false}, {"protocol: 99", false}, {"http2: {maxConcurrentStreams: 0}", false},
		{"http2: {maxConcurrentStreams: 2147483648}", false}, {"connectionPool: {maxConnections: 0}", false},
		{"connectionPool: {maxConnections: 2}", true}, {"connectionPool: {maxConnections: 2, maxIdleConnections: 3}", false},
		{"connectionPool: {maxIdleConnections: 0}", true}, {"connectionPool: {idleTimeout: 0s}", false},
	} {
		t.Run(tc.fields, func(t *testing.T) {
			raw := fmt.Sprintf(
				"extensionProviders: [{name: scanner, httpCallout: {url: 'http://localhost:8080', %s}}]",
				tc.fields,
			)
			cfg, err := config.ApplyAgentioConfig(raw, &configv1.AgentioConfig{})
			if err == nil {
				err = Validate(cfg)
			}
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%t error=%v", tc.valid, err)
			}
		})
	}
}

func TestCalloutTransportDefaults(t *testing.T) {
	for _, tc := range []struct {
		fields      string
		connections int
		idle        int
	}{
		{"", 128, 64},
		{"protocol: HTTP1", 128, 64},
		{"protocol: AUTO, http2: {maxConcurrentStreams: 32}", 128, 64},
		{"protocol: HTTP2", 32, 8},
		{"protocol: HTTP2, connectionPool: {}", 32, 8},
		{"protocol: HTTP2, connectionPool: {maxConnections: 4}", 4, 4},
		{"protocol: HTTP1, connectionPool: {maxConnections: 4}", 4, 4},
		{"protocol: HTTP2, connectionPool: {maxConnections: 128, maxIdleConnections: 64}", 128, 64},
		{"protocol: HTTP2, connectionPool: {maxIdleConnections: 0}", 32, 0},
	} {
		t.Run(tc.fields, func(t *testing.T) {
			raw := fmt.Sprintf(
				"extensionProviders: [{name: scanner, httpCallout: {url: 'http://localhost:8080', %s}}]", tc.fields,
			)
			cfg, err := config.ApplyAgentioConfig(raw, &configv1.AgentioConfig{})
			if err != nil {
				t.Fatal(err)
			}
			o, err := calloutOptions(cfg.ExtensionProviders[0].GetHttpCallout())
			if err != nil {
				t.Fatal(err)
			}
			if o.MaxConnsPerHost != tc.connections || o.MaxIdleConnsPerHost != tc.idle ||
				o.MaxConcurrentStreams != 32 || o.IdleConnTimeout != 90*time.Second {
				t.Fatalf(
					"options=%+v, want connections=%d idle=%d streams=32 idleTimeout=90s",
					o, tc.connections, tc.idle,
				)
			}
		})
	}
}
