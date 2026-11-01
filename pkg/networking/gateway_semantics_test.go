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

package networking

import (
	"testing"

	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/model"
)

func TestGatewayPathNormalizationDefaults(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		resources, err := Build(Inputs{
			Gateway: testGateway(&configv1.EgressGateway{
				TlsTermination: &configv1.TlsTerminationConfig{IncludeHosts: []string{"example.com"}},
			}),
			LegacyGateway:    legacy,
			DiscoveryAddress: "agentiod.agentio-system.svc:15012",
			TrustDomain:      "cluster.local",
		})
		if err != nil {
			t.Fatal(err)
		}
		managers := 0
		for _, listener := range messagesOf(t, resources, model.ListenerType, func() *listenerv3.Listener { return &listenerv3.Listener{} }) {
			for _, chain := range listener.FilterChains {
				for _, filter := range chain.Filters {
					if filter.Name != "envoy.filters.network.http_connection_manager" {
						continue
					}
					hcm := &hcmv3.HttpConnectionManager{}
					if err := filter.GetTypedConfig().UnmarshalTo(hcm); err != nil {
						t.Fatal(err)
					}
					managers++
					if !hcm.GetNormalizePath().GetValue() || hcm.GetMergeSlashes() ||
						hcm.GetPathWithEscapedSlashesAction() != hcmv3.HttpConnectionManager_KEEP_UNCHANGED {
						t.Errorf(
							"legacy=%v listener=%s chain=%s: path handling differs from release defaults",
							legacy,
							listener.Name,
							chain.Name,
						)
					}
				}
			}
		}
		if managers < 3 {
			t.Fatalf("only checked %d HTTP managers", managers)
		}
	}
}
