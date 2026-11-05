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

package networklimits

import (
	"encoding/json"
	"testing"

	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/encoding/protojson"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/networking"
)

func TestEnvoyGeneratedConnectRateLimit(t *testing.T) {
	settings := new(configv1.EgressGateway)
	must(t, protojson.Unmarshal([]byte(`{"connectRateLimit": {
      "rateLimits": [
        {"actions": [{"filterState": {"key": "agentio.sandbox.uid", "descriptorKey": "sandbox"}}]},
        {"actions": [{"genericKey": {"descriptorKey": "scope", "descriptorValue": "gateway"}}]}
      ],
      "descriptors": [
        {"entries": [{"key": "sandbox"}],
         "tokenBucket": {"maxTokens": 1, "tokensPerFill": 1, "fillInterval": "60s"}},
        {"entries": [{"key": "scope", "value": "gateway"}],
         "tokenBucket": {"maxTokens": 3, "tokensPerFill": 3, "fillInterval": "60s"}}
      ]
    }}`), settings))
	resources, err := networking.Build(networking.Inputs{
		Gateway:          model.Gateway{Namespace: "agentio-system", Name: "egress", Config: settings},
		DiscoveryAddress: "agentiod:15012",
		TrustDomain:      "cluster.local",
	})
	must(t, err)
	var rateFilter object
	for _, resource := range resources {
		if resource.Key.TypeURL != model.ListenerType || resource.XDSName != networking.ConnectTerminate {
			continue
		}
		listener := new(listenerv3.Listener)
		must(t, resource.Value.UnmarshalTo(listener))
		hcm := new(hcmv3.HttpConnectionManager)
		must(t, listener.FilterChains[0].Filters[0].GetTypedConfig().UnmarshalTo(hcm))
		for _, filter := range hcm.HttpFilters {
			if filter.GetName() != "envoy.filters.http.local_ratelimit" {
				continue
			}
			data, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(filter)
			must(t, err)
			must(t, json.Unmarshal(data, &rateFilter))
		}
	}
	if rateFilter == nil {
		t.Fatal("generated listener has no native rate limiter")
	}
	origin := startOrigin(t, false)
	r := startEnvoy(t, origin.port(), freePort(t), func(l object) {
		fs := filters(l)
		setFilters(l, []any{fs[0], rateFilter, fs[2]})
	})
	a, b := newClient(t, r.port), newClient(t, r.port)
	finish(t, a.open(t, "test", "a", "plain:80", 200))
	b.open(t, "test", "a", "plain:80", 429).close()
	finish(t, b.open(t, "test", "b", "plain:80", 200))
	finish(t, a.open(t, "test", "c", "plain:80", 200))
	b.open(t, "test", "d", "plain:80", 429).close()
}
