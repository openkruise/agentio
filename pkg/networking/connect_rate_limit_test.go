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
	"strings"
	"testing"

	localratelimitv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/local_ratelimit/v3"
	rlexprv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/rate_limit_descriptors/expr/v3"
	"google.golang.org/protobuf/encoding/protojson"

	configv1 "github.com/openkruise/agentio/api/config/v1"
)

func TestConnectRateLimitIndependentActionGroups(t *testing.T) {
	settings := new(configv1.LocalRateLimitSettings)
	if err := protojson.Unmarshal([]byte(`{
      "rateLimits": [
        {"actions": [
          {"filterState": {"key": "tenant.id", "descriptorKey": "tenant"}},
          {"filterState": {"key": "agentio.sandbox.id", "descriptorKey": "sandbox"}}
        ]},
        {"actions": [{"genericKey": {"descriptorKey": "scope", "descriptorValue": "gateway"}}]},
        {"actions": [{"filterState": {"key": "other.id", "descriptorKey": "sandbox"}}]}
      ],
      "descriptors": [
        {"entries": [{"key": "tenant"}, {"key": "sandbox"}],
         "tokenBucket": {"maxTokens": 10, "tokensPerFill": 2, "fillInterval": "1s"}},
        {"entries": [{"key": "scope", "value": "gateway"}],
         "tokenBucket": {"maxTokens": 100, "fillInterval": "1s"}},
        {"entries": [{"key": "sandbox"}],
         "tokenBucket": {"maxTokens": 20, "fillInterval": "1s"}}
      ]
    }`), settings); err != nil {
		t.Fatal(err)
	}
	b := new(resourceBuilder)
	filter, err := b.localRateLimitFilter(settings)
	if err != nil {
		t.Fatal(err)
	}
	got := new(localratelimitv3.LocalRateLimit)
	if err := filter.GetTypedConfig().UnmarshalTo(got); err != nil {
		t.Fatal(err)
	}
	if got.GetTokenBucket() != nil || len(got.GetRateLimits()) != 3 || len(got.GetDescriptors()) != 3 {
		t.Fatalf("descriptor-only config lost independent groups: %v", got)
	}
	first := got.GetRateLimits()[0].GetActions()
	if len(first) != 2 {
		t.Fatalf("composite key has %d actions", len(first))
	}
	for i, action := range []struct {
		descriptor string
		key        string
	}{
		{"tenant", "tenant.id"},
		{"sandbox", "agentio.sandbox.id"},
	} {
		expression := new(rlexprv3.Descriptor)
		if err := first[i].GetExtension().GetTypedConfig().UnmarshalTo(expression); err != nil {
			t.Fatal(err)
		}
		if expression.GetDescriptorKey() != action.descriptor ||
			expression.GetText() != `filter_state["`+action.key+`"]` {
			t.Fatalf("incorrect filter-state action: %v", expression)
		}
	}
	fixed := got.GetRateLimits()[1].GetActions()[0].GetGenericKey()
	if fixed.GetDescriptorKey() != "scope" || fixed.GetDescriptorValue() != "gateway" {
		t.Fatalf("incorrect fixed action: %v", fixed)
	}
	other := new(rlexprv3.Descriptor)
	if err := got.GetRateLimits()[2].GetActions()[0].GetExtension().GetTypedConfig().UnmarshalTo(other); err != nil {
		t.Fatal(err)
	}
	if other.GetText() != `filter_state["other.id"]` {
		t.Fatalf("descriptor key was deduplicated across independent groups: %v", other)
	}
	if got.GetDescriptors()[0].GetTokenBucket().GetMaxTokens() != 10 ||
		got.GetDescriptors()[0].GetTokenBucket().GetTokensPerFill().GetValue() != 2 ||
		got.GetDescriptors()[0].GetTokenBucket().GetFillInterval().AsDuration().Seconds() != 1 {
		t.Fatalf("token bucket was changed: %v", got.GetDescriptors()[0])
	}
}

func TestConnectRateLimitRejectsMixedLegacyCELAtCompilation(t *testing.T) {
	settings := &configv1.LocalRateLimitSettings{
		RateLimits: []*configv1.NetworkLimitRule{{Actions: []*configv1.NetworkLimitAction{{
			FilterState: &configv1.NetworkLimitFilterStateAction{Key: "agentio.sandbox.id", DescriptorKey: "sandbox"},
		}}}},
		Descriptors: []*configv1.RateLimitDescriptor{{Entries: []*configv1.RateLimitEntry{{
			Key: "sandbox",
			Cel: `filter_state["other.id"]`,
		}}}},
	}
	_, err := Build(Inputs{Gateway: testGateway(&configv1.EgressGateway{ConnectRateLimit: settings})})
	if err == nil || !strings.Contains(err.Error(), "cannot be combined with rateLimits") {
		t.Fatalf("mixed legacy/new actions were not rejected at compilation: %v", err)
	}
}
