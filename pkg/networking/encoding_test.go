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
	"errors"
	"strings"
	"testing"

	"github.com/openkruise/agentio/pkg/model"

	"google.golang.org/protobuf/types/known/wrapperspb"
	"istio.io/istio/pkg/test"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/features"
)

func TestExtensionEncodingKeepsFirstError(t *testing.T) {
	b := &resourceBuilder{}
	if value := b.pack(wrapperspb.String(string([]byte{0xff}))); value != nil || b.err == nil {
		t.Fatalf("invalid UTF-8 encoded: value=%v error=%v", value, b.err)
	}
	first := b.err
	if value := b.pack(wrapperspb.String("valid")); value != nil || !errors.Is(b.err, first) {
		t.Fatal("a later extension masked the encoding failure")
	}
}

func TestListenerEncodingFailureDiscardsResources(t *testing.T) {
	test.SetForTest(t, &features.EnableSNITrafficPolicy, true)
	config := effectiveConfig{gateway: &configv1.EgressGateway{
		TlsTermination: &configv1.TlsTerminationConfig{ExcludeHosts: []string{string([]byte{0xff})}},
	}}
	listeners, err := (&resourceBuilder{}).listeners(config, "cluster.local")
	if listeners != nil || err == nil || !strings.Contains(err.Error(), "marshal gateway extension") {
		t.Fatalf("encoding failure must discard listeners: listeners=%v error=%v", listeners, err)
	}
	config.gateway.TlsTermination.ExcludeHosts = []string{"example.com"}
	if _, err := (&resourceBuilder{}).listeners(config, "cluster.local"); err != nil {
		t.Fatalf("failed build contaminated the next build: %v", err)
	}
}

func TestClusterEncodingFailureDiscardsResources(t *testing.T) {
	test.SetForTest(t, &features.GatewayRootCAPath, "/certs/"+string([]byte{0xff}))
	clusters, err := (&resourceBuilder{}).clusters(effectiveConfig{})
	if clusters != nil || err == nil || !strings.Contains(err.Error(), "marshal gateway extension") {
		t.Fatalf("encoding failure must discard clusters: clusters=%v error=%v", clusters, err)
	}
}

func TestGatewayEncodingIsDeterministic(t *testing.T) {
	test.SetForTest(t, &features.EnableSNITrafficPolicy, true)
	inputs := Inputs{Gateway: testGateway(&configv1.EgressGateway{}), DiscoveryAddress: "agentiod.agentio-system.svc:15012", TrustDomain: "cluster.local"}
	versions := map[string]bool{}
	for n := 0; n < 100; n++ {
		r, err := Build(inputs)
		if err != nil {
			t.Fatal(err)
		}
		s, err := model.NewResourceSet(r)
		if err != nil {
			t.Fatal(err)
		}
		versions[s.Version()] = true
	}
	if len(versions) != 1 {
		t.Fatalf("identical gateway input produced %d versions", len(versions))
	}
}
