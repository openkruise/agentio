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

package compiler

import (
	"encoding/json"
	"reflect"
	"testing"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"
	"github.com/openkruise/agentio/extensions/epe/pkg/wiring"
	"github.com/openkruise/agentio/internal/testutil"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

func TestSecurityProfileJSONPreservesSpecAndSourceIdentity(t *testing.T) {
	cms := krt.NewMutableCollection[*corev1.ConfigMap](nil, nil, krt.WithStop(t.Context().Done()))
	f := newIncrementalFixture(t, func(inputs *Inputs) { inputs.ConfigMaps = cms.AsCollection() })
	source := model.SecurityProfile{UID: "source-uid", Name: "policy", Namespace: "ns"}
	if err := json.Unmarshal(
		[]byte(
			`{"selector":{},"inputs":[{"name":"settings","configMap":{"name":"settings"}},{"name":"empty","inline":{}},{"name":"inline","inline":{"value":"kept"}}],"rules":[{"name":"block","match":[{"domains":["example.com"]}],"actions":{"block":{}}}]}`,
		),
		&source.Spec,
	); err != nil {
		t.Fatal(err)
	}
	f.securityProfiles.UpdateObject(source)
	key := model.ResourceKey{TypeURL: model.SecurityProfileType, Name: source.ResourceName()}
	var initial model.Resource
	testutil.Eventually(t, func() bool {
		var found bool
		initial, found = currentSnapshot(t, f.compiler).Get(key)
		return found
	}, "JSON profile body published independently of inputs")
	wire := &securityv1.SecurityProfile{}
	if err := initial.Value.UnmarshalTo(wire); err != nil {
		t.Fatal(err)
	}
	var document model.HTTPPolicy
	if err := json.Unmarshal(wire.PolicyJson, &document); err != nil {
		t.Fatal(err)
	}
	if initial.XDSName != source.ResourceName() || wire.Name != source.Name || wire.Namespace != source.Namespace ||
		wire.Uid != source.UID ||
		!reflect.DeepEqual(document.Rules, source.Spec.Rules) ||
		!reflect.DeepEqual(document.Inputs, source.Spec.Inputs) {
		t.Fatalf("profile spec or identity changed: %+v", document)
	}
	compiled, err := securityprofile.FromXDS(wire, "", nil)
	if err != nil || !reflect.DeepEqual(compiled.Spec.Inputs, source.Spec.Inputs) {
		t.Fatalf("input declarations did not survive xDS admission: %v", err)
	}
	cms.UpdateObject(
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "settings", Namespace: "ns"},
			Data:       map[string]string{"value": "local-to-control-plane"},
		},
	)
	settle()
	current, found := currentSnapshot(t, f.compiler).Get(key)
	if !found || initial.Hash != current.Hash {
		t.Fatal("control-plane ConfigMap changed the opaque profile body")
	}
	source.Spec.Rules = append(source.Spec.Rules, agentsv1alpha1.SecurityRule{Name: "new"})
	f.securityProfiles.UpdateObject(source)
	testutil.Eventually(t, func() bool {
		current, found := currentSnapshot(t, f.compiler).Get(key)
		return found && current.Hash != initial.Hash
	}, "HTTP rule changes update the body even without SNI changes")
}

func TestSecurityProfilePublishesOnlyHTTPView(t *testing.T) {
	f := newIncrementalFixture(t)
	source := model.SecurityProfile{UID: "source-uid", Name: "mixed", Namespace: "ns"}
	if err := json.Unmarshal([]byte(`{
		"selector":{"matchLabels":{"app":"client"}},
		"priority":12,
		"inputs":[{"name":"settings","configMap":{"name":"settings"}}],
		"audit":[{"name":"default","webhook":{"url":"https://audit.example.com"}}],
		"rules":[
			{"name":"tls","match":[{"domains":["tls.example.com"],"ports":[443]}],"actions":{"tls":{"action":"Deny"}}},
			{"name":"http","match":[{"domains":["http.example.com"]}],"actions":{"block":{},"audit":[{"name":"rule","webhook":{"url":"https://rule-audit.example.com"}}]}}
		]
	}`), &source.Spec); err != nil {
		t.Fatal(err)
	}
	f.securityProfiles.UpdateObject(source)
	var wire securityv1.SecurityProfile
	testutil.Eventually(t, func() bool {
		resource, found := currentSnapshot(
			t,
			f.compiler,
		).Get(model.ResourceKey{TypeURL: model.SecurityProfileType, Name: source.ResourceName()})
		if !found {
			return false
		}
		if err := resource.Value.UnmarshalTo(&wire); err != nil {
			t.Fatal(err)
		}
		return true
	}, "profile carries EPE configuration")
	regs, err := wiring.BuildValidationFilters()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := securityprofile.FromXDS(&wire, "", regs)
	if err != nil {
		t.Fatal(err)
	}
	if len(profile.Rules) != 1 || profile.Rules[0].Name != "http" || len(profile.Audits) != 1 ||
		len(profile.Rules[0].Audits) != 1 ||
		profile.Meta.Name != source.Name ||
		profile.Meta.Namespace != source.Namespace ||
		profile.Meta.SourceIdentity.UID != source.UID {
		t.Fatalf("HTTP rules, audit or source identity lost: %+v", profile)
	}
	if !reflect.DeepEqual(profile.Spec.Inputs, source.Spec.Inputs) || profile.Inputs != nil {
		t.Fatal("HTTP policy lost inputs or resolved inputs on the control plane")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(wire.PolicyJson, &fields); err != nil {
		t.Fatal(err)
	}
	for key := range fields {
		if key != "rules" && key != "audit" && key != "inputs" {
			t.Fatalf("non-HTTP field %q was sent to EPE", key)
		}
	}
	if len(profile.Spec.Rules) != 1 || profile.Spec.Rules[0].Actions.TLS != nil || len(source.Spec.Rules) != 2 {
		t.Fatal("HTTP view retained TLS rules or mutated the source")
	}
}
