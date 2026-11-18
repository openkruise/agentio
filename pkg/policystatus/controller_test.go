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

package policystatus

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	agents "github.com/openkruise/agents-api/agents/v1alpha1"
	"istio.io/istio/pkg/test/util/assert"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	dynamicfake "k8s.io/client-go/dynamic/fake"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/config"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/model"
	registry "github.com/openkruise/agentio/pkg/registry/kubernetes"
	"github.com/openkruise/agentio/pkg/validation"
)

func mutable[T any](t *testing.T) krt.StaticCollection[T] {
	t.Helper()
	return krt.NewMutableCollection[T](nil, nil, krt.WithStop(t.Context().Done()))
}

func testController(t *testing.T, scoped bool) (*Controller, *registry.Registry) {
	t.Helper()
	defaults := model.AgentioConfiguration{Value: &configv1.AgentioConfig{}}
	r := &registry.Registry{
		AgentioConfig:                krt.NewStatic(&defaults, true, krt.WithStop(t.Context().Done())).AsCollection(),
		SecurityProfileObjects:       mutable[*agents.SecurityProfile](t).AsCollection(),
		GlobalSecurityProfileObjects: mutable[*agents.GlobalSecurityProfile](t).AsCollection(),
		TrafficPolicyObjects:         mutable[*agents.TrafficPolicy](t).AsCollection(),
		GlobalTrafficPolicyObjects:   mutable[*agents.GlobalTrafficPolicy](t).AsCollection(),
		ConfigMaps:                   mutable[*corev1.ConfigMap](t).AsCollection(),
		Secrets:                      mutable[*corev1.Secret](t).AsCollection(),
		Pods:                         mutable[*corev1.Pod](t).AsCollection(),
		KubernetesServices:           mutable[*corev1.Service](t).AsCollection(),
		EndpointSlices:               mutable[*discoveryv1.EndpointSlice](t).AsCollection(),
	}
	c, err := New(kube.NewFakeClient(), r, "system", testReferences(t, r, scoped),
		func(krt.HandlerContext, string) []netip.Addr { return nil }, t.Context().Done())
	assert.NoError(t, err)
	assert.Equal(t, c.results.WaitUntilSynced(t.Context().Done()), true)
	return c, r
}

func testReferences(t *testing.T, r *registry.Registry, scoped bool) *validation.ReferenceChecker {
	t.Helper()
	return validation.NewReferenceChecker(validation.ReferenceSources{
		ConfigMaps:    r.ConfigMaps,
		Secrets:       r.Secrets,
		Services:      r.KubernetesServices,
		AgentioConfig: r.AgentioConfig,
		RootNamespace: "system",
		ScopedSecrets: scoped,
	}, t.Context().Done())
}

func profileSource(t *testing.T, raw, namespace string) source {
	t.Helper()
	var spec agents.SecurityProfileSpec
	assert.NoError(t, json.Unmarshal([]byte(raw), &spec))
	kind, resource := "SecurityProfile", "securityprofiles"
	if namespace == "" {
		kind, resource = "GlobalSecurityProfile", "globalsecurityprofiles"
	}
	return *policySource(metav1.ObjectMeta{
		Name:       "test",
		Namespace:  namespace,
		UID:        "original",
		Generation: 3,
	}, kind, resource, &spec, nil)
}

func awaitResult(
	t *testing.T,
	results krt.Collection[result],
	key string,
	accepted, refs metav1.ConditionStatus,
	reason string,
) result {
	t.Helper()
	var got *result
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("last result: %+v", got)
		}
	})
	assert.EventuallyEqual(t, func() bool {
		got = results.GetKey(key)
		return got != nil && got.Conditions[0].Status == accepted &&
			got.Conditions[1].Status == refs && got.Conditions[1].Reason == reason
	}, true)
	assert.Equal(t, len(got.Conditions), 3)
	programmed := got.Conditions[2]
	assert.Equal(t, programmed.Type, "Programmed")
	assert.Equal(t, programmed.Status, accepted)
	if accepted == metav1.ConditionTrue {
		assert.Equal(t, got.Conditions[0].Message, "Configuration is valid")
		assert.Equal(t, programmed.Reason, "Programmed")
		assert.Equal(t, programmed.Message, "Configuration is ready for distribution")
	} else {
		assert.Equal(t, programmed.Reason, got.Conditions[0].Reason)
		assert.Equal(t, programmed.Message, got.Conditions[0].Message)
	}
	if refs == metav1.ConditionTrue {
		assert.Equal(t, got.Conditions[1].Reason, "ResolvedRefs")
		assert.Equal(t, got.Conditions[1].Message, "Reference checks passed")
	}
	for _, condition := range got.Conditions {
		assert.Equal(t, got.Source.Metadata.Generation, condition.ObservedGeneration)
	}
	return *got
}

func TestSharedProfileValidation(t *testing.T) {
	c, _ := testController(t, false)
	for _, tc := range []struct {
		name  string
		spec  string
		valid bool
	}{
		{"empty", `{}`, true},
		{"audit CEL uses inputs and result", `{"audit":[{"name":"log","when":"result == 'error' && inputs.config.enabled == 'true'","webhook":{"url":"http://audit"}}]}`, true},
		{"audit CEL syntax invalid", `{"audit":[{"name":"log","when":"request.","webhook":{"url":"http://audit"}}]}`, false},
		{"consumer CEL environment", `{"audit":[{"name":"log","when":"customFunction(customVariable)","webhook":{"url":"http://audit"}}]}`, true},
		{"consumer template environment", `{"audit":[{"name":"log","webhook":{"url":"http://audit/{{ customFunction .ConsumerField }}"}}]}`, true},
		{"audit JSON template invalid", `{"audit": [{"name": "log", "webhook": {"url": "http://audit", "request": {"body": {"json": {"nested": {"text": "{{"}}}}}}]}`, false},
		{"regex invalid", `{"rules":[{"name":"r","match":[{"paths":[{"type":"Regex","value":"["}]}]}]}`, false},
		{"negative priority", `{"priority":-1}`, false},
		{"input union invalid", `{"inputs":[{"name":"config","inline":{"key":"value"},"configMap":{"name":"config"}}]}`, false},
		{"callout without phases", `{"rules":[{"name":"r","actions":{"httpCallout":{"provider":{"name":"scanner"}}}}]}`, false},
		{"token template invalid", `{"rules":[{"name":"r","actions":{"tokenTransformation":{"credentialRef":{"secret":{"name":"cred"}},"apiKey":{"valueTemplate":"{{"}}}}]}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := profileSource(t, tc.spec, "demo")
			compiled := c.compileProfile(s)
			assert.Equal(t, tc.valid, compiled.Accepted.Status == metav1.ConditionTrue, compiled.Accepted.Message)
		})
	}
}

func TestProfileReferencesRecoverWithoutSpecChange(t *testing.T) {
	c, r := testController(t, false)
	maps := mutable[*corev1.ConfigMap](t)
	secrets := mutable[*corev1.Secret](t)
	r.ConfigMaps, r.Secrets = maps.AsCollection(), secrets.AsCollection()
	c.references = testReferences(t, r, false)
	s := profileSource(
		t,
		`{"inputs":[{"name":"config","configMap":{"name":"config"}}],"rules":[{"name":"auth","actions":{"tokenTransformation":{"credentialRef":{"secret":{"name":"cred"}},"apiKey":{"valueTemplate":"Bearer {{ .Token }}"}}}}]}`,
		"demo",
	)
	profiles := krt.NewStaticCollection(nil, []compiledProfile{*c.compileProfile(s)}, krt.WithStop(t.Context().Done()))
	results := krt.NewCollection(profiles, c.profileStatus, krt.WithStop(t.Context().Done()))
	got := awaitResult(t, results, s.ResourceName(), metav1.ConditionTrue, metav1.ConditionFalse, "ConfigMapNotFound")
	assert.Equal(t, got.Conditions[1].Message, `Input "config": ConfigMap demo/config not found`)
	maps.UpdateObject(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "config", Namespace: "demo"}})
	got = awaitResult(t, results, s.ResourceName(), metav1.ConditionTrue, metav1.ConditionFalse, "SecretNotFound")
	assert.Equal(t, got.Conditions[1].Message, `Rule "auth": Secret demo/cred not found`)
	secrets.UpdateObject(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "cred", Namespace: "demo"}})
	awaitResult(t, results, s.ResourceName(), metav1.ConditionTrue, metav1.ConditionTrue, reasonResolvedRefs)
	maps.DeleteObject("demo/config")
	awaitResult(t, results, s.ResourceName(), metav1.ConditionTrue, metav1.ConditionFalse, "ConfigMapNotFound")
}

func TestProfileProviderReferencesTrackAgentioConfig(t *testing.T) {
	c, r := testController(t, false)
	maps := mutable[*corev1.ConfigMap](t)
	r.AgentioConfig = config.NewCollection(maps.AsCollection(), config.Options[*configv1.AgentioConfig]{
		Namespace: "system",
		Names:     []string{"agentio-config", "agentio-config-primary"},
		Defaults:  &configv1.AgentioConfig{},
		Apply:     config.ApplyAgentioConfig,
	}, krt.WithStop(t.Context().Done())).AsCollection()
	c.references = testReferences(t, r, false)
	callout := profileSource(t, `{"rules":[{"name":"scan","actions":{
		"httpCallout":{"provider":{"name":"scanner"},"request":{}}
	}}]}`, "demo")
	oauth := profileSource(t, `{"rules":[{"name":"exchange","actions":{
		"tokenTransformation":{"type":"OAuth2","credentialRef":{"credentialProvider":{"name":"remote-binding"}},
		"oauth2":{"operation":{"resource":{}}}}
	}}]}`, "")
	profiles := krt.NewStaticCollection(nil, []compiledProfile{*c.compileProfile(callout), *c.compileProfile(oauth)},
		krt.WithStop(t.Context().Done()))
	results := krt.NewCollection(profiles, c.profileStatus, krt.WithStop(t.Context().Done()))
	got := awaitResult(
		t,
		results,
		callout.ResourceName(),
		metav1.ConditionTrue,
		metav1.ConditionFalse,
		"ProviderNotFound",
	)
	assert.Equal(t, got.Conditions[1].Message,
		`Rule "scan": HTTP callout provider "scanner" is missing`)
	awaitResult(t, results, oauth.ResourceName(), metav1.ConditionTrue, metav1.ConditionTrue, reasonResolvedRefs)

	maps.UpdateObject(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "agentio-config", Namespace: "system"},
		Data: map[string]string{"config": `extensionProviders:
- name: scanner
  httpCallout: {url: https://scanner.example}
- name: credentials
  credentialProvider: {url: https://credentials.example}
defaultProviders: {credentialProvider: credentials}
`},
	})
	awaitResult(t, results, callout.ResourceName(), metav1.ConditionTrue, metav1.ConditionTrue, reasonResolvedRefs)
	awaitResult(t, results, oauth.ResourceName(), metav1.ConditionTrue, metav1.ConditionTrue, reasonResolvedRefs)

	setPrimary := func(raw string) {
		maps.UpdateObject(&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "agentio-config-primary", Namespace: "system"},
			Data:       map[string]string{"config": raw},
		})
	}
	setPrimary(`extensionProviders:
- name: scanner
  credentialProvider: {url: https://scanner.example}
- name: credentials
  httpCallout: {url: https://credentials.example}
`)
	got = awaitResult(
		t,
		results,
		callout.ResourceName(),
		metav1.ConditionTrue,
		metav1.ConditionFalse,
		"ProviderTypeMismatch",
	)
	assert.Equal(t, got.Conditions[1].Message, `Rule "scan": provider "scanner" must be an HTTP callout provider`)
	got = awaitResult(
		t,
		results,
		oauth.ResourceName(),
		metav1.ConditionTrue,
		metav1.ConditionFalse,
		"ProviderTypeMismatch",
	)
	assert.Equal(t, got.Conditions[1].Message, `Rule "exchange": provider "credentials" must be a credential provider`)

	setPrimary("extensionProviders: []")
	awaitResult(t, results, callout.ResourceName(), metav1.ConditionTrue, metav1.ConditionFalse, "ProviderNotFound")
	got = awaitResult(t, results, oauth.ResourceName(), metav1.ConditionTrue, metav1.ConditionFalse, "ProviderNotFound")
	assert.Equal(t, got.Conditions[1].Message, `Rule "exchange": default credential provider "credentials" is missing`)

	setPrimary("defaultProviders: {credentialProvider: " + configv1.EnvironmentCredentialProviderName + "}")
	awaitResult(t, results, oauth.ResourceName(), metav1.ConditionTrue, metav1.ConditionTrue, reasonResolvedRefs)

	setPrimary("defaultProviders: {}")
	awaitResult(t, results, callout.ResourceName(), metav1.ConditionTrue, metav1.ConditionTrue, reasonResolvedRefs)
	got = awaitResult(
		t,
		results,
		oauth.ResourceName(),
		metav1.ConditionTrue,
		metav1.ConditionFalse,
		"DefaultProviderDisabled",
	)
	assert.Equal(t, got.Conditions[1].Message, `Rule "exchange": the default credential provider is disabled`)

	maps.DeleteObject("system/agentio-config-primary")
	awaitResult(t, results, oauth.ResourceName(), metav1.ConditionTrue, metav1.ConditionTrue, reasonResolvedRefs)
}

func TestProfileProgrammedTracksSpecChanges(t *testing.T) {
	for _, namespace := range []string{"demo", ""} {
		s := profileSource(t, `{}`, namespace)
		t.Run(s.Kind, func(t *testing.T) {
			c, _ := testController(t, false)
			sources := krt.NewMutableCollection(nil, []source{s}, krt.WithStop(t.Context().Done()))
			profiles := krt.NewCollection(
				sources.AsCollection(),
				func(_ krt.HandlerContext, s source) *compiledProfile {
					return c.compileProfile(s)
				},
				krt.WithStop(t.Context().Done()),
			)
			results := krt.NewCollection(profiles, c.profileStatus, krt.WithStop(t.Context().Done()))
			awaitResult(t, results, s.ResourceName(), metav1.ConditionTrue, metav1.ConditionTrue, reasonResolvedRefs)

			invalid := s
			invalid.Profile = s.Profile.DeepCopy()
			priority := int32(-1)
			invalid.Profile.Priority = &priority
			invalid.Metadata.Generation++
			sources.UpdateObject(invalid)
			awaitResult(t, results, s.ResourceName(), metav1.ConditionFalse, metav1.ConditionTrue, reasonResolvedRefs)

			s.Metadata.Generation = invalid.Metadata.Generation + 1
			sources.UpdateObject(s)
			awaitResult(t, results, s.ResourceName(), metav1.ConditionTrue, metav1.ConditionTrue, reasonResolvedRefs)
		})
	}
}

func TestProfileReferenceCheckScope(t *testing.T) {
	c, _ := testController(t, true)
	for _, tc := range []struct {
		name      string
		namespace string
		spec      string
		accepted  metav1.ConditionStatus
		status    metav1.ConditionStatus
		reason    string
	}{
		{"namespaced secret outside scope", "demo", `{"rules":[{"name":"r","actions":{"tokenTransformation":{"credentialRef":{"kind":"Secret","name":"cred"},"apiKey":{"valueTemplate":"Bearer {{ .Token }}"}}}}]}`, metav1.ConditionTrue, metav1.ConditionFalse, "RefNotPermitted"},
		{"global explicit secret outside scope", "", `{"rules":[{"name":"r","actions":{"tokenTransformation":{"credentialRef":{"secret":{"name":"cred","namespace":"demo"}}}}}]}`, metav1.ConditionTrue, metav1.ConditionFalse, "RefNotPermitted"},
		{"global implicit secret", "", `{"rules":[{"name":"r","actions":{"tokenTransformation":{"credentialRef":{"secret":{"name":"cred"}},"apiKey":{"valueTemplate":"Bearer {{ .Token }}"}}}}]}`, metav1.ConditionTrue, metav1.ConditionTrue, reasonResolvedRefs},
		{"credential provider", "demo", `{"rules":[{"name":"r","actions":{"tokenTransformation":{"credentialRef":{"credentialProvider":{"name":"provider"}},"apiKey":{"valueTemplate":"Bearer {{ .Token }}"}}}}]}`, metav1.ConditionTrue, metav1.ConditionTrue, reasonResolvedRefs},
		{"callout", "demo", `{"rules":[{"name":"r","actions":{"httpCallout":{"provider":{"name":"scanner"},"request":{}}}}]}`, metav1.ConditionTrue, metav1.ConditionFalse, "ProviderNotFound"},
		{"disabled transform", "demo", `{"rules":[{"name":"r","actions":{"tokenTransformation":{"disabled":true}}}]}`, metav1.ConditionTrue, metav1.ConditionTrue, reasonResolvedRefs},
		{"invalid global configmap", "", `{"inputs":[{"name":"config","configMap":{"name":"config"}}]}`, metav1.ConditionFalse, metav1.ConditionTrue, reasonResolvedRefs},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := profileSource(t, tc.spec, tc.namespace)
			profiles := krt.NewStaticCollection(
				nil,
				[]compiledProfile{*c.compileProfile(s)},
				krt.WithStop(t.Context().Done()),
			)
			results := krt.NewCollection(profiles, c.profileStatus, krt.WithStop(t.Context().Done()))
			got := awaitResult(t, results, s.ResourceName(), tc.accepted, tc.status, tc.reason)
			if tc.reason == "RefNotPermitted" {
				assert.Equal(
					t,
					got.Conditions[1].Message,
					`Rule "r": Secret demo/cred is outside the permitted namespace system`,
				)
			}
		})
	}
}

func TestTrafficReferencesAndValidation(t *testing.T) {
	c, r := testController(t, false)
	services := mutable[*corev1.Service](t)
	r.KubernetesServices = services.AsCollection()
	c.references = testReferences(t, r, false)
	c.traffic.Services = r.KubernetesServices
	var spec agents.TrafficPolicySpec
	assert.NoError(
		t,
		json.Unmarshal(
			[]byte(
				`{"egress":{"rules":[{"action":"allow","to":[{"service":{"name":"api"}},{"fqdn":"api.example.com"}]}]}}`,
			),
			&spec,
		),
	)
	s := *policySource(metav1.ObjectMeta{Name: "test", Namespace: "demo", Generation: 3}, "TrafficPolicy", "trafficpolicies", nil, &spec)
	sources := krt.NewMutableCollection(nil, []source{s}, krt.WithStop(t.Context().Done()))
	results := krt.NewCollection(sources.AsCollection(), c.trafficStatus, krt.WithStop(t.Context().Done()))
	awaitResult(t, results, s.ResourceName(), metav1.ConditionTrue, metav1.ConditionFalse, "ServiceNotFound")
	services.UpdateObject(&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "demo"}})
	// The fixture's DNS resolver still returns no addresses.
	awaitResult(t, results, s.ResourceName(), metav1.ConditionTrue, metav1.ConditionTrue, reasonResolvedRefs)
	invalid := spec.DeepCopy()
	invalid.Priority = -1
	s.Traffic = invalid
	sources.UpdateObject(s)
	awaitResult(t, results, s.ResourceName(), metav1.ConditionFalse, metav1.ConditionTrue, reasonResolvedRefs)
}

func TestTrafficProgrammedTracksSpecChanges(t *testing.T) {
	for _, namespace := range []string{"demo", ""} {
		kind, resource := "TrafficPolicy", "trafficpolicies"
		if namespace == "" {
			kind, resource = "GlobalTrafficPolicy", "globaltrafficpolicies"
		}
		t.Run(kind, func(t *testing.T) {
			c, _ := testController(t, false)
			s := *policySource(metav1.ObjectMeta{Name: "test", Namespace: namespace, Generation: 3},
				kind, resource, nil, &agents.TrafficPolicySpec{})
			sources := krt.NewMutableCollection(nil, []source{s}, krt.WithStop(t.Context().Done()))
			results := krt.NewCollection(sources.AsCollection(), c.trafficStatus, krt.WithStop(t.Context().Done()))
			awaitResult(t, results, s.ResourceName(), metav1.ConditionTrue, metav1.ConditionTrue, reasonResolvedRefs)

			invalid := s
			invalid.Traffic = s.Traffic.DeepCopy()
			invalid.Traffic.Priority = -1
			invalid.Metadata.Generation++
			sources.UpdateObject(invalid)
			awaitResult(t, results, s.ResourceName(), metav1.ConditionFalse, metav1.ConditionTrue, reasonResolvedRefs)

			s.Metadata.Generation = invalid.Metadata.Generation + 1
			sources.UpdateObject(s)
			awaitResult(t, results, s.ResourceName(), metav1.ConditionTrue, metav1.ConditionTrue, reasonResolvedRefs)
		})
	}
}

func TestSourcesExcludeStatusUpdates(t *testing.T) {
	_, r := testController(t, false)
	profiles := mutable[*agents.SecurityProfile](t)
	globals := mutable[*agents.GlobalSecurityProfile](t)
	traffic := mutable[*agents.TrafficPolicy](t)
	globalTraffic := mutable[*agents.GlobalTrafficPolicy](t)
	r.SecurityProfileObjects, r.GlobalSecurityProfileObjects = profiles.AsCollection(), globals.AsCollection()
	r.TrafficPolicyObjects, r.GlobalTrafficPolicyObjects = traffic.AsCollection(), globalTraffic.AsCollection()
	sources := newSources(r, krt.NewOptionsBuilder(t.Context().Done(), "test", nil))
	globalMeta := metav1.ObjectMeta{Name: "test", Generation: 1}
	meta := globalMeta
	meta.Namespace = "demo"
	profiles.UpdateObject(&agents.SecurityProfile{ObjectMeta: meta})
	globals.UpdateObject(&agents.GlobalSecurityProfile{ObjectMeta: globalMeta})
	traffic.UpdateObject(&agents.TrafficPolicy{ObjectMeta: meta})
	globalTraffic.UpdateObject(&agents.GlobalTrafficPolicy{ObjectMeta: globalMeta})
	assert.EventuallyEqual(t, func() bool { return len(sources.List()) == 4 }, true)
	controller, err := New(kube.NewFakeClient(), r, "system", testReferences(t, r, false),
		func(krt.HandlerContext, string) []netip.Addr { return nil }, t.Context().Done())
	assert.NoError(t, err)
	for _, key := range []string{"securityprofiles/demo/test", "globalsecurityprofiles//test", "trafficpolicies/demo/test", "globaltrafficpolicies//test"} {
		awaitResult(
			t,
			controller.results,
			key,
			metav1.ConditionTrue,
			metav1.ConditionTrue,
			reasonResolvedRefs,
		)
	}
	before := sources.GetKey("securityprofiles/demo/test")
	meta.ResourceVersion = "2"
	profiles.UpdateObject(&agents.SecurityProfile{
		ObjectMeta: meta,
		Status:     agents.SecurityProfileStatus{ObservedGeneration: 1},
	})
	// Read the projected source after the input update: metadata used by validation stays identical.
	after := policySource(meta, "SecurityProfile", "securityprofiles", &agents.SecurityProfileSpec{}, nil)
	assert.Equal(t, before.Equals(*after), true)
}

func TestWriterStopsAndReplaysOnRestart(t *testing.T) {
	c, _ := testController(t, false)
	s := profileSource(t, `{}`, "demo")
	c.results = krt.NewStaticCollection(nil, []result{{Source: s}}, krt.WithStop(t.Context().Done()))
	// Missing objects are harmless; each new leader must replay the current collection.
	for i := range 2 {
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			c.runWriter(ctx)
			close(done)
		}()
		assert.EventuallyEqual(t, func() bool {
			return len(c.client.Dynamic().(*dynamicfake.FakeDynamicClient).Actions()) > i
		}, true)
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("writer did not stop")
		}
	}
}

func TestSecretCacheSynchronizationUpdatesStatus(t *testing.T) {
	c, r := testController(t, false)
	synced := krt.NewStatic[bool](nil, false, krt.WithStop(t.Context().Done()))
	r.Secrets = krt.NewStaticCollection[*corev1.Secret](synced.AsCollection(), nil, krt.WithStop(t.Context().Done()))
	c.references = testReferences(t, r, false)
	s := profileSource(
		t,
		`{"rules":[{"name":"r","actions":{"tokenTransformation":{"credentialRef":{"secret":{"name":"cred"}},"apiKey":{"valueTemplate":"Bearer {{ .Token }}"}}}}]}`,
		"demo",
	)
	profiles := krt.NewStaticCollection(nil, []compiledProfile{*c.compileProfile(s)}, krt.WithStop(t.Context().Done()))
	results := krt.NewCollection(profiles, c.profileStatus, krt.WithStop(t.Context().Done()))
	awaitResult(t, results, s.ResourceName(), metav1.ConditionTrue, metav1.ConditionTrue, reasonResolvedRefs)
	synced.MarkSynced()
	awaitResult(t, results, s.ResourceName(), metav1.ConditionTrue, metav1.ConditionFalse, "SecretNotFound")
}
