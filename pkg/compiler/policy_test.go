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
	"net/netip"
	"reflect"
	"slices"
	"testing"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	securityv1 "github.com/openkruise/agentio/api/security/v1"
	workloadv1 "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	policypkg "github.com/openkruise/agentio/pkg/policy"
)

func TestSandboxSubjectUsesExplicitSandboxSelectorMetadata(t *testing.T) {
	workload := model.Workload{
		Namespace: "workload-namespace",
		Labels:    map[string]string{"source": "workload"},
		Addresses: []string{"10.0.0.1"},
		Ready:     true,
	}
	binding := model.SandboxBinding{SandboxUID: "sandbox-a"}

	implicit := sandboxSubject(workload, binding, nil)
	if implicit.Namespace != workload.Namespace || !reflect.DeepEqual(implicit.Labels, workload.Labels) {
		t.Fatalf("implicit Sandbox selector metadata = namespace %q labels %v, want Workload fallback",
			implicit.Namespace, implicit.Labels)
	}

	explicit := sandboxSubject(workload, binding, &model.Sandbox{
		UID:       binding.SandboxUID,
		Namespace: "sandbox-namespace",
		Labels:    map[string]string{"source": "sandbox"},
	})
	if explicit.Namespace != "sandbox-namespace" || !reflect.DeepEqual(explicit.Labels, map[string]string{"source": "sandbox"}) {
		t.Fatalf("explicit Sandbox selector metadata = namespace %q labels %v", explicit.Namespace, explicit.Labels)
	}
	if !reflect.DeepEqual(explicit.Addresses, workload.Addresses) || explicit.Ready != workload.Ready {
		t.Fatalf("explicit Sandbox lost Workload runtime state: %+v", explicit)
	}

	empty := sandboxSubject(workload, binding, &model.Sandbox{UID: binding.SandboxUID})
	if empty.Namespace != "" || empty.Labels != nil {
		t.Fatalf("explicit empty Sandbox inherited Workload selector metadata: %+v", empty)
	}
}

func TestWorkloadPeerResolutionUsesPodMetadata(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}

	bound := testWorkload("demo", "bound", "10.1.0.3")
	bound.SandboxBindings[0].SandboxUID = "sandbox-bound"
	bound.Labels = map[string]string{"role": "not-peer"}

	agentioConfig := krt.NewStaticCollection[model.AgentioConfiguration](nil, nil, options...)
	inputs := validCompilerInputs(stop)
	inputs.Sandboxes = krt.NewStaticCollection(nil, []model.Sandbox{{
		UID:       "sandbox-bound",
		Namespace: "sandbox-namespace",
		Labels:    map[string]string{"role": "not-peer"},
	}}, options...)
	inputs.Workloads = krt.NewStaticCollection(nil, []model.Workload{bound}, options...)
	inputs.Pods = krt.NewStaticCollection(nil, []*corev1.Pod{{
		ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "bound", Labels: map[string]string{"role": "peer"}},
		Status: corev1.PodStatus{
			PodIP:      "10.1.0.3",
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
		},
	}}, options...)
	inputs.Gateways = testGatewaySource(agentioConfig, options...)
	inputs.TrafficPolicies = krt.NewStaticCollection(nil, []model.TrafficPolicy{{
		Name: "allow-peers", Namespace: "demo",
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionAllow,
				To: []agentsv1alpha1.TrafficPolicyPeer{{Workload: &agentsv1alpha1.TrafficPolicyWorkloadRef{
					Namespace: "demo",
					Selector:  map[string]string{"role": "peer"},
				}}},
			}}},
		},
	}}, options...)
	inputs.AgentioConfig = agentioConfig
	compiler, err := New(inputs, krt.NewOptionsBuilder(stop, "", nil))
	if err != nil {
		t.Fatalf("new compiler: %v", err)
	}

	snapshot := compileSynced(t, compiler)
	resource, found := snapshot.Get(model.ResourceKey{
		TypeURL: model.WorkloadAuthorizationType,
		Name:    "demo/allow-peers-egress",
	})
	if !found {
		t.Fatal("compiled Authorization resource not found")
	}
	authorization := &securityv1.Authorization{}
	if err := proto.Unmarshal(resource.Value.GetValue(), authorization); err != nil {
		t.Fatalf("unmarshal Authorization: %v", err)
	}

	addresses := map[string]struct{}{}
	for _, group := range authorization.GetGroups() {
		for _, rule := range group.GetRules() {
			for _, match := range rule.GetMatches() {
				for _, address := range match.GetDestinationIps() {
					parsed, ok := netip.AddrFromSlice(address.GetAddress())
					if ok {
						addresses[netip.PrefixFrom(parsed, int(address.GetLength())).String()] = struct{}{}
					}
				}
			}
		}
	}
	for _, want := range []string{"10.1.0.3/32"} {
		if _, found := addresses[want]; !found {
			t.Fatalf("Workload peer addresses = %v, missing %s", addresses, want)
		}
	}
}

func TestCompilerPublishesWorkloadsWithoutAttestablePrincipalAndResolvesTrafficPolicyPeers(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}

	withoutServiceAccount := testWorkload("demo", "static-control-plane", "10.1.0.9")
	withoutServiceAccount.Labels = map[string]string{"role": "control-plane"}
	withoutServiceAccount.Principal.ServiceAccount.ServiceAccount = ""
	withoutPrincipal := testWorkload("demo", "opaque-endpoint", "10.1.0.10")
	withoutPrincipal.Labels = map[string]string{"role": "control-plane"}
	withoutPrincipal.Principal = model.Principal{}
	workloads := []model.Workload{withoutServiceAccount, withoutPrincipal}

	inputs := validCompilerInputs(stop)
	inputs.Workloads = krt.NewStaticCollection(nil, workloads, options...)
	inputs.Pods = krt.NewStaticCollection(nil, []*corev1.Pod{
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "static-control-plane", Labels: map[string]string{"role": "control-plane"}},
			Status: corev1.PodStatus{PodIP: "10.1.0.9", Conditions: []corev1.PodCondition{{
				Type: corev1.PodReady, Status: corev1.ConditionTrue,
			}}},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "opaque-endpoint", Labels: map[string]string{"role": "control-plane"}},
			Status: corev1.PodStatus{PodIP: "10.1.0.10", Conditions: []corev1.PodCondition{{
				Type: corev1.PodReady, Status: corev1.ConditionTrue,
			}}},
		},
	}, options...)
	inputs.TrafficPolicies = krt.NewStaticCollection(nil, []model.TrafficPolicy{{
		Name: "allow-control-plane", Namespace: "demo",
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionAllow,
				To: []agentsv1alpha1.TrafficPolicyPeer{{Workload: &agentsv1alpha1.TrafficPolicyWorkloadRef{
					Namespace: "demo",
					Selector:  map[string]string{"role": "control-plane"},
				}}},
			}}},
		},
	}}, options...)

	compiler, err := New(inputs, krt.NewOptionsBuilder(stop, "", nil))
	if err != nil {
		t.Fatalf("new compiler: %v", err)
	}
	snapshot := compileSynced(t, compiler)

	for _, workload := range workloads {
		workloadResource, found := snapshot.Get(model.ResourceKey{TypeURL: model.AddressType, Name: workload.UID})
		if !found {
			t.Fatalf("WDS Address for unattestable workload %q is missing", workload.UID)
		}
		address := &workloadv1.Address{}
		if err := workloadResource.Value.UnmarshalTo(address); err != nil {
			t.Fatalf("unmarshal WDS Address %q: %v", workload.UID, err)
		}
		if got := address.GetWorkload().GetServiceAccount(); got != "" {
			t.Fatalf("WDS ServiceAccount for %q = %q, want omitted", workload.UID, got)
		}
	}

	authorizationResource, found := snapshot.Get(model.ResourceKey{
		TypeURL: model.WorkloadAuthorizationType,
		Name:    "demo/allow-control-plane-egress",
	})
	if !found {
		t.Fatal("compiled TrafficPolicy Authorization is missing")
	}
	authorization := &securityv1.Authorization{}
	if err := proto.Unmarshal(authorizationResource.Value.GetValue(), authorization); err != nil {
		t.Fatalf("unmarshal Authorization: %v", err)
	}
	got := map[netip.Prefix]struct{}{}
	for _, group := range authorization.GetGroups() {
		for _, rule := range group.GetRules() {
			for _, match := range rule.GetMatches() {
				for _, candidate := range match.GetDestinationIps() {
					address, ok := netip.AddrFromSlice(candidate.GetAddress())
					if ok {
						got[netip.PrefixFrom(address, int(candidate.GetLength()))] = struct{}{}
					}
				}
			}
		}
	}
	for _, want := range []netip.Prefix{
		netip.MustParsePrefix("10.1.0.9/32"),
		netip.MustParsePrefix("10.1.0.10/32"),
	} {
		if _, found := got[want]; !found {
			t.Fatalf("TrafficPolicy Workload peers = %v, missing %s", got, want)
		}
	}
}

func TestCompilerPublishesTrafficPolicyAndWorkloadReference(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	workloads := krt.NewStaticCollection[model.Workload](nil, nil, options...)
	services := krt.NewStaticCollection[model.Service](nil, nil, options...)
	endpoints := krt.NewStaticCollection[model.Endpoint](nil, nil, options...)
	trafficPolicies := krt.NewStaticCollection[model.TrafficPolicy](nil, nil, options...)
	securityProfiles := krt.NewStaticCollection[model.SecurityProfile](nil, nil, options...)
	agentioConfig := krt.NewStaticCollection[model.AgentioConfiguration](nil, nil, options...)
	workloads.ConditionalUpdateObject(testWorkload("demo", "client", "10.1.0.2"))
	trafficPolicies.ConditionalUpdateObject(model.TrafficPolicy{Name: "allow", Namespace: "demo", Spec: agentsv1alpha1.TrafficPolicySpec{
		Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
		Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
			Action: agentsv1alpha1.RuleActionAllow, To: []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "203.0.113.0/24"}},
		}}},
	}})

	inputs := validCompilerInputs(stop)
	inputs.Workloads = workloads
	inputs.Services = services
	inputs.Endpoints = endpoints
	inputs.Gateways = testGatewaySource(agentioConfig, options...)
	inputs.TrafficPolicies = trafficPolicies
	inputs.SecurityProfiles = securityProfiles
	inputs.AgentioConfig = agentioConfig
	compiler, err := New(inputs, krt.NewOptionsBuilder(stop, "", nil))
	if err != nil {
		t.Fatalf("new compiler: %v", err)
	}
	snapshot := compileSynced(t, compiler)
	authorizationResource, found := snapshot.Get(model.ResourceKey{
		TypeURL: model.WorkloadAuthorizationType,
		Name:    "demo/allow-egress",
	})
	if !found {
		t.Fatal("compiled Authorization resource not found")
	}
	authorization := &securityv1.Authorization{}
	// Unmarshal the raw bytes: the wire type URL differs from the local descriptor.
	if got := authorizationResource.Value.GetTypeUrl(); got != model.WorkloadAuthorizationType {
		t.Fatalf("authorization type URL = %q, want %q", got, model.WorkloadAuthorizationType)
	}
	if err := proto.Unmarshal(authorizationResource.Value.GetValue(), authorization); err != nil {
		t.Fatalf("unmarshal Authorization: %v", err)
	}
	if authorization.GetName() != "allow-egress" {
		t.Fatalf("authorization name = %q", authorization.GetName())
	}
	workloadResource, found := snapshot.Get(model.ResourceKey{
		TypeURL: model.AddressType,
		Name:    "cluster//Pod/demo/client",
	})
	if !found {
		t.Fatal("compiled Workload resource not found")
	}
	address := &workloadv1.Address{}
	if err := workloadResource.Value.UnmarshalTo(address); err != nil {
		t.Fatalf("unmarshal Workload: %v", err)
	}
	got := address.GetWorkload().GetAuthorizationPolicies()
	if len(got) != 1 || got[0] != "demo/allow-egress" {
		t.Fatalf("workload authorization policies = %v", got)
	}
	if workloadResource.Facts.Workload == nil ||
		!slices.Contains(workloadResource.Facts.Workload.AuthorizationRefs, "demo/allow-egress") {
		t.Fatalf("workload facts do not index the exact Authorization reference: %+v", workloadResource.Facts)
	}
}

func TestAuthorizationResourceCarriesScopeFacts(t *testing.T) {
	tests := []struct {
		name          string
		source        model.TrafficPolicy
		authorization *securityv1.Authorization
		want          model.AuthorizationResourceFacts
	}{
		{
			name:   "global",
			source: model.TrafficPolicy{Name: "global", Namespace: "agentio-system", Global: true},
			authorization: &securityv1.Authorization{
				Name: "global-egress", Namespace: "agentio-system", Scope: securityv1.Scope_GLOBAL,
			},
			want: model.AuthorizationResourceFacts{Scope: model.AuthorizationScopeGlobal},
		},
		{
			name:   "namespace",
			source: model.TrafficPolicy{Name: "namespace", Namespace: "demo"},
			authorization: &securityv1.Authorization{
				Name: "namespace-egress", Namespace: "demo", Scope: securityv1.Scope_NAMESPACE,
			},
			want: model.AuthorizationResourceFacts{Scope: model.AuthorizationScopeNamespace, Namespace: "demo"},
		},
		{
			name:   "selector",
			source: model.TrafficPolicy{Name: "selector", Namespace: "demo"},
			authorization: &securityv1.Authorization{
				Name: "selector-egress", Namespace: "demo", Scope: securityv1.Scope_WORKLOAD_SELECTOR,
			},
			want: model.AuthorizationResourceFacts{Scope: model.AuthorizationScopeWorkload},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resource, err := authorizationResource(policypkg.CompiledAuthorization{
				Name: test.authorization.GetNamespace() + "/" + test.authorization.GetName(), Policy: test.authorization,
			})
			if err != nil {
				t.Fatal(err)
			}
			if resource.Facts.Authorization == nil || *resource.Facts.Authorization != test.want {
				t.Fatalf("Authorization facts = %+v, want %+v", resource.Facts.Authorization, test.want)
			}
		})
	}
}

func TestCompilerResolvesInlineSNIProfile(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	workloads := krt.NewStaticCollection[model.Workload](nil, nil, options...)
	services := krt.NewStaticCollection[model.Service](nil, nil, options...)
	endpoints := krt.NewStaticCollection[model.Endpoint](nil, nil, options...)
	trafficPolicies := krt.NewStaticCollection[model.TrafficPolicy](nil, nil, options...)
	securityProfiles := krt.NewStaticCollection[model.SecurityProfile](nil, nil, options...)
	agentioConfig := krt.NewStaticCollection[model.AgentioConfiguration](nil, nil, options...)
	workload := testWorkload("demo", "client", "10.1.0.2")
	workloads.ConditionalUpdateObject(workload)
	securityProfiles.ConditionalUpdateObject(model.SecurityProfile{Name: "terminate", Namespace: "demo", Spec: agentsv1alpha1.SecurityProfileSpec{
		Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "does-not-match"}},
		Rules:    []agentsv1alpha1.SecurityRule{{Name: "api", Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"api.example.com"}}}}},
	}})
	agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{Value: &configv1.AgentioConfig{
		EgressPolicies: []*extensionsv1.EgressPolicy{{Policy: extensionsv1.EgressPolicyAction_DENY}},
	}})
	inputs := validCompilerInputs(stop)
	inputs.Sandboxes = krt.NewStaticCollection(nil, []model.Sandbox{{
		UID: workload.SandboxBindings[0].SandboxUID,
		PolicyRefs: []model.PolicyRef{{
			Kind: model.PolicyKindSNIPolicy,
			Name: "demo/terminate",
		}},
	}}, options...)
	inputs.Workloads = workloads
	inputs.Services = services
	inputs.Endpoints = endpoints
	inputs.Gateways = testGatewaySource(agentioConfig, options...)
	inputs.TrafficPolicies = trafficPolicies
	inputs.SecurityProfiles = securityProfiles
	inputs.AgentioConfig = agentioConfig
	compiler, err := New(inputs, krt.NewOptionsBuilder(stop, "", nil))
	if err != nil {
		t.Fatalf("new compiler: %v", err)
	}
	snapshot := compileSynced(t, compiler)
	if _, found := snapshot.Get(model.ResourceKey{
		TypeURL: model.SniTrafficPolicyType,
		Name:    "demo/terminate",
	}); found {
		t.Fatal("independent SNI resource must not be published")
	}
	workloadResource, _ := snapshot.Get(model.ResourceKey{
		TypeURL: model.AddressType,
		Name:    "cluster//Pod/demo/client",
	})
	address := &workloadv1.Address{}
	if err := workloadResource.Value.UnmarshalTo(address); err != nil {
		t.Fatalf("unmarshal Workload: %v", err)
	}
	if got := extensionNames(address.GetWorkload().GetExtensions()); !reflect.DeepEqual(got, []string{"workload-metadata", "egress-policies", "sandbox-bindings"}) {
		t.Fatalf("Address workload extensions = %v, want metadata, ztunnel egress policy, and sandbox bindings", got)
	}
	if _, found := snapshot.Get(model.ResourceKey{TypeURL: model.WorkloadType, Name: "cluster//Pod/demo/client"}); found {
		t.Fatal("compiler retained a direct Workload resource")
	}
	if payload := compiler.SNIPolicy(workload.SandboxBindings[0].SandboxUID); payload == nil || len(payload.Rules) != 1 {
		t.Fatalf("inline SNI payload = %v", payload)
	}
	binding := compiler.SandboxPolicyBindings().GetKey(workload.SandboxBindings[0].SandboxUID)
	if binding == nil || !reflect.DeepEqual(binding.PolicyNames(policypkg.PolicyKindSNIPolicy), []string{"demo/terminate"}) {
		t.Fatalf("Sandbox policy binding = %+v", binding)
	}
}

func TestCompilerOmitsWorkloadWithUnresolvedSandboxPolicyReference(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	workload := testWorkload("demo", "client", "10.1.0.2")
	inputs := validCompilerInputs(stop)
	inputs.Workloads = krt.NewStaticCollection(nil, []model.Workload{workload}, options...)
	inputs.Sandboxes = krt.NewStaticCollection(nil, []model.Sandbox{{
		UID: workload.SandboxBindings[0].SandboxUID,
		PolicyRefs: []model.PolicyRef{{
			Kind: model.PolicyKindSNIPolicy, Name: "demo/missing",
		}},
	}}, options...)

	compiler, err := New(inputs, krt.NewOptionsBuilder(stop, "", nil))
	if err != nil {
		t.Fatal(err)
	}
	waitSynced(t, compiler)
	snapshot, err := compiler.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if _, found := snapshot.Get(model.ResourceKey{
		TypeURL: model.AddressType,
		Name:    workload.UID,
	}); found {
		t.Fatal("canonical Address was published with an unresolved policy reference")
	}
	failures := compiler.Failures()
	if _, found := failures["Sandbox/"+workload.SandboxBindings[0].SandboxUID]; !found {
		t.Fatalf("Sandbox failure is missing: %v", failures)
	}
	if _, found := failures["WDSWorkload/"+workload.UID]; !found {
		t.Fatalf("WDS Workload failure is missing: %v", failures)
	}
}

func TestCompilerPublishesPerSandboxEgressPolicies(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	workloads := krt.NewStaticCollection(nil, []model.Workload{
		testWorkload("demo-a", "client", "10.1.0.2"),
		testWorkload("demo-b", "client", "10.2.0.2"),
		testWorkload("other", "client", "10.3.0.2"),
	}, options...)
	config := krt.NewStaticCollection[model.AgentioConfiguration](nil, []model.AgentioConfiguration{{
		Value: &configv1.AgentioConfig{EgressPolicies: []*extensionsv1.EgressPolicy{
			{Namespaces: []string{"demo-a"}, MatchCidrs: []string{"203.0.113.1/32"}, Policy: extensionsv1.EgressPolicyAction_GATEWAY,
				Gateway: &extensionsv1.GatewayAddress{Service: "egress-a.agentio-system.svc.cluster.local", Port: 15008}},
			{Namespaces: []string{"demo-a"}, MatchCidrs: []string{"203.0.113.2/32"}, Policy: extensionsv1.EgressPolicyAction_GATEWAY,
				Gateway: &extensionsv1.GatewayAddress{Service: "egress-a.agentio-system.svc.cluster.local", Port: 15008}},
			{Namespaces: []string{"demo-b"}, MatchCidrs: []string{"198.51.100.1/32"}, Policy: extensionsv1.EgressPolicyAction_GATEWAY,
				Gateway: &extensionsv1.GatewayAddress{Service: "egress-b.agentio-system.svc.cluster.local", Port: 15008}},
			{Namespaces: []string{"demo-b"}, MatchCidrs: []string{"198.51.100.2/32"}, Policy: extensionsv1.EgressPolicyAction_DENY},
		}},
	}}, options...)
	emptyServices := krt.NewStaticCollection[model.Service](nil, nil, options...)
	emptyEndpoints := krt.NewStaticCollection[model.Endpoint](nil, nil, options...)
	emptyTrafficPolicies := krt.NewStaticCollection[model.TrafficPolicy](nil, nil, options...)
	emptySecurity := krt.NewStaticCollection[model.SecurityProfile](nil, nil, options...)
	inputs := validCompilerInputs(stop)
	inputs.Workloads = workloads
	inputs.Services = emptyServices
	inputs.Endpoints = emptyEndpoints
	inputs.Gateways = testGatewaySource(config, options...)
	inputs.TrafficPolicies = emptyTrafficPolicies
	inputs.SecurityProfiles = emptySecurity
	inputs.AgentioConfig = config
	compiler, err := New(inputs, krt.NewOptionsBuilder(stop, "", nil))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := compileSynced(t, compiler)

	tests := []struct {
		uid          string
		wantPolicies int
		wantGateway  string
	}{
		{
			uid:          "cluster//Pod/demo-a/client",
			wantPolicies: 2,
			wantGateway:  "agentio-system/egress-a",
		},
		{
			uid:          "cluster//Pod/demo-b/client",
			wantPolicies: 2,
			wantGateway:  "agentio-system/egress-b",
		},
		{
			uid: "cluster//Pod/other/client",
		},
	}
	for _, test := range tests {
		resource, found := snapshot.Get(model.ResourceKey{TypeURL: model.AddressType, Name: test.uid})
		if !found {
			t.Fatalf("Address %s is missing", test.uid)
		}
		address := &workloadv1.Address{}
		if err := resource.Value.UnmarshalTo(address); err != nil {
			t.Fatal(err)
		}
		var effective *extensionsv1.EgressPolicies
		for _, extension := range address.GetWorkload().GetExtensions() {
			if extension.GetName() != "egress-policies" {
				continue
			}
			effective = &extensionsv1.EgressPolicies{}
			if err := extension.GetConfig().UnmarshalTo(effective); err != nil {
				t.Fatal(err)
			}
		}
		if test.wantPolicies == 0 {
			if effective != nil {
				t.Fatalf("%s received unrelated egress policies: %+v", test.uid, effective)
			}
			continue
		}
		if got := len(effective.GetEgressPolicies()); got != test.wantPolicies {
			t.Fatalf("%s policy count = %d, want %d", test.uid, got, test.wantPolicies)
		}
		if resource.Facts.Workload == nil ||
			!slices.Contains(resource.Facts.Workload.GatewayReferences, test.wantGateway) {
			t.Fatalf("%s facts = %+v, missing Gateway reference %s", test.uid, resource.Facts, test.wantGateway)
		}
		count := 0
		for _, current := range resource.Facts.Workload.GatewayReferences {
			if current == test.wantGateway {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("%s Gateway reference count = %d, want 1", test.uid, count)
		}
	}
}
