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

package policy

import (
	"net/netip"
	"strings"
	"testing"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

func testTrafficPolicyInputs(
	rootNamespace string,
	services krt.Collection[*corev1.Service],
	endpointSlices krt.Collection[*discoveryv1.EndpointSlice],
	pods krt.Collection[*corev1.Pod],
	resolve func(string) []netip.Addr,
) TrafficPolicyInputs {
	if services == nil {
		services = krt.NewStaticCollection[*corev1.Service](nil, nil)
	}
	if endpointSlices == nil {
		endpointSlices = krt.NewStaticCollection[*discoveryv1.EndpointSlice](nil, nil)
	}
	if pods == nil {
		pods = krt.NewStaticCollection[*corev1.Pod](nil, nil)
	}
	var hostnameResolver HostnameResolver
	if resolve != nil {
		hostnameResolver = func(_ krt.HandlerContext, host string) []netip.Addr { return resolve(host) }
	}
	return TrafficPolicyInputs{
		RootNamespace:  rootNamespace,
		Services:       services,
		EndpointSlices: endpointSlices,
		Pods:           pods,
		ServicesByNamespace: krt.NewIndex(services, "testServicesByNamespace",
			func(service *corev1.Service) []string { return []string{service.Namespace} }),
		EndpointSlicesByService: krt.NewIndex(endpointSlices, "testEndpointSlicesByService",
			func(slice *discoveryv1.EndpointSlice) []string {
				serviceName, found := slice.Labels[discoveryv1.LabelServiceName]
				if !found {
					return nil
				}
				return []string{slice.Namespace + "/" + serviceName}
			}),
		PodsByNamespace: krt.NewIndex(pods, "testPodsByNamespace",
			func(pod *corev1.Pod) []string { return []string{pod.Namespace} }),
		Resolve: hostnameResolver,
	}
}

func TestCompileTrafficPolicySandboxUIDAssociation(t *testing.T) {
	inputs := testTrafficPolicyInputs("agentio-system", nil, nil, nil, nil)
	for _, test := range []struct {
		name        string
		declaredUID string
		selectedUID *string
		wantUID     string
		wantErr     bool
	}{
		{name: "declared UID", declaredUID: "sandbox-a", wantUID: "sandbox-a"},
		{name: "selector UID", selectedUID: stringPtr("sandbox-a"), wantUID: "sandbox-a"},
		{name: "equal declarations", declaredUID: "sandbox-a", selectedUID: stringPtr("sandbox-a"), wantUID: "sandbox-a"},
		{name: "conflicting declarations", declaredUID: "sandbox-a", selectedUID: stringPtr("sandbox-b"), wantErr: true},
		{name: "declared whitespace", declaredUID: " sandbox-a", wantErr: true},
		{name: "selector whitespace", selectedUID: stringPtr(" "), wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			selector := metav1.LabelSelector{}
			if test.selectedUID != nil {
				selector.MatchLabels = map[string]string{agentsv1alpha1.LabelSandboxID: *test.selectedUID}
			}
			compiled, err := CompileTrafficPolicy(krt.TestingDummyContext{}, model.TrafficPolicy{
				Name: "allow", Namespace: "demo", SandboxUID: test.declaredUID,
				Spec: agentsv1alpha1.TrafficPolicySpec{
					Selector: selector,
					Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
						Action: agentsv1alpha1.RuleActionAllow,
						To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "10.0.0.0/24"}},
					}}},
				},
			}, inputs)
			if test.wantErr {
				if err == nil || !strings.Contains(err.Error(), "sandbox UID") {
					t.Fatalf("CompileTrafficPolicy() error = %v, want sandbox UID error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("CompileTrafficPolicy(): %v", err)
			}
			if len(compiled) != 1 {
				t.Fatalf("compiled policies = %d, want 1", len(compiled))
			}
			attachment := compiled[0].PolicyAttachment()
			if attachment == nil || attachment.Target.SandboxUID != test.wantUID {
				t.Fatalf("attachment = %+v, want exact Sandbox UID %q", attachment, test.wantUID)
			}
			if got := compiled[0].Policy.GetScope(); got != securityv1.Scope_WORKLOAD_SELECTOR {
				t.Fatalf("Authorization scope = %v, want WORKLOAD_SELECTOR", got)
			}
		})
	}
}

func stringPtr(value string) *string { return &value }

func TestCompileTrafficPolicyResolvesPeersAndPreservesDirection(t *testing.T) {
	start, end := int32(8080), int32(8090)
	compiled, err := CompileTrafficPolicies(krt.TestingDummyContext{}, []model.TrafficPolicy{{
		Name: "api", Namespace: "demo", Spec: agentsv1alpha1.TrafficPolicySpec{
			Priority: 500, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionAllow,
				From:   []agentsv1alpha1.TrafficPolicyPeer{{Workload: &agentsv1alpha1.TrafficPolicyWorkloadRef{Namespace: "demo", Selector: map[string]string{"role": "source"}}}},
				To: []agentsv1alpha1.TrafficPolicyPeer{
					{CIDR: "10.0.0.0/24"},
					{Service: &agentsv1alpha1.TrafficPolicyServiceRef{Namespace: "demo", Name: "backend"}},
					{FQDN: "api.example.com"},
				},
				Ports: []agentsv1alpha1.TrafficPolicyPort{{Protocol: "TCP", Port: &start, EndPort: &end}},
			}}},
		},
	}}, testTrafficPolicyInputs(
		"agentio-system",
		krt.NewStaticCollection(nil, []*corev1.Service{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "backend"},
			Spec:       corev1.ServiceSpec{ClusterIP: "10.96.0.10"},
		}}),
		krt.NewStaticCollection(nil, []*discoveryv1.EndpointSlice{{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "demo",
				Name:      "backend-v4",
				Labels:    map[string]string{discoveryv1.LabelServiceName: "backend"},
			},
			AddressType: discoveryv1.AddressTypeIPv4,
			Endpoints:   []discoveryv1.Endpoint{{Addresses: []string{"10.2.0.2"}}},
		}}),
		krt.NewStaticCollection(nil, []*corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "source", Labels: map[string]string{"role": "source"}},
			Status: corev1.PodStatus{
				PodIP:      "10.1.0.5",
				Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
			},
		}}),
		func(host string) []netip.Addr {
			if host == "api.example.com" {
				return []netip.Addr{netip.MustParseAddr("203.0.113.7")}
			}
			return nil
		},
	))
	if err != nil {
		t.Fatalf("compile policies: %v", err)
	}
	if len(compiled) != 1 {
		t.Fatalf("compiled policies = %d, want 1", len(compiled))
	}
	got := compiled[0]
	if got.ResourceName() != "demo/api-egress" || !got.Attachment.Selects(SandboxSubject{
		Namespace: "demo",
		Labels:    map[string]string{"app": "client"},
	}) {
		t.Fatalf("compiled identity/selector = %+v", got)
	}
	if got.Policy.GetScope() != securityv1.Scope_WORKLOAD_SELECTOR || len(got.Policy.GetGroups()) != 1 {
		t.Fatalf("authorization scope/groups = %+v", got.Policy)
	}
	matches := flattenMatches(got.Policy)
	if !hasAddress(matches, "source", "10.1.0.5/32", false) ||
		!hasAddress(matches, "destination", "10.0.0.0/24", false) ||
		!hasAddress(matches, "destination", "10.96.0.10/32", false) ||
		!hasAddress(matches, "destination", "10.2.0.2/32", false) ||
		!hasAddress(matches, "destination", "203.0.113.7/32", false) {
		t.Fatalf("resolved matches = %+v", matches)
	}
	if !hasPortRange(matches, 8080, 8090, securityv1.Protocol_TCP, false) {
		t.Fatalf("port range missing from %+v", matches)
	}
	extension := got.Policy.GetAuthExtensions()[0]
	decoded := &extensionsv1.TrafficPolicyExtension{}
	if err := extension.GetConfig().UnmarshalTo(decoded); err != nil {
		t.Fatalf("decode traffic policy extension: %v", err)
	}
	if extension.GetName() != "traffic-policy" || decoded.GetPriority() != 500 || decoded.GetMode() != extensionsv1.TrafficPolicyMode_CLIENT {
		t.Fatalf("traffic policy extension = %+v / %+v", extension, decoded)
	}
}

func TestCompileTrafficPolicyWorkloadPeerMatchesSelectedPodsRegardlessOfRuntimeState(t *testing.T) {
	compiled, err := CompileTrafficPolicies(krt.TestingDummyContext{}, []model.TrafficPolicy{{
		Name: "pod-only", Namespace: "demo", Spec: agentsv1alpha1.TrafficPolicySpec{
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionAllow,
				To: []agentsv1alpha1.TrafficPolicyPeer{{Workload: &agentsv1alpha1.TrafficPolicyWorkloadRef{
					Namespace: "demo",
					Selector:  map[string]string{"role": "backend"},
				}}},
			}}},
		},
	}}, testTrafficPolicyInputs(
		"agentio-system", nil, nil,
		krt.NewStaticCollection(nil, []*corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "ready", Labels: map[string]string{"role": "backend"}},
				Status: corev1.PodStatus{
					PodIP:      "10.1.0.5",
					Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "not-ready", Labels: map[string]string{"role": "backend"}},
				Status:     corev1.PodStatus{PodIP: "10.1.0.6"},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:         "demo",
					Name:              "deleting",
					Labels:            map[string]string{"role": "backend"},
					DeletionTimestamp: &metav1.Time{},
				},
				Status: corev1.PodStatus{
					PodIP:      "10.1.0.7",
					Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
				},
			},
		}),
		nil,
	))
	if err != nil {
		t.Fatal(err)
	}
	matches := flattenMatches(compiled[0].Policy)
	if !hasAddress(matches, "destination", "10.1.0.5/32", false) {
		t.Fatalf("Pod peer address is missing: %+v", matches)
	}
	if !hasAddress(matches, "destination", "10.1.0.6/32", false) ||
		!hasAddress(matches, "destination", "10.1.0.7/32", false) {
		t.Fatalf("selected Pod was excluded by runtime state: %+v", matches)
	}
}

func TestCompileTrafficPolicySkipsInvalidPeerAddresses(t *testing.T) {
	compiled, err := CompileTrafficPolicies(krt.TestingDummyContext{}, []model.TrafficPolicy{{
		Name: "pod-addresses", Namespace: "demo", Spec: agentsv1alpha1.TrafficPolicySpec{
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionAllow,
				To: []agentsv1alpha1.TrafficPolicyPeer{{Workload: &agentsv1alpha1.TrafficPolicyWorkloadRef{
					Namespace: "demo",
					Selector:  map[string]string{"role": "backend"},
				}}},
			}}},
		},
	}}, testTrafficPolicyInputs("agentio-system", nil, nil, krt.NewStaticCollection(nil, []*corev1.Pod{{
		ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "backend", Labels: map[string]string{"role": "backend"}},
		Status: corev1.PodStatus{
			PodIPs:     []corev1.PodIP{{IP: "not-an-ip"}, {IP: "10.1.0.5"}},
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
		},
	}}), nil))
	if err != nil {
		t.Fatalf("invalid peer address rejected the TrafficPolicy: %v", err)
	}
	if !hasAddress(flattenMatches(compiled[0].Policy), "destination", "10.1.0.5/32", false) {
		t.Fatalf("valid peer address was not preserved: %+v", compiled[0].Policy)
	}
}

func TestCompileTrafficPolicyRejectUsesNegativeMatches(t *testing.T) {
	compiled, err := CompileTrafficPolicies(krt.TestingDummyContext{}, []model.TrafficPolicy{{
		Name: "deny", Namespace: "demo", Spec: agentsv1alpha1.TrafficPolicySpec{
			Ingress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionReject,
				From:   []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "192.0.2.0/24"}},
				Ports:  []agentsv1alpha1.TrafficPolicyPort{{Protocol: "UDP"}},
			}}},
		},
	}}, testTrafficPolicyInputs("agentio-system", nil, nil, nil, nil))
	if err != nil {
		t.Fatalf("compile reject policy: %v", err)
	}
	matches := flattenMatches(compiled[0].Policy)
	if !hasAddress(matches, "source", "192.0.2.0/24", true) || !hasPortRange(matches, 0, 65535, securityv1.Protocol_UDP, true) {
		t.Fatalf("reject did not compile to negative matches: %+v", matches)
	}
}

func TestCompileTrafficPolicyRejectIncludesNotReadyEndpoints(t *testing.T) {
	compiled, err := CompileTrafficPolicies(krt.TestingDummyContext{}, []model.TrafficPolicy{{
		Name: "deny-backend", Namespace: "demo", Spec: agentsv1alpha1.TrafficPolicySpec{
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionReject,
				To:     []agentsv1alpha1.TrafficPolicyPeer{{Service: &agentsv1alpha1.TrafficPolicyServiceRef{Namespace: "demo", Name: "backend"}}},
			}}},
		},
	}}, testTrafficPolicyInputs(
		"agentio-system",
		krt.NewStaticCollection(nil, []*corev1.Service{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "backend"},
			Spec:       corev1.ServiceSpec{ClusterIP: "10.96.0.10"},
		}}),
		krt.NewStaticCollection(nil, []*discoveryv1.EndpointSlice{{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "demo",
				Name:      "backend-v4",
				Labels:    map[string]string{discoveryv1.LabelServiceName: "backend"},
			},
			AddressType: discoveryv1.AddressTypeIPv4,
			Endpoints: []discoveryv1.Endpoint{
				{Addresses: []string{"10.2.0.2"}},
				{Addresses: []string{"10.2.0.3"}, Conditions: discoveryv1.EndpointConditions{Ready: func() *bool { value := false; return &value }()}},
			},
		}}),
		nil, nil,
	))
	if err != nil {
		t.Fatalf("compile reject policy: %v", err)
	}
	matches := flattenMatches(compiled[0].Policy)
	if !hasAddress(matches, "destination", "10.2.0.3/32", true) {
		t.Fatalf("not-ready endpoint missing from negative match, widening traffic: %+v", matches)
	}
	if !hasAddress(matches, "destination", "10.2.0.2/32", true) || !hasAddress(matches, "destination", "10.96.0.10/32", true) {
		t.Fatalf("ready endpoint or VIP missing from negative match: %+v", matches)
	}
}

func TestCompileTrafficPolicyServiceUsesPolicyNamespaceByDefault(t *testing.T) {
	inputs := testTrafficPolicyInputs("agentio-system", krt.NewStaticCollection(nil, []*corev1.Service{{
		ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "backend"},
		Spec: corev1.ServiceSpec{
			ClusterIP:  "10.96.0.10",
			ClusterIPs: []string{"10.96.0.10", "2001:db8::10"},
		},
	}}), krt.NewStaticCollection(nil, []*discoveryv1.EndpointSlice{{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo",
			Name:      "backend-v4",
			Labels:    map[string]string{discoveryv1.LabelServiceName: "backend"},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{{
			Addresses: []string{"10.2.0.2"},
		}},
	}}), nil, nil)

	for _, serviceName := range []string{"backend", "*"} {
		t.Run(serviceName, func(t *testing.T) {
			serviceRef := &agentsv1alpha1.TrafficPolicyServiceRef{Name: serviceName}
			compiled, err := CompileTrafficPolicies(krt.TestingDummyContext{}, []model.TrafficPolicy{{
				Name: "service", Namespace: "demo", Spec: agentsv1alpha1.TrafficPolicySpec{
					Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
						Action: agentsv1alpha1.RuleActionAllow,
						To:     []agentsv1alpha1.TrafficPolicyPeer{{Service: serviceRef}},
					}}},
				},
			}}, inputs)
			if err != nil {
				t.Fatal(err)
			}
			if serviceRef.Namespace != "" {
				t.Fatalf("compiler mutated Service namespace to %q", serviceRef.Namespace)
			}
			matches := flattenMatches(compiled[0].Policy)
			if !hasAddress(matches, "destination", "10.96.0.10/32", false) ||
				!hasAddress(matches, "destination", "10.2.0.2/32", false) {
				t.Fatalf("Kubernetes Service peer addresses missing: %+v", matches)
			}
			if hasAddress(matches, "destination", "2001:db8::10/128", false) {
				t.Fatalf("secondary ClusterIP unexpectedly matched Agentio primary-ClusterIP behavior: %+v", matches)
			}
		})
	}
}

func TestCompileGlobalTrafficPolicyServiceUsesRootNamespaceByDefault(t *testing.T) {
	compiled, err := CompileTrafficPolicies(krt.TestingDummyContext{}, []model.TrafficPolicy{{
		Name: "global-service", Global: true, Spec: agentsv1alpha1.TrafficPolicySpec{
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionAllow,
				To: []agentsv1alpha1.TrafficPolicyPeer{{Service: &agentsv1alpha1.TrafficPolicyServiceRef{
					Name: "backend",
				}}},
			}}},
		},
	}}, testTrafficPolicyInputs("agentio-system", krt.NewStaticCollection(nil, []*corev1.Service{{
		ObjectMeta: metav1.ObjectMeta{Namespace: "agentio-system", Name: "backend"},
		Spec:       corev1.ServiceSpec{ClusterIP: "10.96.0.20"},
	}}), nil, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	if !hasAddress(flattenMatches(compiled[0].Policy), "destination", "10.96.0.20/32", false) {
		t.Fatalf("root-namespace Service peer address missing: %+v", compiled[0].Policy)
	}
}

func TestCompileTrafficPolicyMissingServiceFailsClosed(t *testing.T) {
	compiled, err := CompileTrafficPolicies(krt.TestingDummyContext{}, []model.TrafficPolicy{{
		Name: "missing-service", Namespace: "demo", Spec: agentsv1alpha1.TrafficPolicySpec{
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionAllow,
				To: []agentsv1alpha1.TrafficPolicyPeer{{Service: &agentsv1alpha1.TrafficPolicyServiceRef{
					Name: "missing",
				}}},
			}}},
		},
	}}, testTrafficPolicyInputs("agentio-system", nil, nil, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled[0].Policy.GetGroups()) != 0 {
		t.Fatalf("missing Service did not make the rule non-matching: %+v", compiled[0].Policy)
	}
}

func TestCompileTrafficPolicyRootNamespaceScope(t *testing.T) {
	inputs := testTrafficPolicyInputs("agentio-system", nil, nil, nil, nil)
	direction := &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
		Action: agentsv1alpha1.RuleActionAllow,
		From:   []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "10.0.0.0/24"}},
	}}}
	for _, test := range []struct {
		name   string
		policy model.TrafficPolicy
		want   securityv1.Scope
	}{
		{
			name:   "root namespace without selector is global",
			policy: model.TrafficPolicy{Name: "mesh", Namespace: "agentio-system", Spec: agentsv1alpha1.TrafficPolicySpec{Ingress: direction}},
			want:   securityv1.Scope_GLOBAL,
		},
		{
			name:   "other namespace without selector stays namespaced",
			policy: model.TrafficPolicy{Name: "local", Namespace: "demo", Spec: agentsv1alpha1.TrafficPolicySpec{Ingress: direction}},
			want:   securityv1.Scope_NAMESPACE,
		},
		{
			name: "root namespace with selector stays selector scoped",
			policy: model.TrafficPolicy{Name: "scoped", Namespace: "agentio-system", Spec: agentsv1alpha1.TrafficPolicySpec{
				Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
				Ingress:  direction,
			}},
			want: securityv1.Scope_WORKLOAD_SELECTOR,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			compiled, err := CompileTrafficPolicy(krt.TestingDummyContext{}, test.policy, inputs)
			if err != nil {
				t.Fatalf("compile policy: %v", err)
			}
			if len(compiled) != 1 {
				t.Fatalf("compiled = %d, want 1", len(compiled))
			}
			if got := compiled[0].Policy.GetScope(); got != test.want {
				t.Fatalf("scope = %v, want %v", got, test.want)
			}
			attachment := compiled[0].PolicyAttachment()
			if (attachment != nil) != (test.want == securityv1.Scope_WORKLOAD_SELECTOR) {
				t.Fatalf("scope %v produced unexpected attachment: %+v", test.want, attachment)
			}
			if attachment != nil && attachment.Name != compiled[0].ResourceName() {
				t.Fatalf("attachment name %q differs from resource name %q", attachment.Name, compiled[0].ResourceName())
			}
		})
	}
}

func TestCompileTrafficPolicyUnresolvedFQDNFailsClosed(t *testing.T) {
	port := int32(443)
	compiled, err := CompileTrafficPolicies(krt.TestingDummyContext{}, []model.TrafficPolicy{{
		Name: "fqdn", Namespace: "demo", Spec: agentsv1alpha1.TrafficPolicySpec{
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionAllow, To: []agentsv1alpha1.TrafficPolicyPeer{{FQDN: "missing.invalid"}},
				Ports: []agentsv1alpha1.TrafficPolicyPort{{Protocol: "TCP", Port: &port}},
			}}},
		},
	}}, testTrafficPolicyInputs("agentio-system", nil, nil, nil, nil))
	if err != nil {
		t.Fatalf("compile unresolved policy: %v", err)
	}
	if len(compiled[0].Policy.GetGroups()) != 0 {
		t.Fatalf("unresolved FQDN did not make the rule non-matching: %+v", compiled[0].Policy)
	}
	wire, err := proto.Marshal(compiled[0].Policy)
	if err != nil {
		t.Fatalf("marshal authorization: %v", err)
	}
	decoded := &securityv1.Authorization{}
	if err := proto.Unmarshal(wire, decoded); err != nil {
		t.Fatalf("unmarshal authorization: %v", err)
	}
	if len(decoded.GetGroups()) != 0 {
		t.Fatalf("protobuf round trip restored the omitted rule: %+v", decoded)
	}
}

func TestCompileTrafficPolicyPassesFQDNUnchangedToResolver(t *testing.T) {
	inputs := testTrafficPolicyInputs("agentio-system", nil, nil, nil, func(host string) []netip.Addr {
		if host == "API.Example.COM." {
			return []netip.Addr{netip.MustParseAddr("203.0.113.7")}
		}
		return nil
	})
	compiled, err := CompileTrafficPolicies(krt.TestingDummyContext{}, []model.TrafficPolicy{{
		Name: "fqdn", Namespace: "demo", Spec: agentsv1alpha1.TrafficPolicySpec{
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionAllow,
				To:     []agentsv1alpha1.TrafficPolicyPeer{{FQDN: "API.Example.COM."}},
			}}},
		},
	}}, inputs)
	if err != nil {
		t.Fatal(err)
	}
	if !hasAddress(flattenMatches(compiled[0].Policy), "destination", "203.0.113.7/32", false) {
		t.Fatalf("resolver did not receive the declared FQDN: %+v", compiled[0].Policy)
	}
}

func TestCompileTrafficPolicyUnmatchedWorkloadPeerFailsClosed(t *testing.T) {
	peer := agentsv1alpha1.TrafficPolicyPeer{Workload: &agentsv1alpha1.TrafficPolicyWorkloadRef{
		Namespace: "demo",
		Selector:  map[string]string{"app": "missing"},
	}}
	for _, test := range []struct {
		name   string
		action agentsv1alpha1.RuleAction
		from   []agentsv1alpha1.TrafficPolicyPeer
		to     []agentsv1alpha1.TrafficPolicyPeer
	}{
		{name: "allow source", action: agentsv1alpha1.RuleActionAllow, from: []agentsv1alpha1.TrafficPolicyPeer{peer}},
		{name: "allow destination", action: agentsv1alpha1.RuleActionAllow, to: []agentsv1alpha1.TrafficPolicyPeer{peer}},
		{name: "reject source", action: agentsv1alpha1.RuleActionReject, from: []agentsv1alpha1.TrafficPolicyPeer{peer}},
		{name: "reject destination", action: agentsv1alpha1.RuleActionReject, to: []agentsv1alpha1.TrafficPolicyPeer{peer}},
	} {
		t.Run(test.name, func(t *testing.T) {
			compiled, err := CompileTrafficPolicies(krt.TestingDummyContext{}, []model.TrafficPolicy{{
				Name: "missing-peer", Namespace: "demo", Spec: agentsv1alpha1.TrafficPolicySpec{
					Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
						Action: test.action,
						From:   test.from,
						To:     test.to,
					}}},
				},
			}}, testTrafficPolicyInputs("agentio-system", nil, nil, nil, nil))
			if err != nil {
				t.Fatalf("compile policy: %v", err)
			}
			if len(compiled[0].Policy.GetGroups()) != 0 {
				t.Fatalf("unmatched workload peer did not make the rule non-matching: %+v", compiled[0].Policy)
			}
		})
	}
}

func TestCompileTrafficPolicyInvalidCIDRFailsClosed(t *testing.T) {
	compiled, err := CompileTrafficPolicies(krt.TestingDummyContext{}, []model.TrafficPolicy{{
		Name: "invalid-cidr", Namespace: "demo", Spec: agentsv1alpha1.TrafficPolicySpec{
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionAllow,
				To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "not-a-cidr"}},
			}}},
		},
	}}, testTrafficPolicyInputs("agentio-system", nil, nil, nil, nil))
	if err != nil {
		t.Fatalf("compile invalid CIDR policy: %v", err)
	}
	if len(compiled[0].Policy.GetGroups()) != 0 {
		t.Fatalf("invalid CIDR did not make the rule non-matching: %+v", compiled[0].Policy)
	}
}

func TestCompileTrafficPolicyUnresolvedRuleDoesNotRemoveOtherRules(t *testing.T) {
	compiled, err := CompileTrafficPolicies(krt.TestingDummyContext{}, []model.TrafficPolicy{{
		Name: "mixed-rules", Namespace: "demo", Spec: agentsv1alpha1.TrafficPolicySpec{
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{
				{Action: agentsv1alpha1.RuleActionAllow, To: []agentsv1alpha1.TrafficPolicyPeer{{FQDN: "missing.invalid"}}},
				{Action: agentsv1alpha1.RuleActionAllow, To: []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "192.0.2.0/24"}}},
			}},
		},
	}}, testTrafficPolicyInputs("agentio-system", nil, nil, nil, nil))
	if err != nil {
		t.Fatalf("compile mixed rules: %v", err)
	}
	groups := compiled[0].Policy.GetGroups()
	if len(groups) != 1 || !hasAddress(flattenMatches(compiled[0].Policy), "destination", "192.0.2.0/24", false) {
		t.Fatalf("unresolved rule affected valid sibling rule: %+v", compiled[0].Policy)
	}
}

func TestCompileTrafficPolicyResolvedPeerKeepsMixedPeerListMatchable(t *testing.T) {
	compiled, err := CompileTrafficPolicies(krt.TestingDummyContext{}, []model.TrafficPolicy{{
		Name: "mixed-peers", Namespace: "demo", Spec: agentsv1alpha1.TrafficPolicySpec{
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionAllow,
				To: []agentsv1alpha1.TrafficPolicyPeer{
					{FQDN: "missing.invalid"},
					{CIDR: "192.0.2.0/24"},
				},
			}}},
		},
	}}, testTrafficPolicyInputs("agentio-system", nil, nil, nil, nil))
	if err != nil {
		t.Fatalf("compile mixed peers: %v", err)
	}
	groups := compiled[0].Policy.GetGroups()
	if len(groups) != 1 || !hasAddress(flattenMatches(compiled[0].Policy), "destination", "192.0.2.0/24", false) {
		t.Fatalf("resolved peer list did not remain matchable: %+v", compiled[0].Policy)
	}
}

func TestCompileTrafficPolicyRuleWithoutPeersRemainsWildcard(t *testing.T) {
	compiled, err := CompileTrafficPolicies(krt.TestingDummyContext{}, []model.TrafficPolicy{{
		Name: "wildcard", Namespace: "demo", Spec: agentsv1alpha1.TrafficPolicySpec{
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionAllow,
			}}},
		},
	}}, testTrafficPolicyInputs("agentio-system", nil, nil, nil, nil))
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	group := compiled[0].Policy.GetGroups()[0]
	if len(group.GetRules()) != 0 {
		t.Fatalf("peerless wildcard rule gained constraints: %+v", group)
	}
}

func flattenMatches(authorization *securityv1.Authorization) []*securityv1.Match {
	var result []*securityv1.Match
	for _, group := range authorization.GetGroups() {
		for _, rules := range group.GetRules() {
			result = append(result, rules.GetMatches()...)
		}
	}
	return result
}

func hasAddress(matches []*securityv1.Match, direction, value string, negative bool) bool {
	prefix := netip.MustParsePrefix(value)
	for _, match := range matches {
		var addresses []*securityv1.Address
		switch {
		case direction == "source" && negative:
			addresses = match.GetNotSourceIps()
		case direction == "source":
			addresses = match.GetSourceIps()
		case negative:
			addresses = match.GetNotDestinationIps()
		default:
			addresses = match.GetDestinationIps()
		}
		for _, address := range addresses {
			parsed, ok := netip.AddrFromSlice(address.GetAddress())
			if ok && parsed == prefix.Addr() && int(address.GetLength()) == prefix.Bits() {
				return true
			}
		}
	}
	return false
}

func hasPortRange(matches []*securityv1.Match, start, end uint32, protocol securityv1.Protocol, negative bool) bool {
	for _, match := range matches {
		ranges := match.GetDestinationPortRanges()
		if negative {
			ranges = match.GetNotDestinationPortRanges()
		}
		for _, portRange := range ranges {
			if portRange.GetStart() == start && portRange.GetEnd() == end && portRange.GetProtocol() == protocol {
				return true
			}
		}
	}
	return false
}
