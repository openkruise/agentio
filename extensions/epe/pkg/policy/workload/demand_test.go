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

package workload

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"istio.io/istio/pkg/test"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	ext "github.com/openkruise/agentio/api/extensions/v1"
	sandboxv1 "github.com/openkruise/agentio/api/sandbox/v1"
	sec "github.com/openkruise/agentio/api/security/v1"
	workload "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/metrics"
	"github.com/openkruise/agentio/extensions/epe/pkg/policy/profilestore"
	"github.com/openkruise/agentio/extensions/epe/pkg/store"
	xdsbackend "github.com/openkruise/agentio/extensions/epe/pkg/store/xds"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
	"github.com/openkruise/agentio/pkg/demandcache"
	"github.com/openkruise/agentio/pkg/features"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/policy"
	controlxds "github.com/openkruise/agentio/pkg/xds"
	controlstore "github.com/openkruise/agentio/pkg/xds/store"
	"github.com/openkruise/agentio/pkg/xdsclient"
)

type demandAuthenticator struct{}

func (demandAuthenticator) Authenticate(context.Context) (model.PeerIdentity, error) {
	return model.PeerIdentity{AttestedBy: model.AttestationKubernetes}, nil
}

// Exercise the EPE resolver through the real client, ADS generators and publication
// store: a cold request must discover both its Workload and its policy dependencies.
func TestDemandDiscovery(t *testing.T) {
	testDemandDiscovery(t, 64, true)
}

func TestWorkloadDemandDiscovery(t *testing.T) {
	testDemandDiscovery(t, 64, false)
}

func TestDemandCacheSmallCapacity(t *testing.T) {
	testDemandDiscovery(t, 1, true)
}

func testDemandDiscovery(t *testing.T, capacity int, sandboxMode bool) {
	test.SetForTest(t, &features.SandboxMode, sandboxMode)
	const clusterID = "edge"
	const uid = "edge//Pod/ns/pod"
	pack := func(value proto.Message) *anypb.Any {
		t.Helper()
		result, err := anypb.New(value)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	resource := func(typ, name string, value proto.Message, facts model.ResourceFacts) model.Resource {
		t.Helper()
		contents := model.Prebuilt(value)
		if address, ok := value.(*workload.Address); ok && address.GetWorkload() != nil {
			base := address.GetWorkload()
			extensions := base.Extensions
			base.Extensions = nil
			contents = model.WorkloadContents(base, extensions)
		}
		result, err := model.NewResource(model.ResourceKey{TypeURL: typ, Name: name}, name, contents, nil, facts)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	workloadResource := func(name, pod, policy string) model.Resource {
		return resource(
			model.AddressType,
			name,
			&workload.Address{Type: &workload.Address_Workload{Workload: &workload.Workload{
				Uid:       name,
				Name:      pod,
				Namespace: "ns",
				ClusterId: clusterID,
				Extensions: []*workload.Extension{
					{
						Name: "traffic-policy-reference",
						Config: pack(&ext.PolicyReference{
							TypeUrl:   model.TrafficPolicyType,
							Resources: []*ext.PolicyResourceReference{{Name: policy}},
						})},
					{
						Name: "security-profile-reference",
						Config: pack(
							&ext.PolicyReference{
								TypeUrl:   model.SecurityProfileType,
								Resources: []*ext.PolicyResourceReference{{Name: "global/" + policy}},
							},
						),
					},
				},
			}}},
			model.ResourceFacts{Workload: &model.WorkloadResourceFacts{
				WorkloadUID:       name,
				Namespace:         "ns",
				TrafficPolicyRefs: []string{policy},
			}},
		)
	}
	profileResource := func(name, rule string) model.Resource {
		document := model.HTTPPolicy{
			Rules: []agentsv1alpha1.SecurityRule{
				{Name: rule, Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"*"}}}},
			},
		}
		data, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		return resource(
			model.SecurityProfileType,
			"global/"+name,
			&sec.SecurityProfile{Name: name, PolicyJson: data, TcpPolicy: &sec.TCPPolicy{}},
			model.ResourceFacts{},
		)
	}
	requestedWorkload := workloadResource(uid, "pod", "policy")
	initial, err := model.NewResourceSet([]model.Resource{
		requestedWorkload,
		profileResource("policy", "initial"), profileResource("unused", "unused"),
		workloadResource("edge//Pod/ns/unused", "unused", "unused"),
	})
	if err != nil {
		t.Fatal(err)
	}
	publications := controlstore.New(initial)
	principal, err := model.NewPrincipal("cluster.local", "ns/gateways/sa/default")
	if err != nil {
		t.Fatal(err)
	}
	server, err := controlxds.NewServer(demandAuthenticator{}, controlxds.ScopeFuncs{
		model.AttestationKubernetes: func(*core.Node, model.PeerIdentity) (model.ClientScope, error) {
			return model.ClientScope{
				Class:       model.ClientEPE,
				Principal:   principal,
				GatewayKey:  "gateways/egress",
				WorkloadUID: "gateway",
				Source:      model.SourceRef{Registry: "kubernetes/edge", Key: "gateway-pod"},
			}, nil
		},
	}, publications, func() bool { return true }, 16, map[string]controlxds.ResourceGenerator{
		model.WorkloadType:        controlxds.WorkloadGenerator{},
		model.SecurityProfileType: controlxds.SecurityProfileGenerator{},
		model.SandboxType:         controlxds.SandboxGenerator{},
	}, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	listener := bufconn.Listen(1 << 20)
	grpcServer := grpc.NewServer()
	discovery.RegisterAggregatedDiscoveryServiceServer(grpcServer, server)
	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			t.Error(err)
		}
	}()
	t.Cleanup(grpcServer.Stop)
	conn, err := grpc.NewClient("passthrough:///demand-test", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	})
	cms := krt.NewMutableCollection[*corev1.ConfigMap](nil, nil, krt.WithStop(t.Context().Done()))
	profileStore := profilestore.NewXDSStore()
	profileSource := xdsbackend.NewProfileSource(profileStore.ObserveAdmission, t.Context().Done())
	watches := append(xdsbackend.Watches(), profileSource.Watches(nil)...)
	var rejected atomic.Bool
	var sandboxRemovals atomic.Int64
	for i := range watches {
		if watches[i].TypeURL == model.SandboxType {
			onDelete := watches[i].OnDelete
			watches[i].OnDelete = func(name string) xdsclient.DeleteAction {
				sandboxRemovals.Add(1)
				return onDelete(name)
			}
		}
		if watches[i].TypeURL == model.SecurityProfileType {
			observe := watches[i].OnChange
			watches[i].OnChange = func(name string, current *xdsclient.Resource, err error) {
				observe(name, current, err)
				if err != nil {
					rejected.Store(true)
				}
			}
		}
	}
	client, err := xdsclient.New(conn, xdsclient.Config{Node: &core.Node{Id: "epe"}, Watches: watches})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	native, err := xdsbackend.NewCached(client, demandcache.Config{IdleTTL: time.Hour, MaxEntries: capacity})
	if err != nil {
		t.Fatal(err)
	}
	profileCollection := profileSource.Collection(cms.AsCollection(), krt.WithStop(t.Context().Done()))
	reg := profileStore.RegisterCollection(profileCollection, native.AcquireProfileReferences)
	t.Cleanup(reg.UnregisterHandler)
	cacheDone := make(chan error, 1)
	go func() { cacheDone <- native.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-cacheDone; err != nil {
			t.Error(err)
		}
	})
	aggregate := store.NewAggregate(native)
	RegisterQueries(aggregate, clusterID)
	await := func(condition func() bool) {
		t.Helper()
		if err := wait.PollUntilContextCancel(ctx, time.Millisecond, true, func(context.Context) (bool, error) {
			aggregate.Refresh()
			return condition(), nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	await(aggregate.Ready)
	for typ, values := range client.Snapshot().Resources {
		if len(values) != 0 {
			t.Fatalf("initial %s watch fetched %d unsolicited resources", typ, len(values))
		}
	}
	subj := subject.Subject{Workload: subject.Workload{Namespace: "ns", Name: "pod"}}
	resolveWorkload := func(ctx context.Context, w subject.Workload) (subject.Workload, error) {
		return lookupBinding(ctx, aggregate, subject.Subject{Workload: w})
	}
	beforeDemand := aggregate.Snapshot()
	resolved, err := resolveWorkload(ctx, subj.Workload)
	if err != nil || resolved.UID != uid || len(resolved.SecurityProfileReferences) != 1 {
		t.Fatalf("cold Workload binding: %+v err=%v", resolved, err)
	}
	if snapshot := client.Snapshot(); len(snapshot.Resources[model.WorkloadType]) != 1 ||
		len(snapshot.Resources[model.TrafficPolicyType]) != 0 {
		t.Fatal("SecurityProfile lookup fetched unrelated Workloads or TrafficPolicies")
	}
	profiles, err := profileStore.ResolveProfiles(ctx, subject.Subject{Workload: resolved})
	if err != nil || len(profiles) != 1 || profiles[0].Meta.Name != "policy" {
		t.Fatalf("referenced xDS profile: %v %v", profiles, err)
	}
	if capacity > 1 {
		removals := sandboxRemovals.Load()
		for range 3 {
			if _, err := profileStore.ResolveProfiles(ctx, subject.Subject{Workload: resolved}); err != nil {
				t.Fatal(err)
			}
		}
		if sandboxRemovals.Load() != removals {
			t.Fatal("missing same-name Sandbox was fetched again instead of staying cached")
		}
	}
	target := netip.MustParseAddrPort("203.0.113.7:443")
	checkAction := func(want bool) {
		t.Helper()
		current, err := resolveWorkload(ctx, subj.Workload)
		if err != nil {
			t.Fatal(err)
		}
		profiles, err := profileStore.ResolveProfiles(ctx, subject.Subject{Workload: current})
		if err != nil || len(profiles) != 1 {
			t.Fatalf("resolve profile: %v %v", profiles, err)
		}
		got, _ := policy.MatchTCPRules(profiles[0].TCPPolicy.GetRules(), target)
		if got != want {
			t.Fatalf("allowed=%v, want %v", got, want)
		}
	}
	checkAction(true)
	if aggregate.Snapshot() != beforeDemand {
		t.Fatal("cold dependency resolution rebuilt the global index")
	}
	if capacity == 1 {
		// A Workload plus its policy exceed the target; both remain pinned
		// until the compiled view has been read, including concurrent readers.
		var workers sync.WaitGroup
		failures := make(chan error, 16)
		for range 16 {
			workers.Go(func() {
				for range 10 {
					profiles, err := profileStore.ResolveProfiles(ctx, subject.Subject{Workload: resolved})
					if err != nil {
						failures <- err
						return
					}
					if allowed, _ := policy.MatchTCPRules(profiles[0].TCPPolicy.GetRules(), target); !allowed {
						t.Error("pinned policy denied")
					}
				}
			})
		}
		workers.Wait()
		close(failures)
		for err := range failures {
			t.Error(err)
		}
		if native.CacheEntries() > 1 {
			t.Fatal("capacity did not recover after concurrent resolution")
		}
		return
	}
	for typ, values := range client.Snapshot().Resources {
		want := 1
		if typ == model.SandboxType {
			want = 0
		}
		if len(values) != want {
			t.Fatalf("%s cached %d resources, want just the requested one", typ, len(values))
		}
	}
	apply := func(changes ...model.ResourceChange) {
		t.Helper()
		if _, err := publications.Apply(changes); err != nil {
			t.Fatal(err)
		}
	}
	metricValue := func(name string) float64 {
		t.Helper()
		families, err := metrics.Registry.Gather()
		if err != nil {
			t.Fatal(err)
		}
		for _, family := range families {
			if family.GetName() != name {
				continue
			}
			for _, metric := range family.Metric {
				for _, label := range metric.Label {
					if label.GetName() == "scope" && label.GetValue() == "global" {
						return metric.GetGauge().GetValue() + metric.GetCounter().GetValue()
					}
				}
			}
		}
		return 0
	}
	beforeFailures := metricValue("epe_profile_compile_failures_total")
	forwardCompatible := resource(
		model.SecurityProfileType,
		"global/policy",
		&sec.SecurityProfile{
			Name: "policy",
			PolicyJson: []byte(
				`{"future":true,"rules":[{"name":"compatible","match":[{"domains":["*"]}],"actions":{"futureAction":{}}}]}`,
			),
		},
		model.ResourceFacts{},
	)
	apply(model.ResourceChange{Key: forwardCompatible.Key, New: &forwardCompatible})
	await(func() bool {
		profiles, err := profileStore.ResolveProfiles(ctx, subject.Subject{Workload: resolved})
		return err == nil && len(profiles) == 1 && len(profiles[0].Rules) == 1 &&
			profiles[0].Rules[0].Name == "compatible"
	})
	if rejected.Load() || metricValue("epe_profile_compile_failures_total") != beforeFailures {
		t.Fatal("unknown fields rejected the update")
	}
	beforeInvalid := client.Snapshot().Resources[model.SecurityProfileType]["global/policy"]
	bad := resource(
		model.SecurityProfileType,
		"global/policy",
		&sec.SecurityProfile{Name: "policy", PolicyJson: []byte(`{"rules":"invalid"}`)},
		model.ResourceFacts{},
	)
	apply(model.ResourceChange{Key: bad.Key, New: &bad})
	await(rejected.Load)
	if metricValue("epe_profile_stale") != 1 || metricValue("epe_profile_compile_failures_total") != beforeFailures+1 {
		t.Fatal("NACK did not report retained policy degradation")
	}
	if client.Snapshot().Resources[model.SecurityProfileType]["global/policy"] != beforeInvalid {
		t.Fatal("invalid profile replaced the last accepted body")
	}
	replacement := profileResource("policy", "updated")
	apply(model.ResourceChange{Key: replacement.Key, New: &replacement})
	await(func() bool {
		profiles, err := profileStore.ResolveProfiles(ctx, subject.Subject{Workload: resolved})
		return err == nil && len(profiles) == 1 && profiles[0].Rules[0].Name == "updated"
	})
	if metricValue("epe_profile_stale") != 0 {
		t.Fatal("accepted update did not clear policy degradation")
	}
	denied := resource(model.SecurityProfileType, "global/policy", &sec.SecurityProfile{
		Name:       "policy",
		PolicyJson: []byte(`{"rules":[]}`),
		TcpPolicy: &sec.TCPPolicy{
			Rules: []*sec.TCPRule{{Name: "deny", Action: sec.TCPAction_TCP_ACTION_DENY, Match: []*sec.TCPMatch{{}}}},
		},
	}, model.ResourceFacts{})
	apply(model.ResourceChange{Key: denied.Key, New: &denied})
	await(func() bool {
		profiles, err := profileStore.ResolveProfiles(ctx, subject.Subject{Workload: resolved})
		return err == nil && len(profiles) == 1 && len(profiles[0].TCPPolicy.GetRules()) == 1
	})
	checkAction(false)
	apply(model.ResourceChange{Key: requestedWorkload.Key, Old: &requestedWorkload})
	await(func() bool { return len(client.Snapshot().Resources[model.WorkloadType]) == 0 })
	if _, err := resolveWorkload(ctx, subj.Workload); err == nil {
		t.Fatal("deleted Workload authorized")
	}
	apply(
		model.ResourceChange{Key: requestedWorkload.Key, New: &requestedWorkload},
		model.ResourceChange{Key: replacement.Key, New: &replacement},
	)
	await(func() bool {
		profiles, err := profileStore.ResolveProfiles(ctx, subject.Subject{Workload: resolved})
		return err == nil && len(profiles) == 1 && len(profiles[0].TCPPolicy.GetRules()) == 0
	})
	checkAction(true)
	// A new binding must demand a previously uncached policy before authorizing.
	rebound := workloadResource(uid, "pod", "unused")
	apply(model.ResourceChange{Key: rebound.Key, New: &rebound})
	await(func() bool {
		value, err := aggregate.Get(store.Key{Type: store.Workload, Name: uid})
		if err != nil || value == nil {
			return false
		}
		binding, err := workloadBinding(value.Value.(*workload.Workload))
		return err == nil && len(binding.SecurityProfileReferences) == 1 &&
			binding.SecurityProfileReferences[0] == "global/unused"
	})
	checkAction(true)
	snapshot := client.Snapshot()
	if len(snapshot.Resources[model.WorkloadType]) != 1 ||
		snapshot.Resources[model.SecurityProfileType]["global/unused"] == nil {
		t.Fatal("rebinding did not demand its SecurityProfile")
	}
	resolved, err = resolveWorkload(ctx, subj.Workload)
	if err != nil {
		t.Fatal(err)
	}
	profiles, err = profileStore.ResolveProfiles(ctx, subject.Subject{Workload: resolved})
	if err != nil || len(profiles) != 1 || profiles[0].Meta.Name != "unused" {
		t.Fatalf("updated SecurityProfile binding: %v %v", profiles, err)
	}
	if !sandboxMode {
		if _, found := client.Snapshot().Synced[model.SandboxType]; found {
			t.Fatal("workload mode started Sandbox discovery")
		}
		return
	}
	sandbox := resource(model.SandboxType, "kruise:delivery", &sandboxv1.Sandbox{
		Uid:      "kruise:delivery",
		Attester: &sandboxv1.Sandbox_Attester{WorkloadUid: uid},
		Extensions: []*anypb.Any{pack(&sec.SecurityProfile{
			Name:       "pod",
			Namespace:  "ns",
			PolicyJson: []byte(`{}`),
		})},
	}, model.ResourceFacts{Sandbox: &model.SandboxResourceFacts{AttesterWorkloadUID: uid}})
	sandbox, err = model.NewResource(
		sandbox.Key,
		sandbox.XDSName,
		model.Prebuilt(sandbox.Value),
		[]string{"ns/pod"},
		sandbox.Facts,
	)
	if err != nil {
		t.Fatal(err)
	}
	apply(model.ResourceChange{Key: sandbox.Key, New: &sandbox})
	await(func() bool {
		profiles, err := profileStore.ResolveProfiles(ctx, subject.Subject{Workload: resolved})
		return err == nil && len(profiles) == 2 && profiles[1].Meta.SandboxUID == "kruise:delivery"
	})
	apply(model.ResourceChange{Key: sandbox.Key, Old: &sandbox})
	await(func() bool { return client.Snapshot().Resources[model.SandboxType][sandbox.Key.Name] == nil })
	profiles, err = profileStore.ResolveProfiles(ctx, subject.Subject{Workload: resolved})
	if err != nil || len(profiles) != 1 {
		t.Fatalf("deleted same-name Sandbox retained its policy: %v %v", profiles, err)
	}
}
