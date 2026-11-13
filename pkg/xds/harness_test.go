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

package xds

import (
	"context"
	"fmt"
	"io"
	"maps"
	"slices"
	"sync"
	"testing"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
	"istio.io/istio/pkg/util/sets"

	securityv1 "github.com/openkruise/agentio/api/security/v1"
	workloadv1 "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/security/mitm"
	xdsstore "github.com/openkruise/agentio/pkg/xds/store"
)

// fakeStream is an in-memory DeltaStream: queued requests, collected responses, EOF when exhausted.
type fakeStream struct {
	ctx      context.Context
	requests chan *discoveryv3.DeltaDiscoveryRequest

	mu         sync.Mutex
	responses  []*discoveryv3.DeltaDiscoveryResponse
	sendErr    error
	beforeSend func()
}

var _ DeltaStream = (*fakeStream)(nil)

func newFakeStream(ctx context.Context, capacity int) *fakeStream {
	return &fakeStream{ctx: ctx, requests: make(chan *discoveryv3.DeltaDiscoveryRequest, capacity)}
}

func (f *fakeStream) send(request *discoveryv3.DeltaDiscoveryRequest) { f.requests <- request }
func (f *fakeStream) closeRequests()                                  { close(f.requests) }

func (f *fakeStream) Send(response *discoveryv3.DeltaDiscoveryResponse) error {
	if f.beforeSend != nil {
		f.beforeSend()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sendErr != nil {
		return f.sendErr
	}
	f.responses = append(f.responses, response)
	return nil
}

func (f *fakeStream) setSendErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sendErr = err
}

func (f *fakeStream) Recv() (*discoveryv3.DeltaDiscoveryRequest, error) {
	select {
	case request, ok := <-f.requests:
		if !ok {
			return nil, io.EOF
		}
		return request, nil
	case <-f.ctx.Done():
		return nil, f.ctx.Err()
	}
}

func (f *fakeStream) sent() []*discoveryv3.DeltaDiscoveryResponse {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*discoveryv3.DeltaDiscoveryResponse(nil), f.responses...)
}

// responsesFor returns the responses emitted for one type, in order.
func (f *fakeStream) responsesFor(typeURL string) []*discoveryv3.DeltaDiscoveryResponse {
	var result []*discoveryv3.DeltaDiscoveryResponse
	for _, response := range f.sent() {
		if response.GetTypeUrl() == typeURL {
			result = append(result, response)
		}
	}
	return result
}

func (f *fakeStream) Context() context.Context     { return f.ctx }
func (f *fakeStream) SetHeader(metadata.MD) error  { return nil }
func (f *fakeStream) SendHeader(metadata.MD) error { return nil }
func (f *fakeStream) SetTrailer(metadata.MD)       {}
func (f *fakeStream) SendMsg(any) error            { return nil }
func (f *fakeStream) RecvMsg(any) error            { return nil }

type fakeAuthenticator struct {
	caller model.PeerIdentity
	err    error
}

func (f fakeAuthenticator) Authenticate(context.Context) (model.PeerIdentity, error) {
	return f.caller, f.err
}

type fakeResolver struct {
	scope model.ClientScope
	err   error
}

func (f fakeResolver) scopeFuncs() ScopeFuncs {
	return ScopeFuncs{model.AttestationKubernetes: func(*corev3.Node, model.PeerIdentity) (model.ClientScope, error) {
		return f.scope, f.err
	}}
}

// fakeResourceStore supplies a snapshot and update subscriptions for the Delta ADS harness.
type fakeResourceStore struct {
	mu            sync.Mutex
	snapshot      model.ResourceSet
	updates       chan xdsstore.Update
	subscriptions sets.Set[*fakeResourceSubscription]
}

type fakeResourceSubscription struct {
	store   *fakeResourceStore
	updates chan xdsstore.Update
	types   sets.Set[string]
}

func newFakeResourceStore(snapshot model.ResourceSet) *fakeResourceStore {
	return &fakeResourceStore{
		snapshot:      snapshot,
		updates:       make(chan xdsstore.Update),
		subscriptions: sets.New[*fakeResourceSubscription](),
	}
}

func (f *fakeResourceStore) Snapshot() model.ResourceSet {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.snapshot
}

func (f *fakeResourceStore) Subscribe(ctx context.Context, _ model.ClientScope) xdsstore.Subscription {
	subscription := &fakeResourceSubscription{
		store:   f,
		updates: make(chan xdsstore.Update, 1),
		types:   sets.New[string](),
	}
	f.mu.Lock()
	f.subscriptions.Insert(subscription)
	f.mu.Unlock()
	go func() {
		<-ctx.Done()
		f.mu.Lock()
		f.subscriptions.Delete(subscription)
		f.mu.Unlock()
	}()
	return subscription
}

func (f *fakeResourceSubscription) Watch(typeURL string, _ ...string) {
	f.store.mu.Lock()
	f.types.Insert(typeURL)
	f.store.mu.Unlock()
}

func (f *fakeResourceSubscription) Updates() <-chan xdsstore.Update { return f.updates }

// updateReversedFrom builds a store update whose before publication is derived
// by reversing changes against the after snapshot.
func updateReversedFrom(t testing.TB, after model.ResourceSet, changes []model.ResourceChange) xdsstore.Update {
	t.Helper()
	reverse := make([]model.ResourceChange, 0, len(changes))
	for _, change := range changes {
		reverse = append(reverse, model.ResourceChange{Key: change.Key, New: change.Old})
	}
	before, _, err := after.Apply(reverse)
	if err != nil {
		t.Fatal(err)
	}
	return updateBetween(before, after, changes)
}

func (f *fakeResourceStore) publish(snapshot model.ResourceSet) {
	f.mu.Lock()
	before := f.snapshot
	changes := before.Diff(snapshot)
	if len(changes) == 0 {
		f.mu.Unlock()
		return
	}
	f.snapshot = snapshot
	update := updateBetween(before, snapshot, changes)
	for subscription := range f.subscriptions {
		affected := false
		for typeURL := range subscription.types {
			if update.Affects(typeURL) {
				affected = true
				break
			}
		}
		if !affected {
			continue
		}
		select {
		case subscription.updates <- update:
		default:
			merged := update
			select {
			case pending := <-subscription.updates:
				merged = xdsstore.Merge(pending, update)
			default:
			}
			select {
			case subscription.updates <- merged:
			default:
			}
		}
	}
	f.mu.Unlock()
}

func (f *fakeResourceStore) apply(changes []model.ResourceChange) error {
	f.mu.Lock()
	current := f.snapshot
	f.mu.Unlock()
	next, changed, err := current.Apply(changes)
	if err != nil || !changed {
		return err
	}
	f.publish(next)
	return nil
}

// fakeSecrets serves on-demand certificates for the domains it knows and refuses
// everything else, mirroring OnDemandIssuer's contract without its CA machinery.
type fakeSecrets struct {
	allowed sets.Set[string]

	mu      sync.Mutex
	calls   int
	evicted sets.Set[string]
}

func newFakeSecrets(domains ...string) *fakeSecrets {
	allowed := sets.NewWithLength[string](len(domains))
	for _, domain := range domains {
		allowed.Insert(domain)
	}
	return &fakeSecrets{allowed: allowed, evicted: sets.New[string]()}
}

func (f *fakeSecrets) Get(_ context.Context, _ model.ClientScope, name string) (mitm.SignedCertificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.getLocked(name)
}

func (f *fakeSecrets) getLocked(name string) (mitm.SignedCertificate, error) {
	f.calls++
	if !f.allowed.Contains(name) {
		return mitm.SignedCertificate{}, fmt.Errorf("domain %q is not authorized", name)
	}
	f.evicted.Delete(name)
	return mitm.SignedCertificate{
		CertificateChain: []byte("certificate-chain-" + name),
		PrivateKey:       []byte("private-key-" + name),
		UsableUntil:      time.Now().Add(59 * time.Minute),
		NotAfter:         time.Now().Add(time.Hour),
		SignedAt:         time.Now(),
		SignerRevision:   "one",
	}, nil
}

func (f *fakeSecrets) Authorize(model.ClientScope) error { return nil }
func (f *fakeSecrets) SignerRevision() string            { return "one" }

func (f *fakeSecrets) Evicted() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	result := make([]string, 0, len(f.evicted))
	for name := range f.evicted {
		result = append(result, name)
	}
	return result
}

func (f *fakeSecrets) evict(name string) {
	f.mu.Lock()
	f.evicted.Insert(name)
	f.mu.Unlock()
}

// testServer wires a Server over a snapshot and a client scope.
type testServer struct {
	server    *Server
	resources *fakeResourceStore
	scope     model.ClientScope
}

func newTestServer(
	t testing.TB,
	scope model.ClientScope,
	resources []model.Resource,
	secrets DomainCertificateProvider,
) *testServer {
	return newTestServerWithScheduler(t, scope, resources, secrets, nil)
}

func newTestServerWithGenerators(
	t testing.TB,
	scope model.ClientScope,
	resources []model.Resource,
	generators map[string]ResourceGenerator,
) *testServer {
	t.Helper()
	snapshot, err := model.NewResourceSet(resources)
	if err != nil {
		t.Fatal(err)
	}
	source := newFakeResourceStore(snapshot)
	server, err := NewServer(
		fakeAuthenticator{
			caller: model.PeerIdentity{
				AttestedBy: model.AttestationKubernetes,
				Kubernetes: model.KubernetesPeer{WorkloadName: "client-pod", Namespace: "demo", ServiceAccount: "app"},
			},
		},
		fakeResolver{scope: scope}.scopeFuncs(),
		source,
		func() bool { return true },
		16,
		testGenerators(generators),
		100,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	return &testServer{server: server, resources: source, scope: scope}
}

func newTestServerWithScheduler(
	t testing.TB,
	scope model.ClientScope,
	resources []model.Resource,
	secrets DomainCertificateProvider,
	pushScheduler *PushScheduler,
) *testServer {
	t.Helper()
	snapshot, err := model.NewResourceSet(resources)
	if err != nil {
		t.Fatal(err)
	}
	source := newFakeResourceStore(snapshot)
	authenticator := fakeAuthenticator{
		caller: model.PeerIdentity{
			AttestedBy: model.AttestationKubernetes,
			Kubernetes: model.KubernetesPeer{WorkloadName: "client-pod", Namespace: "demo", ServiceAccount: "app"},
		},
	}
	resolver := fakeResolver{scope: scope}
	ready := func() bool { return true }
	generators := testGenerators(nil)
	if secrets != nil {
		generators[model.SecretType] = newTestSDSGenerator(t, secrets)
	}
	var server *Server
	if pushScheduler == nil {
		server, err = NewServer(
			authenticator,
			resolver.scopeFuncs(),
			source,
			ready,
			16,
			generators,
			100,
			0,
		)
	} else {
		server, err = newServerWithScheduler(
			authenticator,
			resolver.scopeFuncs(),
			source,
			ready,
			16,
			generators,
			pushScheduler,
			defaultFlowControlConfig(cap(pushScheduler.slots), 0),
		)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	return &testServer{server: server, resources: source, scope: scope}
}

func testGenerators(overrides map[string]ResourceGenerator) map[string]ResourceGenerator {
	result := map[string]ResourceGenerator{
		model.AddressType:               WorkloadGenerator{},
		model.WorkloadType:              WorkloadGenerator{},
		model.WorkloadAuthorizationType: AuthorizationGenerator{},
		model.TrafficPolicyType:         TrafficPolicyGenerator{},
		model.SecurityProfileType:       SecurityProfileGenerator{},
		model.SandboxType:               SandboxGenerator{},
	}
	maps.Copy(result, overrides)
	return result
}

// A typed-nil source must be rejected at construction, before a stream reaches
// the interface call and panics.
func TestNewServerRejectsTypedNilResourceSource(t *testing.T) {
	var source *fakeResourceStore
	server, err := NewServer(
		fakeAuthenticator{},
		fakeResolver{}.scopeFuncs(),
		source,
		func() bool { return true },
		1,
		nil,
		100,
		0,
	)
	if err == nil || server != nil {
		t.Fatalf("NewServer() = (%#v, %v), want nil server and validation error", server, err)
	}
}

// start runs the stream with the request side open so tests can publish between responses.
func (s *testServer) start(stream *fakeStream) <-chan error {
	done := make(chan error, 1)
	go func() { done <- s.server.DeltaAggregatedResources(stream) }()
	return done
}

// finish closes the request side and waits for the server to return.
func (s *testServer) finish(t testing.TB, stream *fakeStream, done <-chan error) error {
	t.Helper()
	stream.closeRequests()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("stream did not finish")
		return nil
	}
}

// awaitResponses blocks until at least count responses have been sent for a type.
func (f *fakeStream) awaitResponses(t testing.TB, typeURL string, count int) []*discoveryv3.DeltaDiscoveryResponse {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if responses := f.responsesFor(typeURL); len(responses) >= count {
			return responses
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("only %d responses for %s, want %d", len(f.responsesFor(typeURL)), typeURL, count)
	return nil
}

func awaitTotalResponses(t testing.TB, stream *fakeStream, count int) []*discoveryv3.DeltaDiscoveryResponse {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if responses := stream.sent(); len(responses) >= count {
			return responses
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("only %d total responses, want %d", len(stream.sent()), count)
	return nil
}

// run drives the stream to completion with the queued requests and returns the
// server's error, so a test can assert both the responses and the outcome.
func (s *testServer) run(t testing.TB, stream *fakeStream) error {
	t.Helper()
	stream.closeRequests()
	done := make(chan error, 1)
	go func() { done <- s.server.DeltaAggregatedResources(stream) }()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("stream did not finish")
		return nil
	}
}

func nodeRequest(typeURL string, subscribe ...string) *discoveryv3.DeltaDiscoveryRequest {
	return &discoveryv3.DeltaDiscoveryRequest{
		Node: &corev3.Node{
			Id: "router~10.0.0.1~client-pod.demo~demo.svc.cluster.local",
			Metadata: &structpb.Struct{Fields: map[string]*structpb.Value{
				"POD_NAME":      structpb.NewStringValue("client-pod"),
				"POD_NAMESPACE": structpb.NewStringValue("demo"),
			}},
		},
		TypeUrl:                typeURL,
		ResourceNamesSubscribe: subscribe,
	}
}

func request(typeURL string, subscribe ...string) *discoveryv3.DeltaDiscoveryRequest {
	return &discoveryv3.DeltaDiscoveryRequest{TypeUrl: typeURL, ResourceNamesSubscribe: subscribe}
}

func mustAny(message proto.Message) *anypb.Any {
	value, err := anypb.New(message)
	if err != nil {
		panic(err)
	}
	return value
}

// mustWireAny wraps a message in an Any under an explicit wire type URL that
// differs from the descriptor's own type URL.
func mustWireAny(typeURL string, message proto.Message) *anypb.Any {
	data, err := proto.Marshal(message)
	if err != nil {
		panic(err)
	}
	return &anypb.Any{TypeUrl: typeURL, Value: data}
}

// addressResource builds a WDS Address-typed resource; payload only needs to
// vary between resources whose hashes must differ.
func addressResource(t testing.TB, name, payload string, aliases ...string) model.Resource {
	t.Helper()
	resource, err := model.NewResource(
		model.ResourceKey{TypeURL: model.AddressType, Name: name}, "",
		testResourceContents(mustAny(&workloadv1.Address{Type: &workloadv1.Address_Workload{
			Workload: &workloadv1.Workload{Uid: name, Name: payload, Namespace: "demo"},
		}})), aliases,
		model.ResourceFacts{Workload: &model.WorkloadResourceFacts{Namespace: "demo",
			WorkloadUID: "cluster//Pod/demo/client-pod",
			Source:      model.SourceRef{Registry: "kubernetes/test", Key: "cluster//Pod/demo/client-pod"},
			NodeName:    "node-a",
			Principal:   model.MustServiceAccountPrincipal("demo", "default"),
		}})
	if err != nil {
		t.Fatal(err)
	}
	return resource
}

// gatewayResource builds a gateway-scoped resource: the wire name is shared
// across gateways while the snapshot key is not.
func gatewayResource(t testing.TB, gatewayKey, xdsName, payload string) model.Resource {
	t.Helper()
	resource, err := model.NewResource(
		model.ResourceKey{TypeURL: model.ClusterType, Name: gatewayKey + "|" + xdsName}, xdsName,
		testResourceContents(mustAny(&clusterv3.Cluster{Name: xdsName, AltStatName: payload})), nil,
		model.ResourceFacts{GatewayOwner: gatewayKey})
	if err != nil {
		t.Fatal(err)
	}
	return resource
}

func gatewayResourceOfType(t testing.TB, typeURL, gatewayKey, xdsName, payload string) model.Resource {
	t.Helper()
	resource, err := model.NewResource(
		model.ResourceKey{TypeURL: typeURL, Name: gatewayKey + "|" + xdsName}, xdsName,
		testResourceContents(&anypb.Any{TypeUrl: typeURL, Value: []byte(payload)}), nil,
		model.ResourceFacts{GatewayOwner: gatewayKey})
	if err != nil {
		t.Fatal(err)
	}
	return resource
}

func gatewayScope() model.ClientScope {
	return model.ClientScope{
		Class:       model.ClientEgressGateway,
		WorkloadUID: "gw",
		Source:      model.SourceRef{Registry: "kubernetes/test", Key: "pod"},
		Principal:   model.MustServiceAccountPrincipal("demo", "egress"),
		GatewayKey:  "demo/egress",
	}
}

func ztunnelScope() model.ClientScope {
	return model.ClientScope{
		Class:       model.ClientDedicatedZTunnel,
		Principal:   model.MustServiceAccountPrincipal("demo", "default"),
		WorkloadUID: "cluster//Pod/demo/client-pod",
		Source:      model.SourceRef{Registry: "kubernetes/test", Key: "cluster//Pod/demo/client-pod"},
	}
}

func resourceNames(response *discoveryv3.DeltaDiscoveryResponse) []string {
	result := make([]string, 0, len(response.GetResources()))
	for _, resource := range response.GetResources() {
		result = append(result, resource.GetName())
	}
	return result
}

// updateBetween obtains an update through the same publication API as production.
func updateBetween(before, after model.ResourceSet, changes []model.ResourceChange) xdsstore.Update {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resources := xdsstore.New(before)
	subscription := resources.Subscribe(ctx, model.ClientScope{})
	for typeURL := range before.CountsByType() {
		subscription.Watch(typeURL)
	}
	for typeURL := range after.CountsByType() {
		subscription.Watch(typeURL)
	}
	expected, _, err := before.Apply(changes)
	if err != nil {
		panic(err)
	}
	if len(expected.Diff(after)) != 0 {
		panic("test update changes do not produce the expected after snapshot")
	}
	if !resources.Replace(after).Changed {
		return xdsstore.Update{}
	}
	return <-subscription.Updates()
}

func updateFromChanges(t testing.TB, changes []model.ResourceChange) xdsstore.Update {
	t.Helper()
	var oldResources []model.Resource
	for _, change := range changes {
		if change.Old != nil {
			oldResources = append(oldResources, *change.Old)
		}
	}
	before, err := model.NewResourceSet(oldResources)
	if err != nil {
		t.Fatal(err)
	}
	after, _, err := before.Apply(changes)
	if err != nil {
		t.Fatal(err)
	}
	return updateBetween(before, after, changes)
}

func fullUpdate(t testing.TB, name string) xdsstore.Update {
	t.Helper()
	resources := xdsstore.New(newSnapshot(t, name))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	subscription := resources.Subscribe(ctx, model.ClientScope{})
	subscription.Watch(model.AddressType)
	resources.Notify()
	return <-subscription.Updates()
}

var _ ResourceStore = (*xdsstore.Store)(nil)

type recordingGenerator struct {
	calls int
	delta GeneratedDelta
	err   error
}

type subscriptionRecordingGenerator struct {
	sentNames []string
}

type scopeRecordingGenerator struct {
	scope model.ClientScope
}

type requestRecordingGenerator struct {
	request GenerationRequest
}

func (g *subscriptionRecordingGenerator) Generate(
	_ context.Context,
	request GenerationRequest,
) (GeneratedDelta, error) {
	g.sentNames = request.Subscription.SentNames()
	request.Subscription.sent["cluster//Pod/demo/unrelated"] = "mutated"
	return GeneratedDelta{}, nil
}

func (g *recordingGenerator) Generate(context.Context, GenerationRequest) (GeneratedDelta, error) {
	g.calls++
	return g.delta, g.err
}

func (g *scopeRecordingGenerator) Generate(_ context.Context, request GenerationRequest) (GeneratedDelta, error) {
	g.scope = request.Scope
	return GeneratedDelta{}, nil
}

func (g *requestRecordingGenerator) Generate(_ context.Context, request GenerationRequest) (GeneratedDelta, error) {
	g.request = request
	return GeneratedDelta{}, nil
}

func watchSentNames(watch *watchState) []string {
	return newSubscriptionView(watch).SentNames()
}

func selectionSnapshot(t *testing.T, resources []model.Resource) model.ResourceSet {
	t.Helper()
	snapshot, err := model.NewResourceSet(resources)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func selectionWorkload(t *testing.T, uid, namespace, node, service, policyName string) model.Resource {
	t.Helper()
	facts := model.ResourceFacts{Workload: &model.WorkloadResourceFacts{Namespace: namespace,
		WorkloadUID: uid,
		Source:      model.SourceRef{Registry: "kubernetes/test", Key: uid},
		NodeName:    node,
		Principal:   model.MustServiceAccountPrincipal(namespace, "default"),
	}}
	if service != "" {
		facts.Workload.ServiceKeys = []string{"demo/" + service}
	}
	authorizationPolicies := []string(nil)
	if policyName != "" {
		authorizationPolicies = []string{policyName}
		facts.Workload.AuthorizationRefs = []string{policyName}
	}
	resource, err := model.NewResource(
		model.ResourceKey{TypeURL: model.AddressType, Name: uid},
		"",
		testResourceContents(
			mustAny(&workloadv1.Address{Type: &workloadv1.Address_Workload{Workload: &workloadv1.Workload{
				Uid:                   uid,
				Namespace:             namespace,
				Node:                  node,
				AuthorizationPolicies: authorizationPolicies,
			}}}),
		),
		nil,
		facts,
	)
	if err != nil {
		t.Fatal(err)
	}
	return resource
}

func projectedWorkloads(
	t *testing.T,
	scope model.ClientScope,
	snapshot model.ResourceSet,
	names []string,
) []model.Resource {
	t.Helper()
	subscription := SubscriptionView{wildcard: names == nil, names: append([]string(nil), names...)}
	delta, err := (WorkloadGenerator{}).Generate(context.Background(), GenerationRequest{
		Scope:        scope,
		TypeURL:      model.WorkloadType,
		Subscription: subscription,
		Snapshot:     snapshot,
		Full:         true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return delta.Resources
}

func selectionService(t *testing.T, name string, aliases ...string) model.Resource {
	t.Helper()
	resource, err := model.NewResource(
		model.ResourceKey{TypeURL: model.AddressType, Name: name}, "",
		testResourceContents(mustAny(&workloadv1.Address{Type: &workloadv1.Address_Service{Service: &workloadv1.Service{
			Name: name,
		}}})), aliases, model.ResourceFacts{Service: &model.ServiceResourceFacts{ServiceKey: name}})
	if err != nil {
		t.Fatal(err)
	}
	return resource
}

func selectionWithGatewayReference(t *testing.T, resource model.Resource, gatewayKey string) model.Resource {
	t.Helper()
	facts := resource.Facts
	workload := *facts.Workload
	workload.GatewayReferences = append(append([]string(nil), workload.GatewayReferences...), gatewayKey)
	facts.Workload = &workload
	updated, err := model.NewResource(
		resource.Key,
		resource.XDSName,
		testResourceContents(testResourceValue(resource)),
		resource.Aliases,
		facts,
	)
	if err != nil {
		t.Fatal(err)
	}
	return updated
}

func selectionOwnedByGateway(t *testing.T, resource model.Resource, gatewayKey string) model.Resource {
	t.Helper()
	facts := resource.Facts
	facts.GatewayOwner = gatewayKey
	updated, err := model.NewResource(
		resource.Key,
		resource.XDSName,
		testResourceContents(testResourceValue(resource)),
		resource.Aliases,
		facts,
	)
	if err != nil {
		t.Fatal(err)
	}
	return updated
}

func selectionAuthorization(
	t *testing.T,
	name string,
	scope model.AuthorizationScope,
	namespace string,
) model.Resource {
	t.Helper()
	resource, err := model.NewResource(
		model.ResourceKey{TypeURL: model.WorkloadAuthorizationType, Name: name}, "",
		testResourceContents(mustWireAny(model.WorkloadAuthorizationType, &securityv1.Authorization{Name: name})), nil,
		model.ResourceFacts{Authorization: &model.AuthorizationResourceFacts{Scope: scope, Namespace: namespace}},
	)
	if err != nil {
		t.Fatal(err)
	}
	return resource
}

func selectedNames(resources []model.Resource) []string {
	names := make([]string, 0, len(resources))
	for _, resource := range resources {
		names = append(names, resource.XDSName)
	}
	slices.Sort(names)
	return names
}

func scaleWorkloadTransition(t testing.TB, resourceCount int) (
	model.ResourceSet, model.ResourceSet, xdsstore.Update, model.Resource,
) {
	t.Helper()
	resources := make([]model.Resource, 0, resourceCount)
	for index := range resourceCount {
		name := fmt.Sprintf("workload-%06d", index)
		resource, err := model.NewResource(
			model.ResourceKey{TypeURL: model.AddressType, Name: name},
			"",
			testResourceContents(
				&workloadv1.Address{
					Type: &workloadv1.Address_Workload{Workload: &workloadv1.Workload{Uid: name, Name: "old"}},
				},
			),
			nil,
			model.ResourceFacts{Workload: &model.WorkloadResourceFacts{Namespace: "demo",
				WorkloadUID: name,
				Source:      model.SourceRef{Registry: "kubernetes/test", Key: name},
				NodeName:    fmt.Sprintf("node-%03d", index%100),
				Principal:   model.MustServiceAccountPrincipal("demo", "default"),
			}},
		)
		if err != nil {
			t.Fatal(err)
		}
		resources = append(resources, resource)
	}
	before, err := model.NewResourceSet(resources)
	if err != nil {
		t.Fatal(err)
	}
	targetKey := model.ResourceKey{TypeURL: model.AddressType, Name: "workload-005050"}
	oldTarget, found := before.Get(targetKey)
	if !found {
		t.Fatalf("target Workload %q not found", targetKey.Name)
	}
	newTarget, err := model.NewResource(
		targetKey,
		"",
		testResourceContents(
			&workloadv1.Address{
				Type: &workloadv1.Address_Workload{Workload: &workloadv1.Workload{Uid: targetKey.Name, Name: "new"}},
			},
		),
		oldTarget.Aliases,
		oldTarget.Facts,
	)
	if err != nil {
		t.Fatal(err)
	}
	after, changed, err := before.Apply([]model.ResourceChange{{Key: targetKey, New: &newTarget}})
	if err != nil || !changed {
		t.Fatalf("build Workload transition: changed=%v err=%v", changed, err)
	}
	update := updateBetween(before, after, []model.ResourceChange{{
		Key: targetKey,
		Old: &oldTarget,
		New: &newTarget,
	}})
	return before, after, update, newTarget
}

// initializedSubscription models a completed initial response for generator tests
// that subsequently exercise incremental withdrawal or version suppression.
func initializedSubscription(t testing.TB, generator ResourceGenerator, scope model.ClientScope,
	typeURL string, snapshot model.ResourceSet, subscription SubscriptionView,
) SubscriptionView {
	t.Helper()
	delta, err := generator.Generate(context.Background(), GenerationRequest{
		Scope:        scope,
		TypeURL:      typeURL,
		Snapshot:     snapshot,
		Subscription: subscription,
		Full:         true,
	})
	if err != nil {
		t.Fatal(err)
	}
	subscription.sent = make(map[string]string)
	if !delta.elideSentState {
		for _, resource := range delta.Resources {
			subscription.sent[resource.XDSName] = resource.Hash
		}
	}
	return subscription
}

func (*fakeSecrets) SignerGeneration() uint64 { return 0 }

func testResourceContents(value proto.Message) model.ResourceGenerator {
	address := new(workloadv1.Address)
	switch typed := value.(type) {
	case *workloadv1.Address:
		address = proto.Clone(typed).(*workloadv1.Address)
	case *anypb.Any:
		if typed.GetTypeUrl() != model.AddressType {
			return model.Prebuilt(value)
		}
		if err := typed.UnmarshalTo(address); err != nil {
			panic(err)
		}
	default:
		return model.Prebuilt(value)
	}
	workload := address.GetWorkload()
	if workload == nil {
		return model.Prebuilt(value)
	}
	extensions := workload.Extensions
	workload.Extensions = nil
	return model.WorkloadContents(workload, extensions)
}

func testResourceValue(resource model.Resource) *anypb.Any {
	if resource.Value != nil {
		return resource.Value
	}
	encoded, err := resource.Generate(model.ClientScope{Class: model.ClientEgressGateway}, resource.Key.TypeURL)
	if err != nil {
		panic(err)
	}
	return encoded.Value
}
