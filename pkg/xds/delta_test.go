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
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/metrics"
	"github.com/openkruise/agentio/pkg/model"
)

func TestResponseResourceSizeCountsAnyPayloadBytes(t *testing.T) {
	resources := []*discoveryv3.Resource{
		{Resource: &anypb.Any{Value: make([]byte, 7)}},
		nil,
		{},
		{Resource: &anypb.Any{Value: make([]byte, 11)}},
	}
	if got := responseResourceSize(resources); got != 18 {
		t.Fatalf("responseResourceSize() = %d, want 18", got)
	}
}

func TestPushedUpdateRecordsDashboardCompatibilityLifecycle(t *testing.T) {
	previous := metrics.Default
	registry := metrics.NewRegistry()
	metrics.Default = registry
	t.Cleanup(func() { metrics.Default = previous })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	oldResource := addressResource(t, "cluster//Pod/demo/a", "old")
	newResource := addressResource(t, "cluster//Pod/demo/a", "new")
	server := newTestServer(t, ztunnelScope(), []model.Resource{oldResource}, nil)
	stream := newFakeStream(ctx, 4)
	done := server.start(stream)
	stream.send(nodeRequest(model.AddressType))
	stream.awaitResponses(t, model.AddressType, 1)

	if err := server.resources.apply([]model.ResourceChange{{
		Key: newResource.Key,
		Old: &oldResource,
		New: &newResource,
	}}); err != nil {
		t.Fatal(err)
	}
	stream.awaitResponses(t, model.AddressType, 2)

	recorder := httptest.NewRecorder()
	registry.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := recorder.Body.String()
	for _, metric := range []string{
		"pilot_xds_push_time_count{} 2",
		"pilot_xds_config_size_bytes_count{} 2",
		"pilot_proxy_queue_time_count{} 1",
		"pilot_proxy_convergence_time_count{} 1",
	} {
		if !strings.Contains(body, metric) {
			t.Fatalf("missing %q in metrics:\n%s", metric, body)
		}
	}

	if err := server.finish(t, stream, done); err != nil {
		t.Fatal(err)
	}
}

func TestPushFailuresAreRecordedByStage(t *testing.T) {
	valid := addressResource(t, "cluster//Pod/demo/a", "a")
	valid, err := valid.Encode(ztunnelScope(), model.AddressType)
	if err != nil {
		t.Fatal(err)
	}
	invalid := valid
	invalid.Value = &anypb.Any{TypeUrl: model.WorkloadType, Value: valid.Value.GetValue()}

	for _, tc := range []struct {
		name      string
		stage     string
		generator ResourceGenerator
		sendErr   error
	}{
		{
			name:      "generate",
			stage:     "generate",
			generator: &recordingGenerator{err: fmt.Errorf("generate failed")},
		},
		{
			name:      "validate",
			stage:     "validate",
			generator: &recordingGenerator{delta: GeneratedDelta{Resources: []model.Resource{invalid}}},
		},
		{
			name:      "send",
			stage:     "send",
			generator: &recordingGenerator{delta: GeneratedDelta{Resources: []model.Resource{valid}}},
			sendErr:   fmt.Errorf("send failed"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			previousMetrics := metrics.Default
			registry := metrics.NewRegistry()
			metrics.Default = registry
			t.Cleanup(func() { metrics.Default = previousMetrics })

			server := newTestServerWithGenerators(t, ztunnelScope(), nil, map[string]ResourceGenerator{
				model.AddressType: tc.generator,
			})
			stream := newFakeStream(context.Background(), 1)
			stream.setSendErr(tc.sendErr)
			watch := &watchState{names: sets.New[string](), sent: make(map[string]string)}
			err := server.server.generateAndSend(stream, log, watch, GenerationRequest{
				Scope:        server.scope,
				TypeURL:      model.AddressType,
				Subscription: newSubscriptionView(watch),
				Snapshot:     server.resources.Snapshot(),
				Full:         true,
			}, true, nil)
			if err == nil {
				t.Fatal("push unexpectedly succeeded")
			}

			recorder := httptest.NewRecorder()
			registry.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
			body := recorder.Body.String()
			line := fmt.Sprintf(
				`agentio_xds_push_failures_total{stage="%s",type="address"} 1`, tc.stage)
			if !strings.Contains(body, line+"\n") {
				t.Fatalf("metrics do not contain %q:\n%s", line, body)
			}
			if tc.stage == "send" {
				for _, line := range []string{
					"agentio_xds_pushes_total 0",
					"agentio_xds_push_duration_seconds_count{} 0",
					"pilot_xds_push_time_count{} 1",
					"pilot_xds_config_size_bytes_count{} 1",
				} {
					if !strings.Contains(body, line+"\n") {
						t.Fatalf("send-failure metrics do not contain %q:\n%s", line, body)
					}
				}
			}
		})
	}
}

type wrappedResourceGenerator struct {
	inner ResourceGenerator
}

func (g wrappedResourceGenerator) Generate(
	ctx context.Context,
	request GenerationRequest,
) (GeneratedDelta, error) {
	return g.inner.Generate(ctx, request)
}

func TestWildcardSubscriptionDeliversEveryAllowedResource(t *testing.T) {
	ctx := t.Context()
	server := newTestServer(t, ztunnelScope(), []model.Resource{
		addressResource(t, "cluster//Pod/demo/a", "a"),
		addressResource(t, "cluster//Pod/demo/b", "b"),
	}, nil)

	stream := newFakeStream(ctx, 4)
	stream.send(nodeRequest(model.AddressType))
	if err := server.run(t, stream); err != nil {
		t.Fatalf("stream: %v", err)
	}

	responses := stream.responsesFor(model.AddressType)
	if len(responses) != 1 {
		t.Fatalf("responses = %d, want 1", len(responses))
	}
	got := resourceNames(responses[0])
	if !slices.Equal(got, []string{"cluster//Pod/demo/a", "cluster//Pod/demo/b"}) {
		t.Fatalf("resources = %v", got)
	}
}

func TestExplicitWildcardReconnectWithLargeCache(t *testing.T) {
	ctx := t.Context()
	unchanged := addressResource(t, "cluster//Pod/demo/unchanged", "unchanged")
	updated := addressResource(t, "cluster//Pod/demo/updated", "updated")
	added := addressResource(t, "cluster//Pod/demo/added", "added")
	server := newTestServer(t, ztunnelScope(), []model.Resource{unchanged, updated, added}, nil)
	encoded, err := unchanged.Encode(ztunnelScope(), model.AddressType)
	if err != nil {
		t.Fatal(err)
	}
	initial := map[string]string{unchanged.XDSName: encoded.Hash, updated.XDSName: "old-version"}
	removed := make([]string, 0, 29_998)
	for i := range 29_998 {
		name := fmt.Sprintf("cluster//Pod/demo/removed-%05d", i)
		initial[name] = "old-version"
		removed = append(removed, name)
	}
	stream := newFakeStream(ctx, 4)
	watch := &watchState{names: sets.New[string](), sent: map[string]string{}}
	watches := map[string]*watchState{model.AddressType: watch}
	subscription := server.resources.Subscribe(ctx, model.ClientScope{})
	if err := server.server.handleRequest(stream, server.scope, log, watches, subscription,
		&discoveryv3.DeltaDiscoveryRequest{
			TypeUrl:                 model.AddressType,
			ResourceNamesSubscribe:  []string{"*"},
			InitialResourceVersions: initial,
		}); err != nil {
		t.Fatal(err)
	}
	responses := stream.responsesFor(model.AddressType)
	if len(responses) != 1 {
		t.Fatalf("responses = %d, want 1", len(responses))
	}
	if got := resourceNames(responses[0]); !slices.Equal(got, []string{added.XDSName, updated.XDSName}) {
		t.Fatalf("resources = %v, want added and updated resources only", got)
	}
	if got := responses[0].GetRemovedResources(); !slices.Equal(got, removed) {
		t.Fatalf("removals do not match the %d stale cache entries", len(removed))
	}
	if !watch.wildcard || len(watch.names) != 0 || len(watch.sent) != 0 {
		t.Fatalf("wildcard=%t names=%d sent=%d, want wildcard without retained names or versions",
			watch.wildcard, len(watch.names), len(watch.sent))
	}
}

func TestWildcardWDSDoesNotRetainSentHashes(t *testing.T) {
	const resourceCount = 4_096
	resources := make([]model.Resource, 0, resourceCount)
	for index := range resourceCount {
		name := fmt.Sprintf("cluster//Pod/demo/pod-%04d", index)
		resources = append(resources, addressResource(t, name, name))
	}
	server := newTestServer(t, ztunnelScope(), resources, nil)
	stream := newFakeStream(context.Background(), 1)
	watch := &watchState{
		wildcard: true,
		started:  true,
		names:    sets.New[string](),
		sent:     map[string]string{},
	}

	if err := server.server.sendDiff(stream, server.scope, log, model.AddressType, watch, true); err != nil {
		t.Fatal(err)
	}
	if got := len(stream.responsesFor(model.AddressType)[0].GetResources()); got != resourceCount {
		t.Fatalf("initial resources = %d, want %d", got, resourceCount)
	}
	if len(watch.sent) != 0 {
		t.Fatalf("wildcard WDS retained %d sent hashes, want none", len(watch.sent))
	}
}

func TestWrappedWorkloadGeneratorPreservesWildcardStateElision(t *testing.T) {
	resource := addressResource(t, "cluster//Pod/demo/a", "a")
	server := newTestServerWithGenerators(t, ztunnelScope(), []model.Resource{resource}, map[string]ResourceGenerator{
		model.AddressType: wrappedResourceGenerator{inner: WorkloadGenerator{}},
	})
	stream := newFakeStream(context.Background(), 2)
	watch := &watchState{
		wildcard: true,
		started:  true,
		names:    sets.New[string](),
		sent:     map[string]string{},
	}

	if err := server.server.sendDiff(stream, server.scope, log, model.AddressType, watch, true); err != nil {
		t.Fatal(err)
	}
	if len(watch.sent) != 0 {
		t.Fatalf("wrapped workload generator retained sent state: %v", watch.sent)
	}
	if err := server.resources.apply([]model.ResourceChange{{Key: resource.Key}}); err != nil {
		t.Fatal(err)
	}
	update := updateReversedFrom(t, server.resources.Snapshot(), []model.ResourceChange{{
		Key: resource.Key,
		Old: &resource,
	}})
	if err := server.server.sendIncremental(stream, server.scope, log, model.AddressType, watch, update); err != nil {
		t.Fatal(err)
	}
	responses := stream.responsesFor(model.AddressType)
	if len(responses) != 2 || !slices.Equal(responses[1].GetRemovedResources(), []string{resource.XDSName}) {
		t.Fatalf("wrapped workload removal responses = %#v", responses)
	}
	if len(watch.sent) != 0 {
		t.Fatalf("wrapped workload incremental response retained sent state: %v", watch.sent)
	}
}

func TestWildcardSnapshotGeneratorRetainsSentStateForIncrementalRemoval(t *testing.T) {
	resource := gatewayResource(t, "demo/egress", "cluster-a", "a")
	server := newTestServerWithGenerators(t, gatewayScope(), []model.Resource{resource}, map[string]ResourceGenerator{
		model.ClusterType: SnapshotGenerator{},
	})
	stream := newFakeStream(context.Background(), 2)
	watch := &watchState{
		wildcard: true,
		started:  true,
		names:    sets.New[string](),
		sent:     map[string]string{},
	}

	if err := server.server.sendDiff(stream, server.scope, log, model.ClusterType, watch, true); err != nil {
		t.Fatal(err)
	}
	if got := watch.sent[resource.XDSName]; got != resource.Hash {
		t.Fatalf("snapshot generator sent hash = %q, want %q", got, resource.Hash)
	}
	if err := server.resources.apply([]model.ResourceChange{{Key: resource.Key}}); err != nil {
		t.Fatal(err)
	}
	update := updateReversedFrom(t, server.resources.Snapshot(), []model.ResourceChange{{
		Key: resource.Key,
		Old: &resource,
	}})
	if err := server.server.sendIncremental(stream, server.scope, log, model.ClusterType, watch, update); err != nil {
		t.Fatal(err)
	}
	responses := stream.responsesFor(model.ClusterType)
	if len(responses) != 2 {
		t.Fatalf("responses = %d, want initial response and incremental removal", len(responses))
	}
	if got := responses[1].GetRemovedResources(); !slices.Equal(got, []string{resource.XDSName}) {
		t.Fatalf("incremental removals = %v, want %s", got, resource.XDSName)
	}
}

func TestWildcardWDSInitialVersionsIncrementalRemovalAndSubscriptionTransitions(t *testing.T) {
	ctx := t.Context()
	resourceA := addressResource(t, "cluster//Pod/demo/a", "a")
	resourceB := addressResource(t, "cluster//Pod/demo/b", "b")
	server := newTestServer(t, ztunnelScope(), []model.Resource{resourceA, resourceB}, nil)
	stream := newFakeStream(ctx, 8)
	watch := &watchState{names: sets.New[string](), sent: map[string]string{}}
	initialSentStorage := watch.sent
	watches := map[string]*watchState{model.AddressType: watch}
	subscription := server.resources.Subscribe(ctx, model.ClientScope{})

	encoded, err := resourceA.Encode(ztunnelScope(), model.AddressType)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.server.handleRequest(stream, server.scope, log, watches, subscription,
		&discoveryv3.DeltaDiscoveryRequest{
			TypeUrl: model.AddressType,
			InitialResourceVersions: map[string]string{
				resourceA.XDSName:        encoded.Hash,
				"cluster//Pod/demo/gone": "old-version",
			},
		}); err != nil {
		t.Fatal(err)
	}
	initial := stream.responsesFor(model.AddressType)[0]
	if got := resourceNames(initial); !slices.Equal(got, []string{resourceB.XDSName}) {
		t.Fatalf("initial resources = %v, want only %s", got, resourceB.XDSName)
	}
	if got := initial.GetRemovedResources(); !slices.Equal(got, []string{"cluster//Pod/demo/gone"}) {
		t.Fatalf("initial removals = %v, want cluster//Pod/demo/gone", got)
	}
	if len(watch.sent) != 0 {
		t.Fatalf("wildcard initial response retained sent hashes: %v", watch.sent)
	}
	if len(initialSentStorage) != 2 {
		t.Fatalf(
			"wildcard initial response cleared rather than released the %d-entry transient map",
			len(initialSentStorage),
		)
	}

	if err := server.server.handleRequest(stream, server.scope, log, watches, subscription,
		&discoveryv3.DeltaDiscoveryRequest{
			TypeUrl:                  model.AddressType,
			ResponseNonce:            initial.GetNonce(),
			ResourceNamesSubscribe:   []string{resourceA.XDSName},
			ResourceNamesUnsubscribe: []string{"*"},
		}); err != nil {
		t.Fatal(err)
	}
	if watch.wildcard {
		t.Fatal("wildcard-to-named transition remained wildcard")
	}
	if got := resourceNames(
		stream.responsesFor(model.AddressType)[1],
	); !slices.Equal(
		got,
		[]string{resourceA.XDSName},
	) {
		t.Fatalf("wildcard-to-named resources = %v, want %s", got, resourceA.XDSName)
	}
	if got := watch.sent[resourceA.XDSName]; got != encoded.Hash {
		t.Fatalf("named sent version = %q, want %q", got, encoded.Hash)
	}

	if err := server.resources.apply([]model.ResourceChange{{Key: resourceA.Key}}); err != nil {
		t.Fatal(err)
	}
	deleteUpdate := updateReversedFrom(t, server.resources.Snapshot(), []model.ResourceChange{{
		Key: resourceA.Key,
		Old: &resourceA,
	}})
	if err := server.server.sendIncremental(
		stream,
		server.scope,
		log,
		model.AddressType,
		watch,
		deleteUpdate,
	); err != nil {
		t.Fatal(err)
	}
	removed := stream.responsesFor(model.AddressType)[2]
	if got := removed.GetRemovedResources(); !slices.Equal(got, []string{resourceA.XDSName}) {
		t.Fatalf("named incremental removals = %v, want %s", got, resourceA.XDSName)
	}

	resourceC := addressResource(t, "cluster//Pod/demo/c", "c")
	if err := server.resources.apply([]model.ResourceChange{{Key: resourceC.Key, New: &resourceC}}); err != nil {
		t.Fatal(err)
	}
	addUpdate := updateReversedFrom(t, server.resources.Snapshot(), []model.ResourceChange{{
		Key: resourceC.Key,
		New: &resourceC,
	}})
	if err := server.server.sendIncremental(
		stream,
		server.scope,
		log,
		model.AddressType,
		watch,
		addUpdate,
	); err != nil {
		t.Fatal(err)
	}
	if got := len(stream.responsesFor(model.AddressType)); got != 3 {
		t.Fatalf("named watch received unsubscribed uid-c: responses=%d", got)
	}

	if err := server.server.handleRequest(stream, server.scope, log, watches, subscription,
		&discoveryv3.DeltaDiscoveryRequest{
			TypeUrl:                model.AddressType,
			ResponseNonce:          removed.GetNonce(),
			ResourceNamesSubscribe: []string{"*"},
		}); err != nil {
		t.Fatal(err)
	}
	wildcard := stream.responsesFor(model.AddressType)[3]
	if got := resourceNames(wildcard); !slices.Equal(got, []string{resourceB.XDSName, resourceC.XDSName}) {
		t.Fatalf("named-to-wildcard resources = %v, want %s and %s", got, resourceB.XDSName, resourceC.XDSName)
	}
	if len(watch.sent) != 0 {
		t.Fatalf("named-to-wildcard response retained sent hashes: %v", watch.sent)
	}

	if err := server.resources.apply([]model.ResourceChange{{Key: resourceB.Key}}); err != nil {
		t.Fatal(err)
	}
	wildcardDelete := updateReversedFrom(t, server.resources.Snapshot(), []model.ResourceChange{{
		Key: resourceB.Key,
		Old: &resourceB,
	}})
	if err := server.server.sendIncremental(
		stream,
		server.scope,
		log,
		model.AddressType,
		watch,
		wildcardDelete,
	); err != nil {
		t.Fatal(err)
	}
	last := stream.responsesFor(model.AddressType)[4]
	if got := last.GetRemovedResources(); !slices.Equal(got, []string{resourceB.XDSName}) {
		t.Fatalf("wildcard incremental removals = %v, want %s", got, resourceB.XDSName)
	}
	if len(watch.sent) != 0 {
		t.Fatalf("wildcard incremental response retained sent hashes: %v", watch.sent)
	}
}

func TestWildcardAddressIncrementalMembershipUsesExactChanges(t *testing.T) {
	service := selectionService(t, "demo/svc-a", "/10.96.0.1")
	oldWorkload := selectionWorkload(t, "uid-a", "demo", "node-a", "svc-a", "")
	scope := model.ClientScope{
		Class:     model.ClientSharedZTunnel,
		Principal: model.MustServiceAccountPrincipal("demo", "ztunnel"),
		NodeName:  "node-a",
	}
	server := newTestServer(t, scope, []model.Resource{service, oldWorkload}, nil)
	stream := newFakeStream(context.Background(), 4)
	watch := &watchState{
		wildcard: true,
		started:  true,
		names:    sets.New[string](),
		sent:     map[string]string{},
	}

	if err := server.resources.apply([]model.ResourceChange{{Key: oldWorkload.Key}}); err != nil {
		t.Fatal(err)
	}
	deleteUpdate := updateReversedFrom(t, server.resources.Snapshot(), []model.ResourceChange{{
		Key: oldWorkload.Key,
		Old: &oldWorkload,
	}})
	if err := server.server.sendIncremental(stream, scope, log, model.AddressType, watch, deleteUpdate); err != nil {
		t.Fatal(err)
	}
	responses := stream.responsesFor(model.AddressType)
	if len(responses) != 1 {
		t.Fatalf("delete responses = %d, want 1", len(responses))
	}
	wantRemoved := []string{service.XDSName, oldWorkload.XDSName}
	if got := responses[0].GetRemovedResources(); !slices.Equal(got, wantRemoved) {
		t.Fatalf("delete removals = %v, want %v", got, wantRemoved)
	}

	newWorkload := selectionWorkload(t, "uid-b", "demo", "node-a", "svc-a", "")
	if err := server.resources.apply([]model.ResourceChange{{Key: newWorkload.Key, New: &newWorkload}}); err != nil {
		t.Fatal(err)
	}
	addUpdate := updateReversedFrom(t, server.resources.Snapshot(), []model.ResourceChange{{
		Key: newWorkload.Key,
		New: &newWorkload,
	}})
	if err := server.server.sendIncremental(stream, scope, log, model.AddressType, watch, addUpdate); err != nil {
		t.Fatal(err)
	}
	responses = stream.responsesFor(model.AddressType)
	wantAdded := []string{service.XDSName, newWorkload.XDSName}
	if got := resourceNames(responses[1]); !slices.Equal(got, wantAdded) {
		t.Fatalf("add resources = %v, want %v", got, wantAdded)
	}
	if len(watch.sent) != 0 {
		t.Fatalf("incremental membership responses retained sent hashes: %v", watch.sent)
	}
}

func TestWildcardWorkloadIncrementalDeleteUsesExactChange(t *testing.T) {
	oldWorkload := selectionWorkload(t, "uid-a", "demo", "node-a", "", "")
	scope := gatewayScope()
	server := newTestServer(t, scope, []model.Resource{oldWorkload}, nil)
	stream := newFakeStream(context.Background(), 2)
	watch := &watchState{
		wildcard: true,
		started:  true,
		names:    sets.New[string](),
		sent:     map[string]string{},
	}
	if err := server.server.sendDiff(stream, scope, log, model.WorkloadType, watch, true); err != nil {
		t.Fatal(err)
	}
	if initial := stream.responsesFor(model.WorkloadType); len(initial) != 1 || len(initial[0].GetResources()) != 1 {
		t.Fatalf("initial Workload responses = %#v, want one resource", initial)
	}
	if err := server.resources.apply([]model.ResourceChange{{Key: oldWorkload.Key}}); err != nil {
		t.Fatal(err)
	}
	update := updateReversedFrom(t, server.resources.Snapshot(), []model.ResourceChange{{
		Key: oldWorkload.Key,
		Old: &oldWorkload,
	}})

	if err := server.server.sendIncremental(stream, scope, log, model.WorkloadType, watch, update); err != nil {
		t.Fatal(err)
	}
	responses := stream.responsesFor(model.WorkloadType)
	if len(responses) != 2 {
		t.Fatalf("responses = %d, want initial response and removal", len(responses))
	}
	if got := responses[1].GetRemovedResources(); !slices.Equal(got, []string{oldWorkload.XDSName}) {
		t.Fatalf("removed = %v, want %s", got, oldWorkload.XDSName)
	}
	if len(watch.sent) != 0 {
		t.Fatalf("incremental Workload response retained sent hashes: %v", watch.sent)
	}
}

func TestNamedSubscriptionDeliversOnlyRequestedResources(t *testing.T) {
	ctx := t.Context()
	server := newTestServer(t, ztunnelScope(), []model.Resource{
		addressResource(t, "cluster//Pod/demo/a", "a"),
		addressResource(t, "cluster//Pod/demo/b", "b"),
	}, nil)

	stream := newFakeStream(ctx, 4)
	stream.send(nodeRequest(model.AddressType, "cluster//Pod/demo/b"))
	if err := server.run(t, stream); err != nil {
		t.Fatalf("stream: %v", err)
	}

	got := resourceNames(stream.responsesFor(model.AddressType)[0])
	if !slices.Equal(got, []string{"cluster//Pod/demo/b"}) {
		t.Fatalf("resources = %v, want only the subscribed name", got)
	}
}

// A resource can be requested by any of its aliases, which is how ztunnel asks
// for a workload by IP rather than by UID.
func TestNamedSubscriptionMatchesAliases(t *testing.T) {
	ctx := t.Context()
	server := newTestServer(t, ztunnelScope(), []model.Resource{
		addressResource(t, "cluster//Pod/demo/a", "a", "/10.1.0.1"),
	}, nil)

	stream := newFakeStream(ctx, 4)
	stream.send(nodeRequest(model.AddressType, "/10.1.0.1"))
	if err := server.run(t, stream); err != nil {
		t.Fatalf("stream: %v", err)
	}

	responses := stream.responsesFor(model.AddressType)
	if len(responses) != 1 || len(responses[0].GetResources()) != 1 {
		t.Fatalf("alias subscription did not deliver the resource: %v", responses)
	}
	if got := responses[0].GetResources()[0].GetName(); got != "cluster//Pod/demo/a" {
		t.Fatalf("resource name = %q, want the canonical name", got)
	}
}

func TestNamedServiceSubscriptionTracksEndpointScopeAndDeletion(t *testing.T) {
	ctx := t.Context()
	workloadA := selectionWorkload(t, "uid-a", "demo", "node-a", "svc-a", "")
	service := selectionService(t, "demo/svc-a", "/10.96.0.1")
	scope := model.ClientScope{
		Class:     model.ClientSharedZTunnel,
		Principal: model.MustServiceAccountPrincipal("demo", "ztunnel"),
		NodeName:  "node-a",
	}
	server := newTestServer(t, scope, []model.Resource{workloadA, service}, nil)
	stream := newFakeStream(ctx, 8)
	done := server.start(stream)
	stream.send(nodeRequest(model.AddressType, "/10.96.0.1"))
	responses := stream.awaitResponses(t, model.AddressType, 1)
	if got := resourceNames(responses[0]); !slices.Equal(got, []string{"demo/svc-a", "uid-a"}) {
		t.Fatalf("initial resources = %v, want service and node-local endpoint", got)
	}

	updatedWorkloadA, err := model.NewResource(
		workloadA.Key,
		workloadA.XDSName,
		testResourceContents(testResourceValue(workloadA)),
		[]string{"uid-a-alias"},
		workloadA.Facts,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.resources.apply(
		[]model.ResourceChange{{Key: updatedWorkloadA.Key, New: &updatedWorkloadA}},
	); err != nil {
		t.Fatal(err)
	}
	responses = stream.awaitResponses(t, model.AddressType, 2)
	if got := resourceNames(responses[1]); !slices.Equal(got, []string{"uid-a"}) {
		t.Fatalf("endpoint update resources = %v, want updated derived endpoint", got)
	}

	workloadB := selectionWorkload(t, "uid-b", "demo", "node-a", "svc-a", "")
	if err := server.resources.apply([]model.ResourceChange{{Key: workloadB.Key, New: &workloadB}}); err != nil {
		t.Fatal(err)
	}
	responses = stream.awaitResponses(t, model.AddressType, 3)
	if got := resourceNames(responses[2]); !slices.Equal(got, []string{"uid-b"}) {
		t.Fatalf("endpoint add resources = %v, want new derived endpoint", got)
	}

	movedWorkloadB := selectionWorkload(t, "uid-b", "demo", "node-b", "svc-a", "")
	if err := server.resources.apply(
		[]model.ResourceChange{{Key: movedWorkloadB.Key, New: &movedWorkloadB}},
	); err != nil {
		t.Fatal(err)
	}
	responses = stream.awaitResponses(t, model.AddressType, 4)
	if got := resourceNames(responses[3]); !slices.Equal(got, []string{"uid-b"}) {
		t.Fatalf("endpoint scope move resources = %v, want subscribed remote endpoint update", got)
	}
	if got := responses[3].GetRemovedResources(); len(got) != 0 {
		t.Fatalf("endpoint scope move removed = %v, want none while Service remains subscribed", got)
	}

	if err := server.resources.apply([]model.ResourceChange{{Key: service.Key}}); err != nil {
		t.Fatal(err)
	}
	responses = stream.awaitResponses(t, model.AddressType, 5)
	if got := responses[4].GetRemovedResources(); !slices.Equal(got, []string{"demo/svc-a", "uid-b"}) {
		t.Fatalf(
			"service deletion removed = %v, want service and remote endpoint; node-local endpoint remains implicit",
			got,
		)
	}

	if err := server.finish(t, stream, done); err != nil {
		t.Fatalf("stream: %v", err)
	}
}

func TestNamedServiceUnsubscribeRemovesDerivedWorkloads(t *testing.T) {
	ctx := t.Context()
	workload := selectionWorkload(t, "uid-a", "demo", "node-a", "svc-a", "")
	service := selectionService(t, "demo/svc-a", "/10.96.0.1")
	scope := model.ClientScope{
		Class:     model.ClientSharedZTunnel,
		Principal: model.MustServiceAccountPrincipal("demo", "ztunnel"),
		NodeName:  "node-a",
	}
	server := newTestServer(t, scope, []model.Resource{workload, service}, nil)
	stream := newFakeStream(ctx, 4)
	done := server.start(stream)
	stream.send(nodeRequest(model.AddressType, "/10.96.0.1"))
	first := stream.awaitResponses(t, model.AddressType, 1)[0]
	stream.send(&discoveryv3.DeltaDiscoveryRequest{
		TypeUrl:                  model.AddressType,
		ResponseNonce:            first.GetNonce(),
		ResourceNamesUnsubscribe: []string{"/10.96.0.1"},
	})
	responses := stream.awaitResponses(t, model.AddressType, 2)
	if got := responses[1].GetRemovedResources(); !slices.Equal(got, []string{"demo/svc-a"}) {
		t.Fatalf("unsubscribe removed = %v, want service only; node-local endpoint remains implicit", got)
	}
	if err := server.finish(t, stream, done); err != nil {
		t.Fatalf("stream: %v", err)
	}
}

func TestGatewayNamedServiceSubscriptionTracksEndpointMembership(t *testing.T) {
	ctx := t.Context()
	workload := selectionWorkload(t, "uid-a", "demo", "node-a", "svc-a", "")
	service := selectionService(t, "demo/svc-a", "/10.96.0.1")
	server := newTestServer(t, gatewayScope(), []model.Resource{workload, service}, nil)
	stream := newFakeStream(ctx, 4)
	done := server.start(stream)
	stream.send(nodeRequest(model.AddressType, "/10.96.0.1"))
	first := stream.awaitResponses(t, model.AddressType, 1)
	if got := resourceNames(first[0]); !slices.Equal(got, []string{"demo/svc-a", "uid-a"}) {
		t.Fatalf("initial gateway resources = %v", got)
	}

	detached := selectionWorkload(t, "uid-a", "demo", "node-a", "", "")
	if err := server.resources.apply([]model.ResourceChange{{Key: detached.Key, New: &detached}}); err != nil {
		t.Fatal(err)
	}
	responses := stream.awaitResponses(t, model.AddressType, 2)
	if got := responses[1].GetRemovedResources(); !slices.Equal(got, []string{"uid-a"}) {
		t.Fatalf("detached gateway endpoint removed = %v, want uid-a", got)
	}
	if err := server.finish(t, stream, done); err != nil {
		t.Fatalf("stream: %v", err)
	}
}

func TestGatewayWorkloadTypeNamedServiceTracksCrossTypeLifecycle(t *testing.T) {
	ctx := t.Context()
	workloadA := selectionWorkload(t, "uid-a", "demo", "node-a", "svc-a", "")
	service := selectionService(t, "demo/svc-a", "/10.96.0.1")
	server := newTestServer(t, gatewayScope(), []model.Resource{workloadA, service}, nil)
	stream := newFakeStream(ctx, 16)
	done := server.start(stream)
	stream.send(nodeRequest(model.WorkloadType, "/10.96.0.1"))
	responses := stream.awaitResponses(t, model.WorkloadType, 1)
	if got := resourceNames(responses[0]); !slices.Equal(got, []string{"uid-a"}) {
		t.Fatalf("initial Workload resources = %v, want service endpoint only", got)
	}

	workloadB := selectionWorkload(t, "uid-b", "demo", "node-b", "svc-a", "")
	if err := server.resources.apply([]model.ResourceChange{{Key: workloadB.Key, New: &workloadB}}); err != nil {
		t.Fatal(err)
	}
	responses = stream.awaitResponses(t, model.WorkloadType, 2)
	if got := resourceNames(responses[1]); !slices.Equal(got, []string{"uid-b"}) {
		t.Fatalf("added Workload resources = %v, want uid-b", got)
	}

	updatedWorkloadB, err := model.NewResource(
		workloadB.Key,
		workloadB.XDSName,
		testResourceContents(testResourceValue(workloadB)),
		[]string{"uid-b-alias"},
		workloadB.Facts,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.resources.apply(
		[]model.ResourceChange{{Key: updatedWorkloadB.Key, New: &updatedWorkloadB}},
	); err != nil {
		t.Fatal(err)
	}
	responses = stream.awaitResponses(t, model.WorkloadType, 3)
	if got := resourceNames(responses[2]); !slices.Equal(got, []string{"uid-b"}) {
		t.Fatalf("updated Workload resources = %v, want uid-b", got)
	}

	detachedWorkloadB := selectionWorkload(t, "uid-b", "demo", "node-b", "", "")
	if err := server.resources.apply(
		[]model.ResourceChange{{Key: detachedWorkloadB.Key, New: &detachedWorkloadB}},
	); err != nil {
		t.Fatal(err)
	}
	responses = stream.awaitResponses(t, model.WorkloadType, 4)
	if got := responses[3].GetRemovedResources(); !slices.Equal(got, []string{"uid-b"}) {
		t.Fatalf("detached Workload removals = %v, want uid-b", got)
	}

	aliasedService, err := model.NewResource(
		service.Key,
		service.XDSName,
		testResourceContents(testResourceValue(service)),
		[]string{"/10.96.0.9"},
		service.Facts,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.resources.apply(
		[]model.ResourceChange{{Key: aliasedService.Key, New: &aliasedService}},
	); err != nil {
		t.Fatal(err)
	}
	responses = stream.awaitResponses(t, model.WorkloadType, 5)
	if got := responses[4].GetRemovedResources(); !slices.Equal(got, []string{"uid-a"}) {
		t.Fatalf("service alias change removals = %v, want uid-a", got)
	}

	stream.send(&discoveryv3.DeltaDiscoveryRequest{
		TypeUrl:                  model.WorkloadType,
		ResponseNonce:            responses[4].GetNonce(),
		ResourceNamesSubscribe:   []string{"/10.96.0.9"},
		ResourceNamesUnsubscribe: []string{"/10.96.0.1"},
	})
	responses = stream.awaitResponses(t, model.WorkloadType, 6)
	if got := resourceNames(responses[5]); !slices.Equal(got, []string{"uid-a"}) {
		t.Fatalf("new service alias resources = %v, want uid-a", got)
	}

	stream.send(&discoveryv3.DeltaDiscoveryRequest{
		TypeUrl:                  model.WorkloadType,
		ResponseNonce:            responses[5].GetNonce(),
		ResourceNamesUnsubscribe: []string{"/10.96.0.9"},
	})
	responses = stream.awaitResponses(t, model.WorkloadType, 7)
	if got := responses[6].GetRemovedResources(); !slices.Equal(got, []string{"uid-a"}) {
		t.Fatalf("service unsubscribe removals = %v, want uid-a", got)
	}

	stream.send(&discoveryv3.DeltaDiscoveryRequest{
		TypeUrl:                model.WorkloadType,
		ResponseNonce:          responses[6].GetNonce(),
		ResourceNamesSubscribe: []string{"/10.96.0.9"},
	})
	responses = stream.awaitResponses(t, model.WorkloadType, 8)
	if got := resourceNames(responses[7]); !slices.Equal(got, []string{"uid-a"}) {
		t.Fatalf("resubscribed service resources = %v, want uid-a", got)
	}

	if err := server.resources.apply([]model.ResourceChange{{Key: aliasedService.Key}}); err != nil {
		t.Fatal(err)
	}
	responses = stream.awaitResponses(t, model.WorkloadType, 9)
	if got := responses[8].GetRemovedResources(); !slices.Equal(got, []string{"uid-a"}) {
		t.Fatalf("service deletion removals = %v, want uid-a", got)
	}
	if err := server.finish(t, stream, done); err != nil {
		t.Fatalf("stream: %v", err)
	}
}

func TestNodeNamedAddressSubscriptionTracksAllLocalWorkloads(t *testing.T) {
	ctx := t.Context()
	serviceA := selectionService(t, "demo/svc-a", "/10.96.0.1")
	serviceB := selectionService(t, "demo/svc-b", "/10.96.0.2")
	localA := selectionWorkload(t, "uid-a", "demo", "node-a", "svc-a", "")
	localB := selectionWorkload(t, "uid-b", "demo", "node-a", "svc-b", "")
	remote := selectionWorkload(t, "uid-remote", "demo", "node-b", "svc-a", "")
	scope := model.ClientScope{
		Class:     model.ClientSharedZTunnel,
		Principal: model.MustServiceAccountPrincipal("demo", "ztunnel"),
		NodeName:  "node-a",
	}
	server := newTestServer(t, scope, []model.Resource{serviceA, serviceB, localA, localB, remote}, nil)
	stream := newFakeStream(ctx, 16)
	done := server.start(stream)
	stream.send(nodeRequest(model.AddressType, "/10.96.0.1"))
	responses := stream.awaitResponses(t, model.AddressType, 1)
	if got := resourceNames(responses[0]); !slices.Equal(got, []string{"demo/svc-a", "uid-a", "uid-b", "uid-remote"}) {
		t.Fatalf("initial node resources = %v, want subscribed service, all endpoints, and every local workload", got)
	}

	updatedLocalB, err := model.NewResource(
		localB.Key,
		localB.XDSName,
		testResourceContents(testResourceValue(localB)),
		[]string{"uid-b-alias"},
		localB.Facts,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.resources.apply(
		[]model.ResourceChange{{Key: updatedLocalB.Key, New: &updatedLocalB}},
	); err != nil {
		t.Fatal(err)
	}
	responses = stream.awaitResponses(t, model.AddressType, 2)
	if got := resourceNames(responses[1]); !slices.Equal(got, []string{"uid-b"}) {
		t.Fatalf("local update resources = %v, want uid-b", got)
	}

	localC := selectionWorkload(t, "uid-c", "demo", "node-a", "svc-b", "")
	if err := server.resources.apply([]model.ResourceChange{{Key: localC.Key, New: &localC}}); err != nil {
		t.Fatal(err)
	}
	responses = stream.awaitResponses(t, model.AddressType, 3)
	if got := resourceNames(responses[2]); !slices.Equal(got, []string{"uid-c"}) {
		t.Fatalf("local add resources = %v, want uid-c", got)
	}

	movedLocalC := selectionWorkload(t, "uid-c", "demo", "node-b", "svc-b", "")
	if err := server.resources.apply([]model.ResourceChange{{Key: movedLocalC.Key, New: &movedLocalC}}); err != nil {
		t.Fatal(err)
	}
	responses = stream.awaitResponses(t, model.AddressType, 4)
	if got := responses[3].GetRemovedResources(); !slices.Equal(got, []string{"uid-c"}) {
		t.Fatalf("local move removals = %v, want uid-c", got)
	}

	if err := server.resources.apply([]model.ResourceChange{{Key: updatedLocalB.Key}}); err != nil {
		t.Fatal(err)
	}
	responses = stream.awaitResponses(t, model.AddressType, 5)
	if got := responses[4].GetRemovedResources(); !slices.Equal(got, []string{"uid-b"}) {
		t.Fatalf("local delete removals = %v, want uid-b", got)
	}

	stream.send(&discoveryv3.DeltaDiscoveryRequest{
		TypeUrl:                  model.AddressType,
		ResponseNonce:            responses[4].GetNonce(),
		ResourceNamesUnsubscribe: []string{"/10.96.0.1"},
	})
	responses = stream.awaitResponses(t, model.AddressType, 6)
	if got := responses[5].GetRemovedResources(); !slices.Equal(got, []string{"demo/svc-a", "uid-remote"}) {
		t.Fatalf("VIP unsubscribe removals = %v, want service and remote derived endpoint", got)
	}
	if err := server.finish(t, stream, done); err != nil {
		t.Fatalf("stream: %v", err)
	}
}

func TestAuthorizationSelectionMovesWithWorkloadReference(t *testing.T) {
	ctx := t.Context()
	oldWorkload := selectionWorkload(t, "uid-a", "demo", "node-a", "", "demo/selector-a")
	newWorkload := selectionWorkload(t, "uid-a", "demo", "node-a", "", "demo/selector-b")
	authorizationA := selectionAuthorization(t, "demo/selector-a", model.AuthorizationScopeWorkload, "")
	authorizationB := selectionAuthorization(t, "demo/selector-b", model.AuthorizationScopeWorkload, "")
	scope := model.ClientScope{
		Class:       model.ClientDedicatedZTunnel,
		Principal:   model.MustServiceAccountPrincipal("demo", "default"),
		WorkloadUID: "uid-a",
		Source:      model.SourceRef{Registry: "kubernetes/test", Key: "uid-a"},
	}
	server := newTestServer(t, scope, []model.Resource{oldWorkload, authorizationA, authorizationB}, nil)
	stream := newFakeStream(ctx, 4)
	done := server.start(stream)
	stream.send(nodeRequest(model.WorkloadAuthorizationType))
	first := stream.awaitResponses(t, model.WorkloadAuthorizationType, 1)
	if got := resourceNames(first[0]); !slices.Equal(got, []string{"demo/selector-a"}) {
		t.Fatalf("initial authorizations = %v", got)
	}

	if err := server.resources.apply([]model.ResourceChange{{Key: newWorkload.Key, New: &newWorkload}}); err != nil {
		t.Fatal(err)
	}
	responses := stream.awaitResponses(t, model.WorkloadAuthorizationType, 2)
	if got := resourceNames(responses[1]); !slices.Equal(got, []string{"demo/selector-b"}) {
		t.Fatalf("updated authorizations = %v, want selector-b", got)
	}
	if got := responses[1].GetRemovedResources(); !slices.Equal(got, []string{"demo/selector-a"}) {
		t.Fatalf("removed authorizations = %v, want selector-a", got)
	}
	if err := server.finish(t, stream, done); err != nil {
		t.Fatalf("stream: %v", err)
	}
}

// Regression: a stale nonce must not discard the subscription carried in the same request.
func TestStaleNonceStillAppliesSubscription(t *testing.T) {
	ctx := t.Context()
	server := newTestServer(t, ztunnelScope(), []model.Resource{
		addressResource(t, "cluster//Pod/demo/a", "a"),
		addressResource(t, "cluster//Pod/demo/b", "b"),
	}, nil)

	stream := newFakeStream(ctx, 4)
	stream.send(nodeRequest(model.AddressType, "cluster//Pod/demo/a"))
	// An on-demand subscription for "b", acknowledging a response the server has
	// no record of.
	stream.send(&discoveryv3.DeltaDiscoveryRequest{
		TypeUrl:                model.AddressType,
		ResponseNonce:          "a-nonce-from-a-previous-response",
		ResourceNamesSubscribe: []string{"cluster//Pod/demo/b"},
	})
	if err := server.run(t, stream); err != nil {
		t.Fatalf("stream: %v", err)
	}

	responses := stream.responsesFor(model.AddressType)
	if len(responses) != 2 {
		t.Fatalf("responses = %d, want 2; the on-demand subscription was dropped", len(responses))
	}
	if got := resourceNames(responses[1]); !slices.Equal(got, []string{"cluster//Pod/demo/b"}) {
		t.Fatalf("second response = %v, want the newly subscribed resource", got)
	}
}

// A nonce that changes nothing is a plain acknowledgement and must not provoke a
// response, or client and server would ping-pong forever.
func TestAcknowledgementsDoNotTriggerResend(t *testing.T) {
	for _, nack := range []bool{false, true} {
		t.Run(fmt.Sprintf("nack=%v", nack), func(t *testing.T) {
			server := newTestServer(t, ztunnelScope(), []model.Resource{
				addressResource(t, "cluster//Pod/demo/a", "a"),
			}, nil)
			stream := newFakeStream(t.Context(), 4)
			done := server.start(stream)
			stream.send(nodeRequest(model.AddressType))
			first := stream.awaitResponses(t, model.AddressType, 1)[0]
			ack := &discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.AddressType, ResponseNonce: first.GetNonce()}
			if nack {
				ack.ErrorDetail = &rpcstatus.Status{
					Code:    int32(codes.InvalidArgument),
					Message: "rejected by the proxy",
				}
			}
			stream.send(ack)
			if err := server.finish(t, stream, done); err != nil {
				t.Fatal(err)
			}
			if got := len(stream.responsesFor(model.AddressType)); got != 1 {
				t.Fatalf("responses = %d, want 1; ACK/NACK must not trigger a resend", got)
			}
		})
	}
}

// Exercise response commits and acknowledgements together, including rejection
// recovery, delayed replies, and nonce isolation between resource types.
func TestDeltaAcknowledgementsTrackLatestResponse(t *testing.T) {
	previousMetrics := metrics.Default
	registry := metrics.NewRegistry()
	metrics.Default = registry
	t.Cleanup(func() { metrics.Default = previousMetrics })
	server := newTestServer(t, gatewayScope(), []model.Resource{
		selectionWorkload(t, "uid-a", "demo", "node-a", "", ""),
	}, nil)
	stream := newFakeStream(t.Context(), 8)
	watches := map[string]*watchState{}
	subscription := server.resources.Subscribe(t.Context(), model.ClientScope{})
	handle := func(request *discoveryv3.DeltaDiscoveryRequest) {
		t.Helper()
		if err := server.server.handleRequest(stream, server.scope, log, watches, subscription, request); err != nil {
			t.Fatal(err)
		}
	}
	reply := func(typeURL, nonce string, detail *rpcstatus.Status) {
		t.Helper()
		handle(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: typeURL, ResponseNonce: nonce, ErrorDetail: detail})
	}
	handle(request(model.AddressType))
	watch := watches[model.AddressType]
	firstNonce := watch.nonceSent
	if firstNonce == "" || firstNonce != stream.responsesFor(model.AddressType)[0].GetNonce() {
		t.Fatal("successful send did not record the response nonce")
	}
	reply(model.AddressType, firstNonce, nil)
	if watch.nonceAcked != firstNonce {
		t.Fatal("ACK did not record the latest response")
	}
	// A spontaneous request is not an ACK; its response starts a new pending update.
	handle(request(model.AddressType))
	secondNonce := watch.nonceSent
	if secondNonce == firstNonce || watch.nonceAcked != firstNonce {
		t.Fatal("new send changed the last ACK or reused the nonce")
	}
	rejection := &rpcstatus.Status{Code: int32(codes.InvalidArgument), Message: "invalid policy"}
	reply(model.AddressType, secondNonce, rejection)
	if watch.nonceNacked != secondNonce || watch.nonceAcked != firstNonce || watch.lastError != rejection.Message ||
		watch.lastErrorCode != codes.InvalidArgument {
		t.Fatalf("NACK state = %+v", watch)
	}
	// An old ACK cannot clear the current rejection.
	reply(model.AddressType, firstNonce, nil)
	if watch.nonceNacked != secondNonce || watch.lastError == "" {
		t.Fatal("old ACK cleared the rejection")
	}
	handle(request(model.AddressType))
	thirdNonce := watch.nonceSent
	if thirdNonce == secondNonce || watch.nonceNacked != secondNonce || watch.lastError == "" {
		t.Fatal("new send lost the previous rejection")
	}
	reply(model.AddressType, thirdNonce, nil)
	if watch.nonceAcked != thirdNonce || watch.nonceNacked != "" || watch.lastError != "" ||
		watch.lastErrorCode != codes.OK {
		t.Fatalf("recovery ACK state = %+v", watch)
	}
	// An old NACK cannot replace the latest successful ACK.
	reply(model.AddressType, secondNonce, rejection)
	if watch.nonceAcked != thirdNonce || watch.nonceNacked != "" || watch.lastError != "" {
		t.Fatal("old NACK overwrote the latest ACK")
	}
	// Another type's nonce is not an ACK for Address, even on the same stream.
	handle(request(model.WorkloadType))
	workloadWatch := watches[model.WorkloadType]
	reply(model.AddressType, workloadWatch.nonceSent, nil)
	if watch.nonceAcked != thirdNonce || workloadWatch.nonceAcked != "" {
		t.Fatal("nonce crossed resource type boundary")
	}
	reply(model.WorkloadType, workloadWatch.nonceSent, nil)
	if workloadWatch.nonceAcked != workloadWatch.nonceSent {
		t.Fatal("Workload ACK was not recorded")
	}
	if got := len(stream.sent()); got != 4 {
		t.Fatalf("responses = %d, want 4; confirmations must not send responses", got)
	}
	response := httptest.NewRecorder()
	registry.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, want := range []string{"agentio_xds_acks_total 3\n", "agentio_xds_nacks_total 2\n", "agentio_xds_stale_nonces_total 3\n"} {
		if !strings.Contains(response.Body.String(), want) {
			t.Fatalf("missing metric %q", want)
		}
	}
}

func TestDeltaAcknowledgementsPreserveSubscriptionChanges(t *testing.T) {
	for _, stale := range []bool{false, true} {
		for _, nack := range []bool{false, true} {
			t.Run(fmt.Sprintf("stale=%v/nack=%v", stale, nack), func(t *testing.T) {
				server := newTestServer(t, gatewayScope(), []model.Resource{
					selectionWorkload(t, "uid-a", "demo", "node-a", "", ""),
					selectionWorkload(t, "uid-b", "demo", "node-a", "", ""),
				}, nil)
				stream := newFakeStream(t.Context(), 4)
				watches := map[string]*watchState{}
				subscription := server.resources.Subscribe(t.Context(), model.ClientScope{})
				handle := func(req *discoveryv3.DeltaDiscoveryRequest) {
					t.Helper()
					if err := server.server.handleRequest(
						stream,
						server.scope,
						log,
						watches,
						subscription,
						req,
					); err != nil {
						t.Fatal(err)
					}
				}
				handle(request(model.AddressType, "uid-a"))
				watch := watches[model.AddressType]
				nonce := watch.nonceSent
				if stale {
					nonce = "unknown-response"
				}
				req := &discoveryv3.DeltaDiscoveryRequest{
					TypeUrl:                  model.AddressType,
					ResponseNonce:            nonce,
					ResourceNamesSubscribe:   []string{"uid-b"},
					ResourceNamesUnsubscribe: []string{"uid-a"},
				}
				if nack {
					req.ErrorDetail = &rpcstatus.Status{Message: "invalid resource"}
				}
				handle(req)
				responses := stream.responsesFor(model.AddressType)
				if len(responses) != 2 ||
					!slices.Equal(resourceNames(responses[1]), []string{"uid-b"}) ||
					len(responses[1].GetRemovedResources()) != 0 {
					t.Fatalf("subscription delta = %v", responses)
				}
				if _, retained := watch.sent["uid-a"]; retained {
					t.Fatal("unsubscribed resource retained sent state")
				}
				if !watch.names.Contains("uid-b") || watch.names.Contains("uid-a") {
					t.Fatal("subscription changes were dropped")
				}
				if stale {
					if watch.nonceAcked != "" || watch.nonceNacked != "" || watch.lastError != "" {
						t.Fatal("unknown nonce modified acknowledgement state")
					}
				} else if nack {
					if watch.nonceNacked != nonce || watch.lastError != "invalid resource" {
						t.Fatal("NACK with subscription changes was not recorded")
					}
				} else if watch.nonceAcked != nonce {
					t.Fatal("ACK with subscription changes was not recorded")
				}
			})
		}
	}
}

// A resource whose hash has not moved is not re-sent on a later push, which is
// what keeps a snapshot change from re-delivering the whole configuration.
func TestUnchangedResourcesAreNotResent(t *testing.T) {
	ctx := t.Context()
	stable := addressResource(t, "cluster//Pod/demo/a", "a")
	server := newTestServer(t, ztunnelScope(), []model.Resource{stable}, nil)

	stream := newFakeStream(ctx, 8)
	done := server.start(stream)
	stream.send(nodeRequest(model.AddressType))
	stream.awaitResponses(t, model.AddressType, 1)

	// Only now add a second resource, leaving the first untouched.
	updated, err := model.NewResourceSet([]model.Resource{stable, addressResource(t, "cluster//Pod/demo/b", "b")})
	if err != nil {
		t.Fatal(err)
	}
	server.resources.publish(updated)
	responses := stream.awaitResponses(t, model.AddressType, 2)

	if err := server.finish(t, stream, done); err != nil {
		t.Fatalf("stream: %v", err)
	}
	if got := resourceNames(responses[1]); !slices.Equal(got, []string{"cluster//Pod/demo/b"}) {
		t.Fatalf("push response = %v, want only the added resource", got)
	}
}

// A resource that leaves the snapshot must be withdrawn explicitly, or the proxy
// keeps enforcing configuration the control plane no longer has.
func TestRemovedResourcesAreWithdrawn(t *testing.T) {
	previousMetrics := metrics.Default
	registry := metrics.NewRegistry()
	metrics.Default = registry
	t.Cleanup(func() { metrics.Default = previousMetrics })

	ctx := t.Context()
	keep := addressResource(t, "cluster//Pod/demo/a", "a")
	server := newTestServer(t, ztunnelScope(), []model.Resource{
		keep, addressResource(t, "cluster//Pod/demo/b", "b"),
	}, nil)

	stream := newFakeStream(ctx, 8)
	done := server.start(stream)
	stream.send(nodeRequest(model.AddressType))
	first := stream.awaitResponses(t, model.AddressType, 1)
	if got := len(first[0].GetResources()); got != 2 {
		t.Fatalf("initial resources = %d, want 2", got)
	}

	shrunk, err := model.NewResourceSet([]model.Resource{keep})
	if err != nil {
		t.Fatal(err)
	}
	server.resources.publish(shrunk)
	responses := stream.awaitResponses(t, model.AddressType, 2)

	if err := server.finish(t, stream, done); err != nil {
		t.Fatalf("stream: %v", err)
	}
	if got := responses[1].GetRemovedResources(); !slices.Equal(got, []string{"cluster//Pod/demo/b"}) {
		t.Fatalf("removed = %v, want the deleted resource withdrawn", got)
	}
	recorder := httptest.NewRecorder()
	registry.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := recorder.Body.String()
	if !strings.Contains(body, "agentio_xds_push_resources_sum{} 3\n") {
		t.Fatalf("push resource histogram did not count the removal:\n%s", body)
	}
}

// Envoy must garbage collect unreferenced extension configs itself
// (envoyproxy/envoy#32823); an ECDS response carrying removed_resources can
// break listeners that still reference the extension.
func TestECDSNeverSendsRemovals(t *testing.T) {
	ctx := t.Context()
	keep := gatewayResourceOfType(t, model.ExtensionConfigurationType, "demo/egress", "ext-keep", "v1")
	dropped := gatewayResourceOfType(t, model.ExtensionConfigurationType, "demo/egress", "ext-dropped", "v1")
	server := newTestServer(t, gatewayScope(), []model.Resource{keep, dropped}, nil)
	stream := newFakeStream(ctx, 4)
	done := server.start(stream)
	stream.send(nodeRequest(model.ExtensionConfigurationType, keep.XDSName, dropped.XDSName))
	first := stream.awaitResponses(t, model.ExtensionConfigurationType, 1)[0]
	if got := resourceNames(first); !slices.Equal(got, []string{"ext-dropped", "ext-keep"}) {
		t.Fatalf("initial ECDS resources = %v", got)
	}

	updated := gatewayResourceOfType(t, model.ExtensionConfigurationType, "demo/egress", "ext-keep", "v2")
	if err := server.resources.apply([]model.ResourceChange{
		{Key: dropped.Key},
		{Key: updated.Key, New: &updated},
	}); err != nil {
		t.Fatal(err)
	}
	responses := stream.awaitResponses(t, model.ExtensionConfigurationType, 2)
	if got := responses[1].GetRemovedResources(); len(got) != 0 {
		t.Fatalf("ECDS removed = %v, want none (Envoy garbage collects extensions)", got)
	}
	if got := resourceNames(responses[1]); !slices.Equal(got, []string{"ext-keep"}) {
		t.Fatalf("ECDS push resources = %v, want updated extension only", got)
	}
	if err := server.finish(t, stream, done); err != nil {
		t.Fatalf("stream: %v", err)
	}
}

// A single KRT batch may change several xDS types. Their delivery order cannot
// depend on Go map iteration: Envoy must consistently see cluster state before
// route state that can refer to it.
func TestPushUsesDeterministicTypeOrder(t *testing.T) {
	ctx := t.Context()
	cluster := gatewayResourceOfType(t, model.ClusterType, "demo/egress", "outbound", "cluster-0")
	route := gatewayResourceOfType(t, model.RouteType, "demo/egress", "outbound", "route-0")
	server := newTestServer(t, gatewayScope(), []model.Resource{cluster, route}, nil)
	stream := newFakeStream(ctx, 16)
	done := server.start(stream)
	stream.send(nodeRequest(model.ClusterType))
	stream.send(request(model.RouteType, route.XDSName))
	awaitTotalResponses(t, stream, 2)

	for i := 1; i <= 24; i++ {
		cluster = gatewayResourceOfType(t, model.ClusterType, "demo/egress", "outbound", fmt.Sprintf("cluster-%d", i))
		route = gatewayResourceOfType(t, model.RouteType, "demo/egress", "outbound", fmt.Sprintf("route-%d", i))
		if err := server.resources.apply([]model.ResourceChange{
			{Key: route.Key, New: &route},
			{Key: cluster.Key, New: &cluster},
		}); err != nil {
			t.Fatal(err)
		}
		responses := awaitTotalResponses(t, stream, 2+i*2)
		pair := responses[len(responses)-2:]
		if pair[0].GetTypeUrl() != model.ClusterType || pair[1].GetTypeUrl() != model.RouteType {
			t.Fatalf("push %d order = [%s, %s], want [cluster, route]", i, pair[0].GetTypeUrl(), pair[1].GetTypeUrl())
		}
	}

	if err := server.finish(t, stream, done); err != nil {
		t.Fatalf("stream: %v", err)
	}
}

// An incremental wildcard WDS update must use only its exact changed keys. It
// must neither withdraw unrelated resources nor retain their hashes.
func TestWildcardIncrementalPushDoesNotRetainUnrelatedSentState(t *testing.T) {
	ctx := t.Context()
	oldResource := addressResource(t, "cluster//Pod/demo/a", "old")
	newResource := addressResource(t, "cluster//Pod/demo/a", "new")
	unrelated := addressResource(t, "cluster//Pod/demo/unrelated", "unchanged")
	server := newTestServer(t, ztunnelScope(), []model.Resource{newResource, unrelated}, nil)
	stream := newFakeStream(ctx, 1)
	watch := &watchState{
		wildcard: true,
		started:  true,
		names:    sets.New[string](),
		sent: map[string]string{
			oldResource.XDSName: oldResource.Hash,
			unrelated.XDSName:   unrelated.Hash,
		},
	}
	update := updateReversedFrom(t, server.resources.Snapshot(), []model.ResourceChange{{
		Key: newResource.Key,
		Old: &oldResource,
		New: &newResource,
	}})

	if err := server.server.sendIncremental(stream, server.scope, log, model.AddressType, watch, update); err != nil {
		t.Fatal(err)
	}
	responses := stream.responsesFor(model.AddressType)
	if len(responses) != 1 || !slices.Equal(resourceNames(responses[0]), []string{newResource.XDSName}) {
		t.Fatalf("incremental response = %#v", responses)
	}
	if len(responses[0].GetRemovedResources()) != 0 {
		t.Fatalf("unrelated state was withdrawn: %v", responses[0].GetRemovedResources())
	}
	if len(watch.sent) != 0 {
		t.Fatalf("incremental push retained sent state: %v", watch.sent)
	}
}

func TestWildcardReferencedGatewayLifecycle(t *testing.T) {
	scope := model.ClientScope{
		Class:       model.ClientDedicatedZTunnel,
		WorkloadUID: "uid-a",
		Source:      model.SourceRef{Registry: "kubernetes/test", Key: "uid-a"},
		Principal:   model.MustServiceAccountPrincipal("demo", "default"),
	}
	plain := selectionWorkload(t, "uid-a", "demo", "node-a", "", "")
	withReference := func(key string) model.Resource {
		return selectionWithGatewayReference(t, plain, key)
	}
	gatewayWorkload := func(uid, key, revision string) model.Resource {
		resource := selectionOwnedByGateway(t,
			selectionWorkload(t, uid, "agentio-system", "gateway-node", "", ""), key)
		updated, err := model.NewResource(
			resource.Key,
			resource.XDSName,
			testResourceContents(testResourceValue(resource)),
			[]string{"revision/" + revision},
			resource.Facts,
		)
		if err != nil {
			t.Fatal(err)
		}
		return updated
	}
	gatewayService := func(name, key string) model.Resource {
		return selectionOwnedByGateway(t, selectionService(t, name), key)
	}
	aWorkload := gatewayWorkload("gateway-a", "agentio-system/egress-a", "one")
	aService := gatewayService("agentio-system/egress-a.agentio-system.svc.cluster.local", "agentio-system/egress-a")
	bWorkload := gatewayWorkload("gateway-b", "agentio-system/egress-b", "one")
	bService := gatewayService("agentio-system/egress-b.agentio-system.svc.cluster.local", "agentio-system/egress-b")

	state := selectionSnapshot(t, []model.Resource{plain, aWorkload, aService})
	transition := func(nextResources []model.Resource, wantResources, wantRemoved []string) {
		t.Helper()
		next := selectionSnapshot(t, nextResources)
		delta := generateWDSIncremental(GenerationRequest{
			Scope:        scope,
			TypeURL:      model.AddressType,
			Subscription: SubscriptionView{wildcard: true},
			Snapshot:     next,
			Update:       updateBetween(state, next, state.Diff(next)),
		}, false)
		gotResources := selectedNames(delta.Resources)
		gotRemoved := append([]string(nil), delta.Removed...)
		slices.Sort(gotRemoved)
		slices.Sort(wantResources)
		slices.Sort(wantRemoved)
		if !slices.Equal(gotResources, wantResources) || !slices.Equal(gotRemoved, wantRemoved) {
			t.Fatalf("delta resources=%v removed=%v, want resources=%v removed=%v",
				gotResources, gotRemoved, wantResources, wantRemoved)
		}
		state = next
	}

	transition([]model.Resource{withReference("agentio-system/egress-a"), aWorkload, aService},
		[]string{"uid-a", "gateway-a", "agentio-system/egress-a.agentio-system.svc.cluster.local"}, nil)
	aWorkloadUpdated := gatewayWorkload("gateway-a", "agentio-system/egress-a", "two")
	transition([]model.Resource{withReference("agentio-system/egress-a"), aWorkloadUpdated, aService},
		[]string{"gateway-a"}, nil)
	transition([]model.Resource{withReference("agentio-system/egress-b"), aWorkloadUpdated, aService},
		[]string{"uid-a"}, []string{"gateway-a", "agentio-system/egress-a.agentio-system.svc.cluster.local"})
	transition(
		[]model.Resource{withReference("agentio-system/egress-b"), aWorkloadUpdated, aService, bWorkload, bService},
		[]string{"gateway-b", "agentio-system/egress-b.agentio-system.svc.cluster.local"},
		nil,
	)
	transition([]model.Resource{withReference("agentio-system/egress-b"), aWorkloadUpdated, aService}, nil,
		[]string{"gateway-b", "agentio-system/egress-b.agentio-system.svc.cluster.local"})
	transition([]model.Resource{aWorkloadUpdated, aService}, nil, []string{"uid-a"})
}

// Asserts pushes are globally capacity-limited across streams.
func TestPushConcurrencyIsGloballyScheduled(t *testing.T) {
	ctx := t.Context()
	oldResource := addressResource(t, "cluster//Pod/demo/a", "old")
	newResource := addressResource(t, "cluster//Pod/demo/a", "new")
	server := newTestServerWithScheduler(t, ztunnelScope(), []model.Resource{oldResource}, nil,
		NewPushScheduler(1))

	first := newFakeStream(ctx, 4)
	second := newFakeStream(ctx, 4)
	first.send(nodeRequest(model.AddressType))
	firstDone := server.start(first)
	initial := first.awaitResponses(t, model.AddressType, 1)[0]
	first.send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.AddressType, ResponseNonce: initial.Nonce})
	second.send(nodeRequest(model.AddressType))
	secondDone := server.start(second)
	initial = second.awaitResponses(t, model.AddressType, 1)[0]
	second.send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.AddressType, ResponseNonce: initial.Nonce})

	started := make(chan int, 2)
	release := make(chan struct{})
	first.beforeSend = func() {
		started <- 1
		<-release
	}
	second.beforeSend = func() {
		started <- 2
		<-release
	}
	if err := server.resources.apply([]model.ResourceChange{{Key: newResource.Key, New: &newResource}}); err != nil {
		t.Fatal(err)
	}

	var firstPushed int
	select {
	case firstPushed = <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("no pushed connection entered Send")
	}
	select {
	case id := <-started:
		t.Fatalf("second connection %d entered Send before the first released the global push slot", id)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	consumed := first
	if firstPushed == 2 {
		consumed = second
	}
	response := consumed.awaitResponses(t, model.AddressType, 2)[1]
	consumed.send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.AddressType, ResponseNonce: response.Nonce})
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("second connection did not run after the push slot was released")
	}
	for _, stream := range []*fakeStream{first, second} {
		response := stream.awaitResponses(t, model.AddressType, 2)[1]
		stream.send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.AddressType, ResponseNonce: response.Nonce})
	}

	if err := server.finish(t, first, firstDone); err != nil {
		t.Fatalf("first stream: %v", err)
	}
	if err := server.finish(t, second, secondDone); err != nil {
		t.Fatalf("second stream: %v", err)
	}
}

// A failed spontaneous send still releases its scheduler capacity, so the next
// stream can make progress instead of being blocked forever by a dead stream.
func TestPushSendErrorReleasesSchedulerCapacity(t *testing.T) {
	firstContext, cancelFirst := context.WithCancel(context.Background())
	defer cancelFirst()
	oldResource := addressResource(t, "cluster//Pod/demo/a", "old")
	newResource := addressResource(t, "cluster//Pod/demo/a", "new")
	finalResource := addressResource(t, "cluster//Pod/demo/a", "final")
	server := newTestServerWithScheduler(t, ztunnelScope(), []model.Resource{oldResource}, nil,
		NewPushScheduler(1))

	stream := newFakeStream(firstContext, 4)
	stream.send(nodeRequest(model.AddressType))
	done := server.start(stream)
	stream.awaitResponses(t, model.AddressType, 1)
	stream.setSendErr(fmt.Errorf("send failed"))
	if err := server.resources.apply([]model.ResourceChange{{Key: newResource.Key, New: &newResource}}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil || err.Error() != "send failed" {
			t.Fatalf("stream error = %v, want send failed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stream did not return its send error")
	}
	cancelFirst()

	secondContext := t.Context()
	second := newFakeStream(secondContext, 4)
	second.send(nodeRequest(model.AddressType))
	secondDone := server.start(second)
	second.awaitResponses(t, model.AddressType, 1)
	if err := server.resources.apply(
		[]model.ResourceChange{{Key: finalResource.Key, New: &finalResource}},
	); err != nil {
		t.Fatal(err)
	}
	second.awaitResponses(t, model.AddressType, 2)
	if err := server.finish(t, second, secondDone); err != nil {
		t.Fatalf("second stream: %v", err)
	}
}

// A dedicated ztunnel has no business asking for the gateway's Envoy graph.
func TestDedicatedZTunnelCannotSubscribeToGatewayTypes(t *testing.T) {
	ctx := t.Context()
	server := newTestServer(t, ztunnelScope(), nil, nil)

	stream := newFakeStream(ctx, 4)
	stream.send(nodeRequest(model.ClusterType))
	err := server.run(t, stream)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("error = %v, want PermissionDenied", err)
	}
}

func TestServerRejectsUnboundGatewayScope(t *testing.T) {
	ctx := t.Context()
	scope := gatewayScope()
	scope.GatewayKey = "demo/other"
	scope.Source.Key = ""
	server := newTestServer(t, scope, []model.Resource{
		gatewayResource(t, "demo/other", "main_internal", "theirs"),
	}, nil)

	stream := newFakeStream(ctx, 2)
	stream.send(nodeRequest(model.ClusterType))
	if err := server.run(t, stream); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("error = %v, want PermissionDenied", err)
	}
	if responses := stream.responsesFor(model.ClusterType); len(responses) != 0 {
		t.Fatalf("unauthorized gateway received %d responses", len(responses))
	}
}

// Gateway-scoped resources share a wire name across gateways, so scoping has to
// use the owner fact rather than the name.
func TestGatewayReceivesOnlyItsOwnScopedResources(t *testing.T) {
	ctx := t.Context()
	server := newTestServer(t, gatewayScope(), []model.Resource{
		gatewayResource(t, "demo/egress", "main_internal", "mine"),
		gatewayResource(t, "other/egress", "main_internal", "theirs"),
	}, nil)

	stream := newFakeStream(ctx, 4)
	stream.send(nodeRequest(model.ClusterType))
	if err := server.run(t, stream); err != nil {
		t.Fatalf("stream: %v", err)
	}

	responses := stream.responsesFor(model.ClusterType)
	if len(responses) != 1 {
		t.Fatalf("responses = %d, want 1", len(responses))
	}
	if got := len(responses[0].GetResources()); got != 1 {
		t.Fatalf("resources = %d, want only this gateway's; got %v", got, resourceNames(responses[0]))
	}
	payload := responses[0].GetResources()[0]
	if payload.GetName() != "main_internal" {
		t.Fatalf("wire name = %q", payload.GetName())
	}
}

// One unauthorized domain is skipped; it must not terminate the stream.
func TestUnauthorizedSecretDomainDoesNotTearDownTheStream(t *testing.T) {
	ctx := t.Context()
	secrets := newFakeSecrets("allowed.example.com")
	server := newTestServer(t, gatewayScope(), []model.Resource{
		gatewayResource(t, "demo/egress", "main_internal", "mine"),
	}, secrets)

	stream := newFakeStream(ctx, 8)
	stream.send(nodeRequest(model.ClusterType))
	stream.send(request(model.SecretType, "allowed.example.com", "denied.example.com"))
	err := server.run(t, stream)
	if err != nil {
		t.Fatalf("one bad domain terminated the stream: %v", err)
	}

	// The gateway still got its clusters.
	if got := len(stream.responsesFor(model.ClusterType)); got != 1 {
		t.Fatalf("cluster responses = %d, want 1", got)
	}
	// And it got the domain it is allowed to have, without the one it is not.
	secretResponses := stream.responsesFor(model.SecretType)
	var names, removed []string
	for _, response := range secretResponses {
		names = append(names, resourceNames(response)...)
		removed = append(removed, response.RemovedResources...)
	}
	if !slices.Equal(names, []string{"allowed.example.com"}) || !slices.Equal(removed, []string{"denied.example.com"}) {
		t.Fatalf("secrets = %v removed = %v", names, removed)
	}
}

func TestExplicitSecretRequestReissuesEvictedDomain(t *testing.T) {
	ctx := t.Context()
	secrets := newFakeSecrets("old.example.com")
	secrets.evict("old.example.com")
	server := newTestServer(t, gatewayScope(), nil, secrets)
	stream := newFakeStream(ctx, 2)
	stream.send(nodeRequest(model.SecretType, "old.example.com"))

	if err := server.run(t, stream); err != nil {
		t.Fatal(err)
	}
	responses := stream.responsesFor(model.SecretType)
	if len(responses) != 1 || !slices.Equal(resourceNames(responses[0]), []string{"old.example.com"}) {
		t.Fatalf("secret responses = %#v, want one reissued old.example.com", responses)
	}
	if evicted := secrets.Evicted(); len(evicted) != 0 {
		t.Fatalf("explicit request left eviction state: %v", evicted)
	}
}

func TestRepeatedSecretSubscribeReissuesEvictedDomain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		secrets := newFakeSecrets("old.example.com")
		server := newTestServer(t, gatewayScope(), nil, secrets)
		stream := newFakeStream(t.Context(), 3)
		done := make(chan error, 1)
		go func() { done <- server.server.serveDelta(stream) }()
		stream.send(nodeRequest(model.SecretType, "old.example.com"))
		synctest.Wait()
		if len(stream.responsesFor(model.SecretType)) != 1 {
			t.Fatal("missing initial response")
		}
		secrets.evict("old.example.com")
		repeated := request(model.SecretType, "old.example.com")
		repeated.ResponseNonce = "1"
		stream.send(repeated)
		synctest.Wait()
		if len(stream.responsesFor(model.SecretType)) != 2 {
			t.Fatal("missing repeated response")
		}
		if len(secrets.Evicted()) != 0 {
			t.Fatal("explicit request did not reissue")
		}
		stream.closeRequests()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	})
}

// The first request has to identify the client, since everything else is
// authorized against it.
func TestFirstRequestMustCarryNodeMetadata(t *testing.T) {
	ctx := t.Context()
	server := newTestServer(t, ztunnelScope(), nil, nil)

	stream := newFakeStream(ctx, 4)
	stream.send(request(model.AddressType))
	err := server.run(t, stream)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("error = %v, want InvalidArgument", err)
	}
}

// Serving configuration before the snapshot is built would hand out a partial
// view, so an unready server refuses the stream outright.
func TestUnreadyServerRefusesTheStream(t *testing.T) {
	ctx := t.Context()
	server := newTestServer(t, ztunnelScope(), nil, nil)
	server.server.ready = func() bool { return false }

	stream := newFakeStream(ctx, 4)
	stream.send(nodeRequest(model.AddressType))
	if code := status.Code(server.run(t, stream)); code != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", code)
	}
}

func TestIncrementalGenerationUsesCurrentSnapshot(t *testing.T) {
	oldResource := addressResource(t, "cluster//Pod/demo/a", "old")
	middleResource := addressResource(t, "cluster//Pod/demo/a", "middle")
	newResource := addressResource(t, "cluster//Pod/demo/a", "new")
	snapshot := func(resource model.Resource) model.ResourceSet {
		result, err := model.NewResourceSet([]model.Resource{resource})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	before := snapshot(oldResource)
	after := snapshot(middleResource)
	live := snapshot(newResource)
	generator := &requestRecordingGenerator{}
	server := newTestServerWithGenerators(
		t,
		ztunnelScope(),
		[]model.Resource{newResource},
		map[string]ResourceGenerator{
			model.AddressType: generator,
		},
	)
	watch := &watchState{wildcard: true, started: true, names: sets.New[string](), sent: map[string]string{}}
	update := updateBetween(before, after, []model.ResourceChange{{
		Key: oldResource.Key,
		Old: &oldResource,
		New: &middleResource,
	}})

	if got := server.resources.Snapshot().Version(); got != live.Version() {
		t.Fatalf("live snapshot version = %q, want %q", got, live.Version())
	}
	if err := server.server.sendIncremental(newFakeStream(context.Background(), 1), server.scope, log,
		model.AddressType, watch, update); err != nil {
		t.Fatal(err)
	}

	if got := generator.request.Snapshot.Version(); got != live.Version() {
		t.Fatalf("generator snapshot = %q, want current %q", got, live.Version())
	}
	if got := generator.request.Update.Candidates(model.AddressType); len(got) != 1 || got[0].Key != oldResource.Key {
		t.Fatalf("generator lost queued candidates: %#v", got)
	}
}

func TestIncrementalGenerationCopiesOnlyRelevantSentState(t *testing.T) {
	oldResource := addressResource(t, "cluster//Pod/demo/a", "old")
	newResource := addressResource(t, "cluster//Pod/demo/a", "new")
	generator := &subscriptionRecordingGenerator{}
	server := newTestServerWithGenerators(
		t,
		ztunnelScope(),
		[]model.Resource{newResource},
		map[string]ResourceGenerator{
			model.AddressType: generator,
		},
	)
	watch := &watchState{
		wildcard: true,
		started:  true,
		names:    sets.New[string](),
		sent: map[string]string{
			oldResource.XDSName:           oldResource.Hash,
			"cluster//Pod/demo/unrelated": "unchanged-hash",
		},
	}
	update := updateReversedFrom(t, server.resources.Snapshot(), []model.ResourceChange{{
		Key: newResource.Key,
		Old: &oldResource,
		New: &newResource,
	}})
	if err := server.server.sendIncremental(
		newFakeStream(context.Background(), 1),
		server.scope,
		log,
		model.AddressType,
		watch,
		update,
	); err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(generator.sentNames, []string{oldResource.XDSName}) {
		t.Fatalf("incremental sent-state copy = %v, want only %q", generator.sentNames, oldResource.XDSName)
	}
	if got := watch.sent["cluster//Pod/demo/unrelated"]; got != "unchanged-hash" {
		t.Fatalf("generator mutated live sent state to %q", got)
	}
}

func TestFailedSendDoesNotCommitGeneratedDelta(t *testing.T) {
	oldResource := addressResource(t, "cluster//Pod/demo/old", "old")
	newResource := addressResource(t, "cluster//Pod/demo/new", "new")
	newResource, encodeErr := newResource.Encode(ztunnelScope(), model.AddressType)
	if encodeErr != nil {
		t.Fatal(encodeErr)
	}
	generator := &recordingGenerator{delta: GeneratedDelta{
		Resources: []model.Resource{newResource},
		Removed:   []string{oldResource.XDSName},
	}}
	server := newTestServerWithGenerators(t, ztunnelScope(), nil, map[string]ResourceGenerator{
		model.AddressType: generator,
	})
	watch := &watchState{
		wildcard:  true,
		started:   true,
		names:     sets.New[string](),
		sent:      map[string]string{oldResource.XDSName: oldResource.Hash},
		nonceSent: "previous",
	}
	stream := newFakeStream(context.Background(), 1)
	stream.setSendErr(errors.New("send failed"))
	err := server.server.generateAndSend(stream, log, watch, GenerationRequest{
		Scope:        server.scope,
		TypeURL:      model.AddressType,
		Subscription: newSubscriptionView(watch),
		Full:         true,
	}, false, nil)
	if err == nil || err.Error() != "send failed" {
		t.Fatalf("send error = %v, want send failed", err)
	}
	if !slices.Equal(watchSentNames(watch), []string{oldResource.XDSName}) ||
		watch.sent[oldResource.XDSName] != oldResource.Hash {
		t.Fatalf("failed send committed sent state: %v", watch.sent)
	}
	if watch.nonceSent != "previous" {
		t.Fatalf("failed send committed nonce %q", watch.nonceSent)
	}
}

func TestServerRejectsMismatchedGeneratorResource(t *testing.T) {
	resource := addressResource(t, "cluster//Pod/demo/a", "a")
	generator := &recordingGenerator{delta: GeneratedDelta{Resources: []model.Resource{resource}}}
	server := newTestServerWithGenerators(t, gatewayScope(), nil, map[string]ResourceGenerator{
		model.SecretType: generator,
	})
	stream := newFakeStream(context.Background(), 1)
	stream.send(nodeRequest(model.SecretType, "api.example.com"))
	err := server.run(t, stream)
	if err == nil || !strings.Contains(err.Error(), "mismatched type URL") {
		t.Fatalf("stream error = %v, want mismatched type URL", err)
	}
	if responses := stream.sent(); len(responses) != 0 {
		t.Fatalf("invalid generator result was sent: %#v", responses)
	}
}

func TestUnsupportedTypeSubscriptionReturnsEmptyResponseWithoutClosingStream(t *testing.T) {
	for _, tc := range []struct{ name, typeURL string }{
		{name: "unknown type", typeURL: "type.googleapis.com/example.OptionalResource"},
		{name: "legacy WorkloadConfig", typeURL: "type.googleapis.com/kruise.extensions.WorkloadConfig"},
		{name: "versioned legacy WorkloadConfig", typeURL: "type.googleapis.com/kruise.networking.extensions.v1.WorkloadConfig"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := newTestServer(t, ztunnelScope(), nil, nil)
			stream := newFakeStream(t.Context(), 2)
			stream.send(nodeRequest(model.AddressType))
			stream.send(request(tc.typeURL))
			if err := server.run(t, stream); err != nil {
				t.Fatalf("unsupported type subscription closed the stream: %v", err)
			}
			responses := stream.responsesFor(tc.typeURL)
			if len(responses) != 1 || len(responses[0].GetResources()) != 0 {
				t.Fatalf("unsupported type responses = %#v, want one empty response", responses)
			}
		})
	}
}

func TestRepeatedSecretSubscribeRestoresCachedVersion(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const name = "api.example.com"
		server := newTestServer(t, gatewayScope(), nil, newFakeSecrets(name))
		stream := newFakeStream(t.Context(), 3)
		done := make(chan error, 1)
		go func() { done <- server.server.serveDelta(stream) }()
		stream.send(nodeRequest(model.SecretType, name))
		synctest.Wait()
		repeated := request(model.SecretType, name)
		repeated.ResponseNonce = "1"
		stream.send(repeated)
		synctest.Wait()
		ack := request(model.SecretType)
		ack.ResponseNonce = "2"
		stream.send(ack)
		stream.closeRequests()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		responses := stream.responsesFor(model.SecretType)
		if len(responses) != 2 {
			t.Fatalf("responses = %d, want 2 (ACK must not trigger a push)", len(responses))
		}
		for _, response := range responses {
			if !slices.Equal(resourceNames(response), []string{name}) {
				t.Fatalf("explicit subscription did not restore secret: %v", response)
			}
		}
		if responses[0].Resources[0].Version != responses[1].Resources[0].Version {
			t.Fatal("cached certificate version changed")
		}

	})
}

func TestExpiredSecretSendCommitsOnlyWireResources(t *testing.T) {
	for _, deadline := range []time.Time{{}, time.Now().Add(-time.Second)} {
		for _, failSend := range []bool{false, true} {
			t.Run(fmt.Sprintf("deadline=%v/fail=%t", deadline, failSend), func(t *testing.T) {
				expired := gatewayResourceOfType(t, model.SecretType, "demo/gateway", "expired.example.com", "expired")
				static := gatewayResourceOfType(t, model.SecretType, "demo/gateway", "static", "static")
				generator := &recordingGenerator{delta: GeneratedDelta{
					Resources: []model.Resource{expired, static},
					expiresAt: map[string]time.Time{expired.XDSName: deadline},
				}}
				server := newTestServerWithGenerators(t, gatewayScope(), nil, map[string]ResourceGenerator{
					model.SecretType: generator,
				})
				watch := &watchState{
					started:   true,
					names:     sets.New(expired.XDSName, static.XDSName),
					sent:      map[string]string{expired.XDSName: expired.Hash},
					nonceSent: "previous",
				}
				stream := newFakeStream(t.Context(), 1)
				if failSend {
					stream.setSendErr(errors.New("send failed"))
				}
				err := server.server.generateAndSend(stream, log, watch, GenerationRequest{
					Scope:        server.scope,
					TypeURL:      model.SecretType,
					Full:         true,
					Subscription: newSubscriptionView(watch),
				}, false, nil)
				if failSend {
					if err == nil || len(watch.sent) != 1 ||
						watch.sent[expired.XDSName] != expired.Hash || watch.nonceSent != "previous" {
						t.Fatalf(
							"failed send changed state: sent=%v nonce=%s error=%v",
							watch.sent,
							watch.nonceSent,
							err,
						)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if len(watch.sent) != 1 || watch.sent[static.XDSName] != static.Hash {
					t.Fatalf("sent state retained an expired resource: %v", watch.sent)
				}
				responses := stream.responsesFor(model.SecretType)
				if len(responses) != 1 || !slices.Equal(resourceNames(responses[0]), []string{static.XDSName}) ||
					!slices.Equal(responses[0].RemovedResources, []string{expired.XDSName}) {
					t.Fatalf("expired response = %v", responses)
				}
				if responses[0].Resources[0].Ttl != nil {
					t.Fatal("static secret acquired a TTL")
				}
			})
		}
	}
}
