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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/anypb"

	workloadv1 "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/internal/testutil"
	"github.com/openkruise/agentio/pkg/krt"
	agentlog "github.com/openkruise/agentio/pkg/log"
	"github.com/openkruise/agentio/pkg/metrics"
	"github.com/openkruise/agentio/pkg/model"
	xdsstore "github.com/openkruise/agentio/pkg/xds/store"
)

func newSnapshot(t testing.TB, names ...string) model.ResourceSet {
	t.Helper()
	resources := make([]model.Resource, 0, len(names))
	for _, name := range names {
		value, err := anypb.New(&workloadv1.Address{Type: &workloadv1.Address_Workload{
			Workload: &workloadv1.Workload{Uid: name, Name: name},
		}})
		if err != nil {
			t.Fatal(err)
		}
		resource, err := model.NewResource(
			model.ResourceKey{TypeURL: model.AddressType, Name: name}, "", testResourceContents(value), nil,
			model.ResourceFacts{Workload: &model.WorkloadResourceFacts{
				WorkloadUID: name,
				Principal:   model.MustServiceAccountPrincipal("default", "default"),
			}})
		if err != nil {
			t.Fatal(err)
		}
		resources = append(resources, resource)
	}
	set, err := model.NewResourceSet(resources)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

// stubSource returns whatever snapshot it is currently holding and counts calls,
// so a test can tell how many times the debouncer decided to compile.
type stubSource struct {
	mu       sync.Mutex
	current  model.ResourceSet
	err      error
	compiles int
	events   krt.EventStream[model.Resource]
}

func (c *stubSource) Snapshot() (model.ResourceSet, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.compiles++
	if c.err != nil {
		return model.ResourceSet{}, c.err
	}
	return c.current, nil
}

func (c *stubSource) set(set model.ResourceSet, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.current, c.err = set, err
}

func (c *stubSource) calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.compiles
}

func (c *stubSource) Resources() krt.EventStream[model.Resource] {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.events == nil {
		c.events = newFakeResourceEvents()
	}
	return c.events
}

func (c *stubSource) HasSynced() bool {
	return true
}

// fakeResourceEvents is a small EventStream implementation for exercising the
// Controller boundary without depending on KRT's handler internals.
type fakeResourceEvents struct {
	mu       sync.Mutex
	nextID   int
	handlers map[int]func([]krt.Event[model.Resource])
}

func newFakeResourceEvents() *fakeResourceEvents {
	return &fakeResourceEvents{handlers: make(map[int]func([]krt.Event[model.Resource]))}
}

func (f *fakeResourceEvents) HasSynced() bool {
	return true
}

func (f *fakeResourceEvents) WaitUntilSynced(<-chan struct{}) bool {
	return true
}

func (f *fakeResourceEvents) Register(handler func(krt.Event[model.Resource])) krt.HandlerRegistration {
	return f.RegisterBatch(func(events []krt.Event[model.Resource]) {
		for _, event := range events {
			handler(event)
		}
	}, false)
}

func (f *fakeResourceEvents) RegisterBatch(handler func([]krt.Event[model.Resource]), _ bool) krt.HandlerRegistration {
	f.mu.Lock()
	id := f.nextID
	f.nextID++
	f.handlers[id] = handler
	f.mu.Unlock()
	return &fakeResourceRegistration{events: f, id: id}
}

func (f *fakeResourceEvents) Emit(resource model.Resource) {
	f.mu.Lock()
	handlers := make([]func([]krt.Event[model.Resource]), 0, len(f.handlers))
	for _, handler := range f.handlers {
		handlers = append(handlers, handler)
	}
	f.mu.Unlock()
	for _, handler := range handlers {
		handler([]krt.Event[model.Resource]{{New: &resource}})
	}
}

func (f *fakeResourceEvents) HandlerCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.handlers)
}

type fakeResourceRegistration struct {
	events *fakeResourceEvents
	id     int
	once   sync.Once
}

func (f *fakeResourceRegistration) HasSynced() bool {
	return true
}

func (f *fakeResourceRegistration) WaitUntilSynced(<-chan struct{}) bool {
	return true
}

func (f *fakeResourceRegistration) UnregisterHandler() {
	f.once.Do(func() {
		f.events.mu.Lock()
		defer f.events.mu.Unlock()
		delete(f.events.handlers, f.id)
	})
}

// fakeResourcePublisher records whether Controller published via Replace or Apply.
type fakeResourcePublisher struct {
	mu       sync.Mutex
	snapshot model.ResourceSet
	full     int
	delta    int
}

type synchronizedBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

func (b *synchronizedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.Write(data)
}

func (b *synchronizedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.String()
}

func (f *fakeResourcePublisher) Replace(snapshot model.ResourceSet) xdsstore.Publication {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.full++
	f.snapshot = snapshot
	return xdsstore.Publication{Changed: true, Snapshot: snapshot}
}

func (f *fakeResourcePublisher) Apply([]model.ResourceChange) (xdsstore.Publication, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delta++
	return xdsstore.Publication{Changed: true, Snapshot: f.snapshot}, nil
}

func (f *fakeResourcePublisher) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.full, f.delta = 0, 0
}

func TestControllerLogsPublishedSnapshotAtInfo(t *testing.T) {
	var output synchronizedBuffer
	previousLogger := slog.Default()
	previousLevel := agentlog.OutputLevel()
	slog.SetDefault(slog.New(slog.NewTextHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug})))
	agentlog.ConfigureOutputLevel(slog.LevelDebug)
	t.Cleanup(func() {
		slog.SetDefault(previousLogger)
		agentlog.ConfigureOutputLevel(previousLevel)
	})

	ctx, cancel := context.WithCancel(context.Background())
	source := &stubSource{}
	source.set(newSnapshot(t, "one"), nil)
	sink := &fakeResourcePublisher{}
	controller, err := NewController(source, sink, time.Millisecond, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- controller.Run(ctx) }()
	testutil.Eventually(t, func() bool {
		return strings.Contains(output.String(), `msg="xDS snapshot published"`)
	}, "snapshot publication logged")
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	for _, line := range strings.Split(output.String(), "\n") {
		if !strings.Contains(line, `msg="xDS snapshot published"`) {
			continue
		}
		for _, field := range []string{"level=INFO", "full=true", "changes=0", "resources=1", "version=", "debounce_duration=", "publication_duration="} {
			if !strings.Contains(line, field) {
				t.Fatalf("configuration calculation log missing %q: %s", field, line)
			}
		}
		return
	}
	t.Fatalf("missing configuration calculation log:\n%s", output.String())
}

func TestPublicationSummaryIsBoundedAndExcludesResourceContents(t *testing.T) {
	var output bytes.Buffer
	previousLogger := slog.Default()
	previousLevel := agentlog.OutputLevel()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	agentlog.ConfigureOutputLevel(slog.LevelInfo)
	t.Cleanup(func() {
		slog.SetDefault(previousLogger)
		agentlog.ConfigureOutputLevel(previousLevel)
	})

	changes := make([]model.ResourceChange, 100)
	for i := range changes {
		resource := addressResource(t, fmt.Sprintf("workload-%03d", i), "payload-must-not-appear-in-logs")
		changes[i] = model.ResourceChange{Key: resource.Key, New: &resource}
	}
	store := xdsstore.New(newSnapshot(t))
	store.Subscribe(t.Context(), model.ClientScope{}).Watch(model.AddressType)
	store.Subscribe(t.Context(), model.ClientScope{}).Watch(model.ClusterType)
	publication, err := store.Apply(changes)
	if err != nil {
		t.Fatal(err)
	}
	// Logging must retain the publication-time total, including the unaffected
	// Cluster subscriber, even if another client connects before the log write.
	store.Subscribe(t.Context(), model.ClientScope{}).Watch(model.AddressType)
	logPublication(t.Context(), false, changes, publication, time.Second, time.Millisecond)
	// Replaying the same changes must not emit a second INFO summary.
	unchanged, err := store.Apply(changes)
	if err != nil {
		t.Fatal(err)
	}
	logPublication(t.Context(), false, changes, unchanged, time.Second, time.Millisecond)
	lines := bytes.Split(bytes.TrimSpace(output.Bytes()), []byte{'\n'})
	if len(lines) != 1 {
		t.Fatalf("want one summary for the actual publication, got %d:\n%s", len(lines), output.String())
	}
	var entry struct {
		Message            string              `json:"msg"`
		Version            string              `json:"version"`
		Changes            int                 `json:"changes"`
		ConnectedEndpoints int                 `json:"connected_endpoints"`
		ByType             map[string]int      `json:"changes_by_type"`
		Sample             []model.ResourceKey `json:"resource_sample"`
	}
	if err := json.Unmarshal(lines[0], &entry); err != nil {
		t.Fatal(err)
	}
	if entry.Message != "xDS snapshot published" || entry.Version != publication.Snapshot.Version() ||
		entry.Changes != 100 || entry.ByType[model.AddressType] != 100 || len(entry.Sample) != 3 || entry.ConnectedEndpoints != 2 {
		t.Fatalf("unexpected batch summary: %+v", entry)
	}
	for _, key := range entry.Sample {
		if _, found := publication.Snapshot.Get(key); !found {
			t.Fatalf("sample key does not belong to this snapshot: %+v", key)
		}
	}
	if strings.Contains(output.String(), "payload-must-not-appear-in-logs") {
		t.Fatalf("resource contents leaked into logs: %s", output.String())
	}
}

func (f *fakeResourcePublisher) calls() (full, delta int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.full, f.delta
}

// Asserts Controller registers the resource handler in Run and unregisters it on return.
func TestControllerOwnsCompiledResourceRegistration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	source := &stubSource{}
	source.set(newSnapshot(t), nil)
	sink := &fakeResourcePublisher{}
	controller, err := NewController(source, sink, time.Millisecond, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- controller.Run(ctx) }()
	testutil.Eventually(t, func() bool {
		return source.Resources().(*fakeResourceEvents).HandlerCount() == 1
	}, "compiled resource handler registered")
	testutil.Eventually(t, func() bool {
		full, _ := sink.calls()
		return full == 1
	}, "initial snapshot published")
	sink.reset()

	resource := newSnapshot(t, "one").List(model.AddressType)[0]
	source.Resources().(*fakeResourceEvents).Emit(resource)
	testutil.Eventually(t, func() bool {
		_, delta := sink.calls()
		return delta == 1
	}, "compiled resource event applied")

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("controller did not stop")
	}
	if got := source.Resources().(*fakeResourceEvents).HandlerCount(); got != 0 {
		t.Fatalf("resource handlers after run = %d, want 0", got)
	}
}

// Controller sends steady-state KRT changes through Apply, while an explicit
// trigger recompiles and replaces the complete snapshot.
func TestControllerUsesResourcePublisherForDeltaAndFullPushes(t *testing.T) {
	ctx := t.Context()
	source := &stubSource{}
	source.set(newSnapshot(t, "a"), nil)
	sink := &fakeResourcePublisher{}
	controller, err := NewController(source, sink, 20*time.Millisecond, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = controller.Run(ctx) }()

	testutil.Eventually(t, func() bool {
		full, _ := sink.calls()
		return full == 1
	}, "initial snapshot published")
	sink.reset()

	resource := newSnapshot(t, "b").List(model.AddressType)[0]
	controller.Enqueue([]model.ResourceChange{{Key: resource.Key, New: &resource}})
	testutil.Eventually(t, func() bool {
		_, delta := sink.calls()
		return delta == 1
	}, "changed resource applied")
	if full, delta := sink.calls(); full != 0 || delta != 1 {
		t.Fatalf("steady-state calls = full:%d delta:%d, want full:0 delta:1", full, delta)
	}

	sink.reset()
	controller.Trigger()
	testutil.Eventually(t, func() bool {
		full, _ := sink.calls()
		return full == 1
	}, "explicit trigger published full snapshot")
	if full, delta := sink.calls(); full != 1 || delta != 0 {
		t.Fatalf("explicit-trigger calls = full:%d delta:%d, want full:1 delta:0", full, delta)
	}
}

// The controller coalesces a burst of triggers into a single compile. Without
// that, every Pod event in a rollout would rebuild and republish the snapshot.
func TestControllerCoalescesTriggersIntoOneCompile(t *testing.T) {
	ctx := t.Context()
	source := &stubSource{}
	source.set(newSnapshot(t, "a"), nil)
	store := xdsstore.New(newSnapshot(t))
	controller, err := NewController(source, store, 50*time.Millisecond, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = controller.Run(ctx) }()

	for range 20 {
		controller.Trigger()
	}
	testutil.Eventually(t, func() bool { return store.Snapshot().Len() == 1 }, "snapshot published")

	// Run issues one trigger of its own at startup, so at most two compiles should
	// have happened: the startup one and the burst.
	if got := source.calls(); got > 2 {
		t.Fatalf("compiles = %d, want the burst coalesced into at most 2", got)
	}
}

// Steady-state KRT events are applied directly without a full recompile.
func TestControllerAppliesKRTIncrementalBatchWithoutFullCompile(t *testing.T) {
	ctx := t.Context()
	source := &stubSource{}
	source.set(newSnapshot(t), nil)
	store := xdsstore.New(newSnapshot(t))
	controller, err := NewController(source, store, 20*time.Millisecond, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	resources := krt.NewMutableCollection[model.Resource](nil, nil, krt.WithStop(ctx.Done()))
	source.events = resources.AsCollection()
	go func() { _ = controller.Run(ctx) }()
	testutil.Eventually(t, func() bool { return source.calls() > 0 }, "initial full compile")
	before := source.calls()

	resource := newSnapshot(t, "a").List(model.AddressType)[0]
	resources.UpdateObject(resource)
	testutil.Eventually(t, func() bool { return store.Snapshot().Len() == 1 }, "changed resource applied")
	if got := source.calls(); got != before {
		t.Fatalf("steady-state change event caused full compile: calls=%d, want %d", got, before)
	}
}

func TestControllerRunUnregistersResourceEvents(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	source := &stubSource{}
	store := xdsstore.New(newSnapshot(t))
	controller, err := NewController(source, store, time.Second, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	resources := krt.NewMutableCollection[model.Resource](nil, nil, krt.WithStop(ctx.Done()))
	source.events = resources.AsCollection()
	done := make(chan error, 1)
	go func() { done <- controller.Run(ctx) }()
	firstSnapshot := newSnapshot(t, "first")
	first := firstSnapshot.List(model.AddressType)[0]
	source.set(firstSnapshot, nil)
	resources.UpdateObject(first)
	testutil.Eventually(t, func() bool {
		controller.mu.Lock()
		defer controller.mu.Unlock()
		return len(controller.changes) == 1
	}, "watch forwarded the first event")

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("controller did not stop")
	}
	second := newSnapshot(t, "second").List(model.AddressType)[0]
	resources.UpdateObject(second)
	time.Sleep(50 * time.Millisecond)
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if len(controller.changes) != 0 {
		t.Fatalf("unregistered watch forwarded an event: %#v", controller.changes)
	}
	if _, found := store.Snapshot().Get(first.Key); !found {
		t.Fatal("first event was lost during shutdown flush")
	}
	if _, found := store.Snapshot().Get(second.Key); found {
		t.Fatal("unregistered watch forwarded the second event")
	}
}

// The quiet period has an upper bound: a stream of changes that never goes quiet
// still has to be published, or a busy cluster would never see an update.
func TestControllerFlushesAtMaximumDelay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	source := &stubSource{}
	source.set(newSnapshot(t, "a"), nil)
	store := xdsstore.New(newSnapshot(t))
	// A quiet period that keeps being reset, and a maximum that forces the flush.
	controller, err := NewController(source, store, 200*time.Millisecond, 300*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	controllerDone := make(chan error, 1)
	go func() { controllerDone <- controller.Run(ctx) }()

	stop := make(chan struct{})
	triggerDone := make(chan struct{})
	go func() {
		defer close(triggerDone)
		for {
			select {
			case <-stop:
				return
			default:
				controller.Trigger()
				time.Sleep(20 * time.Millisecond)
			}
		}
	}()

	testutil.Eventually(t, func() bool { return store.Snapshot().Len() == 1 },
		"snapshot published despite continuous triggers")
	close(stop)
	select {
	case <-triggerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("continuous trigger goroutine did not stop")
	}
	cancel()
	select {
	case err := <-controllerDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("controller did not stop")
	}
}

// A failed compile must leave the previous snapshot in place. This is the
// property that keeps a malformed update from erasing working configuration.
func TestFailedCompilePreservesLastKnownGood(t *testing.T) {
	previousMetrics := metrics.Default
	registry := metrics.NewRegistry()
	metrics.Default = registry
	t.Cleanup(func() { metrics.Default = previousMetrics })

	ctx, cancel := context.WithCancel(context.Background())
	good := newSnapshot(t, "a", "b")
	source := &stubSource{}
	source.set(good, nil)
	store := xdsstore.New(newSnapshot(t))
	controller, err := NewController(source, store, 20*time.Millisecond, 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- controller.Run(ctx) }()

	testutil.Eventually(t, func() bool { return store.Snapshot().Version() == good.Version() },
		"good snapshot published")
	subscriptionCtx, cancelSubscription := context.WithCancel(context.Background())
	t.Cleanup(cancelSubscription)
	subscription := store.Subscribe(subscriptionCtx, model.ClientScope{})
	subscription.Watch(model.AddressType)

	source.set(model.ResourceSet{}, fmt.Errorf("compilation exploded"))
	before := source.calls()
	controller.Trigger()
	testutil.Eventually(t, func() bool { return source.calls() > before }, "failing compile attempted")
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	if got := store.Snapshot().Version(); got != good.Version() {
		t.Fatalf("failed compile replaced the snapshot: %s != %s", got, good.Version())
	}
	if got := store.Snapshot().Len(); got != 2 {
		t.Fatalf("snapshot length = %d, want the previous 2", got)
	}
	select {
	case update := <-subscription.Updates():
		t.Fatalf("failed compile notified a typed subscriber: %#v", update)
	default:
	}

	recorder := httptest.NewRecorder()
	registry.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := recorder.Body.String()
	for _, line := range []string{
		"agentio_compile_total 2",
		"agentio_compile_failures_total 1",
		"agentio_snapshot_resources 2",
	} {
		if !strings.Contains(body, line+"\n") {
			t.Fatalf("metrics do not contain %q:\n%s", line, body)
		}
	}
}

// Shutting down flushes whatever is pending, so a change that arrived just before
// SIGTERM is not silently lost.
func TestControllerFlushesPendingWorkOnShutdown(t *testing.T) {
	source := &stubSource{}
	source.set(newSnapshot(t, "a"), nil)
	store := xdsstore.New(newSnapshot(t))
	// A quiet period long enough that only the shutdown path can flush it.
	controller, err := NewController(source, store, 30*time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- controller.Run(ctx) }()

	controller.Trigger()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("controller did not stop")
	}
	if got := store.Snapshot().Len(); got != 1 {
		t.Fatalf("pending work was dropped on shutdown: snapshot length = %d", got)
	}
}

func TestNewControllerRejectsInvalidDebounce(t *testing.T) {
	source := &stubSource{}
	store := xdsstore.New(newSnapshot(t))
	for _, testCase := range []struct {
		name           string
		quiet, maximum time.Duration
	}{
		{"negative maximum", 0, -time.Second},
		{"negative quiet period", -time.Second, time.Second},
		{"maximum below quiet period", time.Second, time.Millisecond},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := NewController(source, store, testCase.quiet, testCase.maximum); err == nil {
				t.Fatal("invalid debounce periods accepted")
			}
		})
	}
}

// A typed-nil Store satisfies ResourcePublisher at compile time, but cannot
// safely replace when Controller flushes its first snapshot.
func TestNewControllerRejectsTypedNilResourcePublisher(t *testing.T) {
	var store *xdsstore.Store
	if _, err := NewController(&stubSource{}, store, time.Millisecond, time.Second); err == nil {
		t.Fatal("typed-nil resource publisher accepted")
	}
}

func TestControllerPublishesWithoutDebounce(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	source := &stubSource{current: newSnapshot(t, "initial")}
	store := xdsstore.New(newSnapshot(t))
	controller, err := NewController(source, store, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	events := newFakeResourceEvents()
	source.events = events
	done := make(chan error, 1)
	go func() { done <- controller.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	testutil.Eventually(t, func() bool { return store.Snapshot().Len() == 1 }, "initial snapshot without timers")
	resource := newSnapshot(t, "added").List(model.AddressType)[0]
	controller.Enqueue([]model.ResourceChange{{Key: resource.Key, New: &resource}})
	testutil.Eventually(t, func() bool { return store.Snapshot().Len() == 2 }, "incremental publication without timers")
	controller.Enqueue([]model.ResourceChange{{Key: resource.Key, Old: &resource}})
	testutil.Eventually(t, func() bool { return store.Snapshot().Len() == 1 }, "resource removal without timers")
	if source.calls() != 1 {
		t.Fatal("incremental updates triggered a full snapshot")
	}
}
