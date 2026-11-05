// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package audit

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"
)

// collector accumulates handled values so tests can assert on delivery
// without sleeping: done is signalled once want values have arrived.
type collector struct {
	mu   sync.Mutex
	got  []int
	want int
	done chan struct{}
	once sync.Once
}

func newCollector(want int) *collector {
	return &collector{want: want, done: make(chan struct{})}
}

func (c *collector) handle(_ context.Context, v int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.got = append(c.got, v)
	if len(c.got) >= c.want {
		c.once.Do(func() { close(c.done) })
	}
}

func (c *collector) snapshot() []int {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]int, len(c.got))
	copy(out, c.got)
	return out
}

type dropRecorder struct {
	mu      sync.Mutex
	reasons []DropReason
}

func (r *dropRecorder) observe(reason DropReason) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reasons = append(r.reasons, reason)
}

func (r *dropRecorder) snapshot() []DropReason {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]DropReason(nil), r.reasons...)
}

func waitForDispatcherState[T any](t *testing.T, d *Dispatcher[T], want dispatcherState) {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for {
		d.mu.Lock()
		got := d.state
		d.mu.Unlock()
		if got == want {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("dispatcher state = %d, want %d", got, want)
		default:
			runtime.Gosched()
		}
	}
}

// TestDispatcher_DeliversAll verifies that every enqueued item is handled
// exactly once.
func TestDispatcher_DeliversAll(t *testing.T) {
	tests := []struct {
		name    string
		workers int
		items   int
	}{
		{name: "single worker", workers: 1, items: 10},
		{name: "multi worker", workers: 4, items: 32},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := newCollector(tc.items)
			d := NewDispatcher("test", tc.items, tc.workers, c.handle, nil)

			ctx, cancel := context.WithCancel(context.Background())
			started := make(chan error, 1)
			go func() { started <- d.Start(ctx) }()

			for i := 0; i < tc.items; i++ {
				d.Enqueue(i)
			}

			select {
			case <-c.done:
			case <-time.After(2 * time.Second):
				t.Fatalf("timed out: handled %d of %d items", len(c.snapshot()), tc.items)
			}
			cancel()
			select {
			case err := <-started:
				if err != nil {
					t.Fatalf("Start returned error: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("Start did not return after ctx cancel")
			}
			if got := len(c.snapshot()); got != tc.items {
				t.Errorf("handled %d items, want %d", got, tc.items)
			}
		})
	}
}

// TestDispatcher_OverflowDrops fills the buffer with no worker running and
// asserts every overflow enqueue reports a buffer-full drop (when observed).
func TestDispatcher_OverflowDrops(t *testing.T) {
	tests := []struct {
		name        string
		buffer      int
		accepted    int
		overflow    int
		nilObserver bool
	}{
		{name: "observer reports every overflow", buffer: 4, accepted: 4, overflow: 3},
		{name: "nil observer tolerated", buffer: 2, accepted: 2, overflow: 5, nilObserver: true},
		{name: "zero capacity rolls pending back to idle", buffer: 0, accepted: 0, overflow: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var reasons []DropReason
			var observe DropObserver
			if !tc.nilObserver {
				observe = func(reason DropReason) {
					mu.Lock()
					defer mu.Unlock()
					reasons = append(reasons, reason)
				}
			}
			d := NewDispatcher("test", tc.buffer, 1, func(context.Context, int) {}, observe)

			// Workers are intentionally not started: exactly buffer sends
			// succeed, the rest must drop without blocking.
			for i := 0; i < tc.accepted+tc.overflow; i++ {
				d.Enqueue(i)
			}
			if got := d.Len(); got != tc.accepted {
				t.Errorf("queue length = %d, want %d", got, tc.accepted)
			}
			d.mu.Lock()
			pending := d.pending
			idle := d.idle
			d.mu.Unlock()
			if pending != int64(tc.accepted) {
				t.Errorf("pending = %d, want %d", pending, tc.accepted)
			}
			if tc.accepted == 0 {
				select {
				case <-idle:
				default:
					t.Error("dispatcher did not return to idle after buffer-full rollback")
				}
			}
			if !tc.nilObserver {
				mu.Lock()
				got := append([]DropReason(nil), reasons...)
				mu.Unlock()
				if len(got) != tc.overflow {
					t.Fatalf("observed %d drop reasons, want %d", len(got), tc.overflow)
				}
				for i, reason := range got {
					if reason != DropBufferFull {
						t.Errorf("drop reason %d = %q, want %q", i, reason, DropBufferFull)
					}
				}
			}
		})
	}
}

// TestDispatcher_DrainTracksAcceptedBeforeReceive verifies that an item is
// visible to the drain barrier from admission until its handler returns,
// including while it is still queued with no worker available to receive it.
func TestDispatcher_DrainTracksAcceptedBeforeReceive(t *testing.T) {
	handlerEntered := make(chan struct{})
	releaseHandler := make(chan struct{})
	d := NewDispatcher("test", 1, 1, func(context.Context, int) {
		close(handlerEntered)
		<-releaseHandler
	}, nil)

	d.Enqueue(1)
	d.mu.Lock()
	pending := d.pending
	idle := d.idle
	d.mu.Unlock()
	if pending != 1 {
		t.Fatalf("pending before receive = %d, want 1", pending)
	}
	select {
	case <-idle:
		t.Fatal("idle barrier closed while an accepted item was queued")
	default:
	}

	drainCtx, cancelDrain := context.WithCancel(context.Background())
	cancelDrain()
	if err := d.Drain(drainCtx); err != context.Canceled {
		t.Fatalf("Drain() before receive = %v, want %v", err, context.Canceled)
	}

	startCtx, cancelStart := context.WithCancel(context.Background())
	startDone := make(chan error, 1)
	go func() { startDone <- d.Start(startCtx) }()
	select {
	case <-handlerEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not receive the accepted item")
	}
	close(releaseHandler)

	settleCtx, cancelSettle := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelSettle()
	if err := d.Drain(settleCtx); err != nil {
		t.Fatalf("Drain() after handler return: %v", err)
	}
	cancelStart()
	select {
	case err := <-startDone:
		if err != nil {
			t.Fatalf("Start returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after ctx cancel")
	}
}

// TestDispatcher_DrainTracksImmediateReceive verifies that a worker receiving
// immediately cannot settle an item outside the same pending/idle invariant.
func TestDispatcher_DrainTracksImmediateReceive(t *testing.T) {
	handlerEntered := make(chan struct{})
	releaseHandler := make(chan struct{})
	d := NewDispatcher("test", 1, 1, func(context.Context, int) {
		close(handlerEntered)
		<-releaseHandler
	}, nil)

	startCtx, cancelStart := context.WithCancel(context.Background())
	startDone := make(chan error, 1)
	go func() { startDone <- d.Start(startCtx) }()
	d.Enqueue(1)
	select {
	case <-handlerEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not receive the accepted item")
	}

	d.mu.Lock()
	pending := d.pending
	d.mu.Unlock()
	if pending != 1 {
		t.Fatalf("pending in handler = %d, want 1", pending)
	}
	drainCtx, cancelDrain := context.WithCancel(context.Background())
	cancelDrain()
	if err := d.Drain(drainCtx); err != context.Canceled {
		t.Fatalf("Drain() in handler = %v, want %v", err, context.Canceled)
	}

	close(releaseHandler)
	settleCtx, cancelSettle := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelSettle()
	if err := d.Drain(settleCtx); err != nil {
		t.Fatalf("Drain() after handler return: %v", err)
	}
	cancelStart()
	select {
	case err := <-startDone:
		if err != nil {
			t.Fatalf("Start returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after ctx cancel")
	}
}

// TestDispatcher_CancelDrainsAndExits preloads the queue before starting
// workers, cancels immediately, and asserts that all preloaded items are
// still flushed before Start returns.
func TestDispatcher_CancelDrainsAndExits(t *testing.T) {
	const preload = 5
	type handledItem struct {
		value  int
		ctxErr error
	}
	handled := make(chan handledItem, preload)
	drops := &dropRecorder{}
	d := NewDispatcher("test", 16, 1, func(ctx context.Context, value int) {
		handled <- handledItem{value: value, ctxErr: ctx.Err()}
	}, drops.observe)
	for i := 0; i < preload; i++ {
		d.Enqueue(i)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() { done <- d.Start(ctx) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after ctx cancel")
	}
	close(handled)
	seen := make(map[int]int, preload)
	for item := range handled {
		seen[item.value]++
		if item.ctxErr != nil {
			t.Errorf("handler context for preloaded item %d = %v, want live context", item.value, item.ctxErr)
		}
	}
	for value := 0; value < preload; value++ {
		if got := seen[value]; got != 1 {
			t.Errorf("handled preloaded item %d %d times, want exactly once", value, got)
		}
	}
	if got := drops.snapshot(); len(got) != 0 {
		t.Errorf("preloaded items reported drops %v, want none", got)
	}
	waitForDispatcherState(t, d, stateStopped)
}

// TestDispatcher_ParentCancellationDoesNotCancelInFlightWork verifies that
// accepted work keeps a live context during the bounded drain. The worker
// context is canceled only after the handler settles or the drain times out.
func TestDispatcher_ParentCancellationDoesNotCancelInFlightWork(t *testing.T) {
	handlerEntered := make(chan struct{})
	probeContext := make(chan struct{})
	contextErr := make(chan error, 1)
	releaseHandler := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseHandler) }) }

	d := NewDispatcher("test", 1, 1, func(ctx context.Context, _ int) {
		close(handlerEntered)
		<-probeContext
		contextErr <- ctx.Err()
		<-releaseHandler
	}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		release()
	})

	d.Enqueue(1)
	select {
	case <-handlerEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not start")
	}
	cancel()
	close(probeContext)

	var gotContextErr error
	select {
	case gotContextErr = <-contextErr:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not report its context state")
	}
	release()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after the in-flight handler settled")
	}
	if gotContextErr != nil {
		t.Errorf("in-flight handler context after parent cancellation = %v, want live context", gotContextErr)
	}
}

// TestDispatcher_EnqueueRacingDrainSettlesOrDrops verifies that admission and
// the Accepting-to-Draining transition are atomic. Every racing enqueue is
// either handled exactly once or reported as a draining drop.
func TestDispatcher_EnqueueRacingDrainSettlesOrDrops(t *testing.T) {
	const racers = 64
	handlerEntered := make(chan struct{})
	releaseHandler := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseHandler) }) }

	var handledMu sync.Mutex
	handled := make(map[int]int, racers+1)
	drops := &dropRecorder{}
	d := NewDispatcher("test", racers+1, 1, func(_ context.Context, value int) {
		if value == -1 {
			close(handlerEntered)
			<-releaseHandler
		}
		handledMu.Lock()
		handled[value]++
		handledMu.Unlock()
	}, drops.observe)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		release()
	})

	d.Enqueue(-1)
	select {
	case <-handlerEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("sentinel handler did not start")
	}

	raceGate := make(chan struct{})
	cancelIssued := make(chan struct{})
	go func() {
		<-raceGate
		cancel()
		close(cancelIssued)
	}()
	var enqueueWG sync.WaitGroup
	enqueueWG.Add(racers)
	for value := 0; value < racers; value++ {
		go func() {
			defer enqueueWG.Done()
			<-raceGate
			d.Enqueue(value)
		}()
	}
	close(raceGate)
	enqueueWG.Wait()
	<-cancelIssued
	waitForDispatcherState(t, d, stateDraining)

	// This enqueue is strictly after the transition, pinning the late-admission
	// reason even if every racing enqueue happened to win the mutex first.
	d.Enqueue(racers)
	release()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after accepted work settled")
	}

	handledMu.Lock()
	gotHandled := make(map[int]int, len(handled))
	for value, count := range handled {
		gotHandled[value] = count
	}
	handledMu.Unlock()
	if got := gotHandled[-1]; got != 1 {
		t.Errorf("sentinel handled %d times, want exactly once", got)
	}
	if got := gotHandled[racers]; got != 0 {
		t.Errorf("post-drain item handled %d times, want 0", got)
	}
	racedHandled := 0
	for value := 0; value < racers; value++ {
		if got := gotHandled[value]; got > 1 {
			t.Errorf("racing item %d handled %d times, want at most once", value, got)
		}
		racedHandled += gotHandled[value]
	}
	reasons := drops.snapshot()
	for i, reason := range reasons {
		if reason != DropDraining {
			t.Errorf("drop reason %d = %q, want %q", i, reason, DropDraining)
		}
	}
	if got := racedHandled + len(reasons) - 1; got != racers {
		t.Errorf("settled or dropped racing items = %d, want %d (handled=%d drops=%d including one late drop)", got, racers, racedHandled, len(reasons))
	}
	waitForDispatcherState(t, d, stateStopped)
}

// TestDispatcher_ShutdownTimeoutCancelsWorkerAndPurgesQueue verifies the
// timeout path: the in-flight handler is canceled, workers exit, and only
// then are unstarted accepted items settled as shutdown-timeout drops.
func TestDispatcher_ShutdownTimeoutCancelsWorkerAndPurgesQueue(t *testing.T) {
	handlerEntered := make(chan struct{})
	handlerExited := make(chan struct{})
	handlerContextErr := make(chan error, 1)

	var handledMu sync.Mutex
	var handled []int
	var observerMu sync.Mutex
	var reasons []DropReason
	var observerStates []dispatcherState
	observerRanBeforeHandlerExit := false
	var d *Dispatcher[int]
	d = NewDispatcher("test", 4, 1, func(ctx context.Context, value int) {
		if value == 0 {
			close(handlerEntered)
			<-ctx.Done()
			handlerContextErr <- ctx.Err()
			close(handlerExited)
		}
		handledMu.Lock()
		handled = append(handled, value)
		handledMu.Unlock()
	}, func(reason DropReason) {
		select {
		case <-handlerExited:
		default:
			observerRanBeforeHandlerExit = true
		}
		d.mu.Lock()
		state := d.state
		d.mu.Unlock()
		observerMu.Lock()
		reasons = append(reasons, reason)
		observerStates = append(observerStates, state)
		observerMu.Unlock()
	})
	d.drainTimeout = 0
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Start(ctx) }()
	t.Cleanup(cancel)

	d.Enqueue(0)
	select {
	case <-handlerEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight handler did not start")
	}
	d.Enqueue(1)
	d.Enqueue(2)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start returned parent cancellation as an error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not complete the zero-timeout shutdown")
	}
	select {
	case err := <-handlerContextErr:
		if err != context.Canceled {
			t.Errorf("worker context error = %v, want %v", err, context.Canceled)
		}
	default:
		t.Error("in-flight handler was not canceled before Start returned")
	}

	handledMu.Lock()
	gotHandled := append([]int(nil), handled...)
	handledMu.Unlock()
	if len(gotHandled) != 1 || gotHandled[0] != 0 {
		t.Errorf("handled items = %v, want only in-flight item 0", gotHandled)
	}
	observerMu.Lock()
	gotReasons := append([]DropReason(nil), reasons...)
	gotStates := append([]dispatcherState(nil), observerStates...)
	observerMu.Unlock()
	if observerRanBeforeHandlerExit {
		t.Error("shutdown-timeout observer ran before the worker handler exited")
	}
	if len(gotReasons) != 2 {
		t.Fatalf("shutdown-timeout drops = %v, want two", gotReasons)
	}
	for i, reason := range gotReasons {
		if reason != DropShutdownTimeout {
			t.Errorf("drop reason %d = %q, want %q", i, reason, DropShutdownTimeout)
		}
		if gotStates[i] != stateDraining {
			t.Errorf("state during drop %d = %d, want draining", i, gotStates[i])
		}
	}
	if got := d.Len(); got != 0 {
		t.Errorf("queue length after purge = %d, want 0", got)
	}
	if err := d.Drain(context.Background()); err != nil {
		t.Errorf("Drain() after timeout purge: %v", err)
	}
	d.mu.Lock()
	pending := d.pending
	d.mu.Unlock()
	if pending != 0 {
		t.Errorf("pending after timeout purge = %d, want 0", pending)
	}
	waitForDispatcherState(t, d, stateStopped)
}

// TestDispatcher_EnqueueAfterStopIsSafe pins the property the production
// wiring depends on: the queue is never closed, so producers that outlive
// shutdown degrade to drops rather than panicking. See the Dispatcher type
// documentation for why the ext-proc shutdown ordering makes this reachable.
func TestDispatcher_EnqueueAfterStopIsSafe(t *testing.T) {
	drops := &dropRecorder{}
	d := NewDispatcher("test", 4, 1, func(context.Context, int) {
		t.Error("post-stop item reached handler")
	}, drops.observe)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Start(ctx) }()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after ctx cancel")
	}

	// Well past Start's return: must not panic, at any queue depth.
	for i := 0; i < 16; i++ {
		d.Enqueue(i)
	}
	if got := d.Len(); got != 0 {
		t.Errorf("post-stop queue length = %d, want 0", got)
	}
	reasons := drops.snapshot()
	if len(reasons) != 16 {
		t.Fatalf("post-stop drops = %d, want 16", len(reasons))
	}
	for i, reason := range reasons {
		if reason != DropStopped {
			t.Errorf("post-stop drop reason %d = %q, want %q", i, reason, DropStopped)
		}
	}
}

// TestDispatcher_StartIsOneShot verifies that a second invocation cannot
// create another worker pool, either while the first Start is active or after
// it has reached Stopped.
func TestDispatcher_StartIsOneShot(t *testing.T) {
	handlerEntered := make(chan struct{})
	releaseHandler := make(chan struct{})
	d := NewDispatcher("test", 1, 1, func(context.Context, int) {
		close(handlerEntered)
		<-releaseHandler
	}, nil)

	firstCtx, cancelFirst := context.WithCancel(context.Background())
	firstDone := make(chan error, 1)
	go func() { firstDone <- d.Start(firstCtx) }()
	d.Enqueue(1)
	select {
	case <-handlerEntered:
	case <-time.After(2 * time.Second):
		cancelFirst()
		close(releaseHandler)
		t.Fatal("first Start did not launch its worker")
	}

	secondCtx, cancelSecond := context.WithCancel(context.Background())
	cancelSecond()
	secondErr := d.Start(secondCtx)
	cancelFirst()
	close(releaseHandler)
	select {
	case err := <-firstDone:
		if err != nil {
			t.Fatalf("first Start returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first Start did not return")
	}
	if secondErr == nil {
		t.Error("second Start while running returned nil, want rejection")
	}

	thirdCtx, cancelThird := context.WithCancel(context.Background())
	cancelThird()
	if err := d.Start(thirdCtx); err == nil {
		t.Error("Start after Stopped returned nil, want rejection")
	}
}

// TestDispatcher_EnqueueNilSafe verifies nil receivers and zero values never
// panic from the hot path.
func TestDispatcher_EnqueueNilSafe(t *testing.T) {
	tests := []struct {
		name string
		d    *Dispatcher[int]
	}{
		{name: "nil receiver", d: nil},
		{name: "zero value with nil channel", d: &Dispatcher[int]{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Must not panic.
			tc.d.Enqueue(1)
		})
	}

	var nilDispatcher *Dispatcher[int]
	if err := nilDispatcher.Drain(context.Background()); err != nil {
		t.Fatalf("nil Dispatcher Drain() = %v, want nil", err)
	}
	zeroDispatcher := &Dispatcher[int]{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := zeroDispatcher.Drain(ctx); err != context.Canceled {
		t.Fatalf("zero-value Dispatcher Drain() = %v, want %v", err, context.Canceled)
	}
	constructed := NewDispatcher("test", 1, 1, func(context.Context, int) {}, nil)
	if err := constructed.Drain(context.Background()); err != nil {
		t.Fatalf("new Dispatcher Drain() = %v, want nil", err)
	}
}

// TestDispatcher_ConstructorNormalization checks buffer/worker clamping and
// the Cap accessor.
func TestDispatcher_ConstructorNormalization(t *testing.T) {
	tests := []struct {
		name        string
		buffer      int
		workers     int
		wantCap     int
		wantWorkers int
	}{
		{name: "explicit values kept", buffer: 16, workers: 4, wantCap: 16, wantWorkers: 4},
		{name: "negative buffer clamps to zero", buffer: -1, workers: 1, wantCap: 0, wantWorkers: 1},
		{name: "non-positive workers clamp to one", buffer: 8, workers: 0, wantCap: 8, wantWorkers: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := NewDispatcher("test", tc.buffer, tc.workers, func(context.Context, int) {}, nil)
			if got := d.Cap(); got != tc.wantCap {
				t.Errorf("Cap() = %d, want %d", got, tc.wantCap)
			}
			if got := d.Workers(); got != tc.wantWorkers {
				t.Errorf("Workers() = %d, want %d", got, tc.wantWorkers)
			}
		})
	}
}
