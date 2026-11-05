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
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"

	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	agentlog "github.com/openkruise/agentio/pkg/log"
	"github.com/openkruise/agentio/pkg/metrics"
	"github.com/openkruise/agentio/pkg/model"
)

type countingAuthenticator struct {
	calls  int
	caller model.PeerIdentity
}

func (a *countingAuthenticator) Authenticate(context.Context) (model.PeerIdentity, error) {
	a.calls++
	return a.caller, nil
}

func TestNewServerRegistersAllClientClassMetrics(t *testing.T) {
	previousMetrics := metrics.Default
	registry := metrics.NewRegistry()
	metrics.Default = registry
	t.Cleanup(func() { metrics.Default = previousMetrics })

	snapshot, err := model.NewResourceSet(nil)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(
		fakeAuthenticator{}, fakeResolver{}.scopeFuncs(), newFakeResourceStore(snapshot), func() bool { return true },
		1, nil, 1, 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)

	recorder := httptest.NewRecorder()
	registry.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := recorder.Body.String()
	for _, class := range []model.ClientClass{
		model.ClientSharedZTunnel,
		model.ClientDedicatedZTunnel,
		model.ClientEgressGateway,
	} {
		line := fmt.Sprintf(`agentio_xds_connections_by_class{class="%s"} 0`, class)
		if !strings.Contains(body, line+"\n") {
			t.Fatalf("metrics do not contain %q:\n%s", line, body)
		}
	}
}

// A reconnect storm must be rejected before authentication and before the
// receive goroutine can fill the per-client request queue.
func TestRequestRateLimitRejectsBeforeQueueGrowth(t *testing.T) {
	authenticator := &countingAuthenticator{}
	snapshot, err := model.NewResourceSet(nil)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(
		authenticator,
		fakeResolver{scope: ztunnelScope()}.scopeFuncs(),
		newFakeResourceStore(snapshot),
		func() bool { return true },
		1,
		testGenerators(nil),
		1,
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := server.flow.acceptRequest(ctx); err != nil {
		t.Fatalf("first request rejected: %v", err)
	}
	if err := server.flow.acceptRequest(ctx); !errors.Is(err, errRequestRateLimited) {
		t.Fatalf("second acceptRequest() error = %v, want errRequestRateLimited", err)
	}
	stream := newFakeStream(ctx, 1)
	stream.send(nodeRequest(model.AddressType))
	err = server.serveDelta(stream)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("serveDelta() error = %v, want ResourceExhausted", err)
	}
	if authenticator.calls != 0 {
		t.Fatalf("Authenticate called %d times for rejected request", authenticator.calls)
	}
	if queued := len(stream.requests); queued != 1 {
		t.Fatalf("queued requests = %d, want first request left unread", queued)
	}
}

func TestNewServerRejectsNonFiniteRequestRateLimit(t *testing.T) {
	snapshot, err := model.NewResourceSet(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		limit float64
	}{
		{name: "NaN", limit: math.NaN()},
		{name: "positive infinity", limit: math.Inf(1)},
		{name: "negative infinity", limit: math.Inf(-1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, err := NewServer(
				fakeAuthenticator{},
				fakeResolver{}.scopeFuncs(),
				newFakeResourceStore(snapshot),
				func() bool { return true },
				1,
				nil,
				1,
				tc.limit,
			)
			if server != nil {
				server.Close()
			}
			if err == nil || server != nil {
				t.Fatalf(
					"NewServer(requestRateLimit=%v) = (%#v, %v), want nil server and validation error",
					tc.limit,
					server,
					err,
				)
			}
		})
	}
}

func TestServeDeltaLogsConnectionLifecycleWithConnectionID(t *testing.T) {
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	server := newTestServer(t, ztunnelScope(),
		[]model.Resource{addressResource(t, "workload-a", "payload")}, nil)
	stream := newFakeStream(context.Background(), 4)
	stream.send(nodeRequest(model.AddressType))
	if err := server.run(t, stream); err != nil {
		t.Fatal(err)
	}

	logs := output.String()
	lineWith := func(msg string) string {
		t.Helper()
		for _, line := range strings.Split(logs, "\n") {
			if strings.Contains(line, msg) {
				return line
			}
		}
		t.Fatalf("no log line containing %q:\n%s", msg, logs)
		return ""
	}
	authenticated := lineWith(`msg="authenticated Delta ADS client"`)
	disconnected := lineWith(`msg="Delta ADS client disconnected"`)
	push := lineWith(`msg="Delta ADS push"`)
	for _, line := range []string{authenticated, disconnected, push} {
		if !strings.Contains(line, "node_id="+nodeRequest(model.AddressType).Node.Id) ||
			!strings.Contains(line, "client_class="+string(ztunnelScope().Class)) {
			t.Fatalf("connection log cannot identify the workload: %s", line)
		}
	}
	if !strings.Contains(push, "version="+stream.sent()[0].SystemVersionInfo) {
		t.Fatalf("push log cannot be correlated with its snapshot: %s", push)
	}

	idPattern := regexp.MustCompile(`connection_id=(\d+)`)
	connectionID := func(line string) string {
		t.Helper()
		match := idPattern.FindStringSubmatch(line)
		if match == nil {
			t.Fatalf("log line has no connection_id: %s", line)
		}
		return match[1]
	}
	id := connectionID(authenticated)
	if got := connectionID(disconnected); got != id {
		t.Fatalf("disconnect connection_id = %s, want %s", got, id)
	}
	if got := connectionID(push); got != id {
		t.Fatalf("push connection_id = %s, want %s", got, id)
	}
	if !strings.Contains(disconnected, "duration=") {
		t.Fatalf("disconnect log has no duration: %s", disconnected)
	}
	if strings.Contains(disconnected, "error=") {
		t.Fatalf("clean shutdown logged an error: %s", disconnected)
	}
	if !strings.Contains(disconnected, "level=INFO") {
		t.Fatalf("clean shutdown log = %s, want INFO", disconnected)
	}
}

func TestCanceledDeltaStreamLogsNormalDisconnect(t *testing.T) {
	var output synchronizedBuffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	server := newTestServer(t, ztunnelScope(), nil, nil)
	stream := newFakeStream(ctx, 1)
	stream.send(nodeRequest(model.AddressType))
	done := server.start(stream)
	stream.awaitResponses(t, model.AddressType, 1)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("stream error = %v, want context cancellation", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("canceled stream did not finish")
	}
	logs := output.String()
	if !strings.Contains(logs, `level=INFO msg="Delta ADS client disconnected"`) ||
		strings.Contains(logs, "level=ERROR") || strings.Contains(logs, "level=WARN") {
		t.Fatalf("normal cancellation logged as a failure:\n%s", logs)
	}
}

func TestExpectedStreamErrorDistinguishesCancellationFromFailures(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"native cancellation", context.Canceled, true},
		{"wrapped cancellation", fmt.Errorf("send: %w", context.Canceled), true},
		{"grpc cancellation", status.Error(codes.Canceled, "closed"), true},
		{"operation timeout", context.DeadlineExceeded, false},
		{"unavailable backend", status.Error(codes.Unavailable, "backend unavailable"), false},
		{"unrelated error text", errors.New("compile failed: context canceled"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := expectedStreamError(tc.err); got != tc.want {
				t.Fatalf("expectedStreamError(%v) = %t, want %t", tc.err, got, tc.want)
			}
		})
	}
}

func TestDeltaRequestLogsSubscriptionCountsWithoutResourceNames(t *testing.T) {
	var output bytes.Buffer
	previousLogger := slog.Default()
	previousLevel := agentlog.OutputLevel()
	slog.SetDefault(slog.New(slog.NewTextHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug})))
	agentlog.ConfigureOutputLevel(slog.LevelDebug)
	t.Cleanup(func() {
		slog.SetDefault(previousLogger)
		agentlog.ConfigureOutputLevel(previousLevel)
	})

	const firstName = "name-that-must-not-be-logged-a"
	const secondName = "name-that-must-not-be-logged-b"
	server := newTestServer(t, ztunnelScope(), nil, nil)
	stream := newFakeStream(context.Background(), 4)
	stream.send(nodeRequest(model.AddressType, firstName, secondName))
	stream.send(&discoveryv3.DeltaDiscoveryRequest{
		TypeUrl:                  model.AddressType,
		ResourceNamesUnsubscribe: []string{firstName},
	})
	if err := server.run(t, stream); err != nil {
		t.Fatal(err)
	}

	logs := output.String()
	var subscribeRequest, unsubscribeRequest, watchStarted string
	for _, line := range strings.Split(logs, "\n") {
		switch {
		case strings.Contains(line, `msg="Delta ADS request"`) && strings.Contains(line, "sub=2"):
			subscribeRequest = line
		case strings.Contains(line, `msg="Delta ADS request"`) && strings.Contains(line, "unsub=1"):
			unsubscribeRequest = line
		case strings.Contains(line, `msg="Delta ADS watch started"`):
			watchStarted = line
		}
	}
	if subscribeRequest == "" || !strings.Contains(subscribeRequest, "unsub=0") {
		t.Fatalf("missing initial request counts:\n%s", logs)
	}
	if unsubscribeRequest == "" || !strings.Contains(unsubscribeRequest, "sub=0") {
		t.Fatalf("missing unsubscribe request counts:\n%s", logs)
	}
	if watchStarted == "" || !strings.Contains(watchStarted, "level=DEBUG") ||
		!strings.Contains(watchStarted, "resources=2") {
		t.Fatalf("watch-start log = %q, want DEBUG with resource count:\n%s", watchStarted, logs)
	}
	if strings.Contains(logs, "resource_names=") || strings.Contains(logs, firstName) ||
		strings.Contains(logs, secondName) {
		t.Fatalf("subscription resource names leaked into logs:\n%s", logs)
	}
}

func TestNACKLogIncludesStatusCode(t *testing.T) {
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	server := newTestServer(t, ztunnelScope(), nil, nil)
	stream := newFakeStream(context.Background(), 3)
	stream.send(nodeRequest(model.AddressType))
	stream.send(&discoveryv3.DeltaDiscoveryRequest{
		TypeUrl:       model.AddressType,
		ResponseNonce: "1",
		ErrorDetail: &rpcstatus.Status{
			Code:    int32(codes.InvalidArgument),
			Message: "rejected by the proxy",
		},
	})
	if err := server.run(t, stream); err != nil {
		t.Fatal(err)
	}

	for _, line := range strings.Split(output.String(), "\n") {
		if strings.Contains(line, `msg="xDS NACK"`) {
			if !strings.Contains(line, "level=WARN") || !strings.Contains(line, "code=InvalidArgument") ||
				!strings.Contains(line, "node_id="+nodeRequest(model.AddressType).Node.Id) {
				t.Fatalf("NACK log = %s, want WARN with status code", line)
			}
			return
		}
	}
	t.Fatalf("missing NACK log:\n%s", output.String())
}

func TestUnexpectedPushFailureIsLoggedBeforeErrorDisconnect(t *testing.T) {
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	server := newTestServer(t, ztunnelScope(), []model.Resource{
		addressResource(t, "workload-a", "payload"),
	}, nil)
	stream := newFakeStream(context.Background(), 1)
	stream.setSendErr(errors.New("send failed"))
	stream.send(nodeRequest(model.AddressType))
	if err := server.run(t, stream); err == nil || err.Error() != "send failed" {
		t.Fatalf("stream error = %v, want send failed", err)
	}

	logs := output.String()
	var pushFailure, disconnected string
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, `msg="Delta ADS push failed"`) {
			pushFailure = line
		}
		if strings.Contains(line, `msg="Delta ADS client disconnected"`) {
			disconnected = line
		}
	}
	if pushFailure == "" || !strings.Contains(pushFailure, "level=WARN") ||
		!strings.Contains(pushFailure, "stage=send") || !strings.Contains(pushFailure, "error=\"send failed\"") {
		t.Fatalf("push failure log = %q, want WARN with send stage and error:\n%s", pushFailure, logs)
	}
	if disconnected == "" || !strings.Contains(disconnected, "level=ERROR") ||
		!strings.Contains(disconnected, "error=\"send failed\"") {
		t.Fatalf("disconnect log = %q, want ERROR with cause:\n%s", disconnected, logs)
	}
}

func TestPushLogUsesHumanReadableSizeAndDemotesEmptyPushes(t *testing.T) {
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	agentlog.ConfigureOutputLevel(slog.LevelDebug)
	t.Cleanup(func() { agentlog.ConfigureOutputLevel(slog.LevelInfo) })

	populated := newTestServer(t, ztunnelScope(),
		[]model.Resource{addressResource(t, "workload-a", "payload")}, nil)
	stream := newFakeStream(context.Background(), 4)
	stream.send(nodeRequest(model.AddressType))
	if err := populated.run(t, stream); err != nil {
		t.Fatal(err)
	}
	empty := newTestServer(t, ztunnelScope(), nil, nil)
	emptyStream := newFakeStream(context.Background(), 4)
	emptyStream.send(nodeRequest(model.AddressType))
	if err := empty.run(t, emptyStream); err != nil {
		t.Fatal(err)
	}

	var populatedPush, emptyPush string
	for _, line := range strings.Split(output.String(), "\n") {
		if !strings.Contains(line, `msg="Delta ADS push"`) {
			continue
		}
		if strings.Contains(line, "resources=0") {
			emptyPush = line
		} else {
			populatedPush = line
		}
	}
	if populatedPush == "" || emptyPush == "" {
		t.Fatalf("missing push logs:\n%s", output.String())
	}
	sizePattern := regexp.MustCompile(`size=\d+(\.\d+)?(B|kB|MB|GB)`)
	for _, line := range []string{populatedPush, emptyPush} {
		if !sizePattern.MatchString(line) || strings.Contains(line, "size_bytes=") {
			t.Fatalf("push log size is not human-readable: %s", line)
		}
		if !strings.Contains(line, "duration=") {
			t.Fatalf("push log has no duration: %s", line)
		}
	}
	if !strings.Contains(populatedPush, "level=INFO") {
		t.Fatalf("populated full push log = %s, want INFO", populatedPush)
	}
	if !strings.Contains(populatedPush, "push=full") {
		t.Fatalf("populated full push log = %s, want full push mode", populatedPush)
	}
	if !strings.Contains(emptyPush, "level=DEBUG") {
		t.Fatalf("empty forced push log = %s, want DEBUG", emptyPush)
	}
}

func TestByteSizeFormatsUnits(t *testing.T) {
	for _, tc := range []struct {
		bytes int
		want  string
	}{
		{0, "0B"},
		{999, "999B"},
		{1000, "1.0kB"},
		{13016, "13.0kB"},
		{68500, "68.5kB"},
		{2_100_000, "2.1MB"},
		{3_200_000_000, "3.2GB"},
	} {
		if got := byteSize(tc.bytes); got != tc.want {
			t.Fatalf("byteSize(%d) = %q, want %q", tc.bytes, got, tc.want)
		}
	}
}

func TestServerPassesResolvedScopeToGeneratorUnchanged(t *testing.T) {
	scope := ztunnelScope()
	generator := &scopeRecordingGenerator{}
	server := newTestServerWithGenerators(t, scope, nil, map[string]ResourceGenerator{
		model.AddressType: generator,
	})
	stream := newFakeStream(context.Background(), 1)
	request := nodeRequest(model.AddressType)
	request.Node.Metadata.Fields["ISTIO_VERSION"] = structpb.NewStringValue("1.24.2")
	stream.send(request)
	if err := server.run(t, stream); err != nil {
		t.Fatal(err)
	}

	if generator.scope != scope {
		t.Fatalf("generator scope = %#v, want resolved scope %#v", generator.scope, scope)
	}
}

func TestServerDispatchesGeneratorByTypeURL(t *testing.T) {
	resource, err := model.NewResource(
		model.ResourceKey{TypeURL: model.SecretType, Name: "demo/egress|api.example.com"},
		"api.example.com",
		mustAny(&tlsv3.Secret{Name: "api.example.com"}),
		nil,
		model.ResourceFacts{GatewayOwner: "demo/egress"},
	)
	if err != nil {
		t.Fatal(err)
	}
	generator := &recordingGenerator{delta: GeneratedDelta{Resources: []model.Resource{resource}}}
	server := newTestServerWithGenerators(t, gatewayScope(), nil, map[string]ResourceGenerator{
		model.SecretType: generator,
	})
	stream := newFakeStream(context.Background(), 1)
	stream.send(nodeRequest(model.SecretType, "api.example.com"))
	if err := server.run(t, stream); err != nil {
		t.Fatal(err)
	}

	if generator.calls != 1 {
		t.Fatalf("generator calls = %d, want 1", generator.calls)
	}
	responses := stream.responsesFor(model.SecretType)
	if len(responses) != 1 || len(responses[0].GetResources()) != 1 {
		t.Fatalf("responses = %#v, want one resource", responses)
	}
	if got := responses[0].GetResources()[0].GetName(); got != "api.example.com" {
		t.Fatalf("resource name = %q, want api.example.com", got)
	}
}

func TestStreamWaitsForScopeBeforeSendingConfiguration(t *testing.T) {
	ts := newTestServer(t, ztunnelScope(), nil, nil)
	var ready atomic.Bool
	attempted := make(chan struct{}, 1)
	ts.server.scopeFuncs = ScopeFuncs{
		model.AttestationKubernetes: func(*corev3.Node, model.PeerIdentity) (model.ClientScope, error) {
			if ready.Load() {
				return ztunnelScope(), nil
			}
			select {
			case attempted <- struct{}{}:
			default:
			}
			return model.ClientScope{}, model.ErrScopeNotReady
		},
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	stream := newFakeStream(ctx, 1)
	stream.send(nodeRequest(model.AddressType))
	sent := make(chan struct{}, 1)
	stream.beforeSend = func() { sent <- struct{}{} }
	done := make(chan error, 1)
	go func() { done <- ts.server.serveDelta(stream) }()
	select {
	case <-attempted:
	case <-ctx.Done():
		t.Fatal("scope was not resolved")
	}
	if len(stream.sent()) != 0 {
		t.Fatal("configuration sent before scope was ready")
	}
	ready.Store(true)
	select {
	case <-sent:
	case err := <-done:
		t.Fatalf("stream ended before ready: %v", err)
	case <-ctx.Done():
		t.Fatal("no configuration after readiness")
	}
	cancel()
	<-done
}

func TestStreamScopeWaitStatus(t *testing.T) {
	for _, tc := range []struct {
		name       string
		resolveErr error
		want       codes.Code
	}{
		{name: "pending times out", resolveErr: model.ErrScopeNotReady, want: codes.DeadlineExceeded},
		{name: "invalid ownership", resolveErr: errors.New("Pod UID does not match"), want: codes.PermissionDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := newTestServer(t, ztunnelScope(), nil, nil)
			ts.server.scopeFuncs = fakeResolver{err: tc.resolveErr}.scopeFuncs()
			ctx, cancel := context.WithTimeout(t.Context(), 75*time.Millisecond)
			defer cancel()
			stream := newFakeStream(ctx, 1)
			stream.send(nodeRequest(model.AddressType))
			if err := ts.server.serveDelta(stream); status.Code(err) != tc.want {
				t.Fatalf("err=%v, want %v", err, tc.want)
			}
			if len(stream.sent()) != 0 {
				t.Fatal("sent configuration without an authorized scope")
			}
		})
	}
}
