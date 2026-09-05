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
	"maps"
	"math"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"istio.io/istio/pkg/util/sets"

	agentlog "github.com/openkruise/agentio/pkg/log"
	"github.com/openkruise/agentio/pkg/metrics"
	"github.com/openkruise/agentio/pkg/model"
)

type countingAuthenticator struct{ calls int }

func (a *countingAuthenticator) Authenticate(context.Context) (model.PeerIdentity, error) {
	a.calls++
	return model.PeerIdentity{}, nil
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
	if err := server.acceptRequest(ctx); err != nil {
		t.Fatalf("first request rejected: %v", err)
	}
	if err := server.acceptRequest(ctx); !errors.Is(err, errRequestRateLimited) {
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
				fakeAuthenticator{}, fakeResolver{}.scopeFuncs(), newFakeResourceStore(snapshot), func() bool { return true },
				1, nil, 1, tc.limit,
			)
			if server != nil {
				server.Close()
			}
			if err == nil || server != nil {
				t.Fatalf("NewServer(requestRateLimit=%v) = (%#v, %v), want nil server and validation error", tc.limit, server, err)
			}
		})
	}
}

func TestApplySubscriptionRecognizesExplicitWildcard(t *testing.T) {
	watch := &watchState{names: sets.New[string](), sent: map[string]string{}}
	changed, err := applySubscription(watch, &discoveryv3.DeltaDiscoveryRequest{
		ResourceNamesSubscribe: []string{"*"},
	})
	if err != nil || !changed || !watch.wildcard || !watch.started {
		t.Fatalf("wildcard subscription = changed:%v wildcard:%v started:%v err:%v", changed, watch.wildcard, watch.started, err)
	}
	if len(watch.names) != 0 {
		t.Fatalf("explicit wildcard retained as a literal resource name: %v", watch.names)
	}
}

func TestApplySubscriptionTypeAwareImplicitWildcard(t *testing.T) {
	tests := []struct {
		name     string
		typeURL  string
		wildcard bool
	}{
		{name: "CDS", typeURL: model.ClusterType, wildcard: true},
		{name: "RDS", typeURL: model.RouteType, wildcard: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			watch := &watchState{names: sets.New[string](), sent: map[string]string{}}
			changed, err := applySubscription(watch, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: test.typeURL})
			if err != nil {
				t.Fatal(err)
			}
			if !changed || !watch.started || watch.wildcard != test.wildcard {
				t.Fatalf("subscription = changed:%t started:%t wildcard:%t, want wildcard:%t",
					changed, watch.started, watch.wildcard, test.wildcard)
			}
		})
	}
}

func TestApplySubscriptionRestoresNamedInitialVersions(t *testing.T) {
	watch := &watchState{names: sets.New[string](), sent: map[string]string{}}
	initial := map[string]string{"route-a": "v1", "route-b": "v2"}
	changed, err := applySubscription(watch, &discoveryv3.DeltaDiscoveryRequest{
		TypeUrl:                 model.RouteType,
		InitialResourceVersions: initial,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !changed || watch.wildcard {
		t.Fatalf("restored subscription = changed:%t wildcard:%t, want changed named watch", changed, watch.wildcard)
	}
	if !maps.Equal(watch.names, sets.New("route-a", "route-b")) {
		t.Fatalf("restored names = %v, want route-a and route-b", watch.names)
	}
	if !maps.Equal(watch.sent, initial) {
		t.Fatalf("restored sent versions = %v, want %v", watch.sent, initial)
	}
}

func TestApplySubscriptionCanLeaveExplicitWildcard(t *testing.T) {
	watch := &watchState{wildcard: true, started: true, names: sets.New[string](), sent: map[string]string{}}
	changed, err := applySubscription(watch, &discoveryv3.DeltaDiscoveryRequest{
		ResourceNamesSubscribe:   []string{"sandbox/default"},
		ResourceNamesUnsubscribe: []string{"*"},
	})
	if err != nil || !changed || watch.wildcard {
		t.Fatalf("named subscription after wildcard = changed:%v wildcard:%v err:%v", changed, watch.wildcard, err)
	}
	if !watch.names.Contains("sandbox/default") {
		t.Fatalf("named subscription missing: %v", watch.names)
	}
}

// A client must not be able to grow per-connection state without bound by
// enrolling ever more resource names across requests.
func TestApplySubscriptionRejectsNamesBeyondLimit(t *testing.T) {
	watch := &watchState{names: sets.New[string](), sent: map[string]string{}}
	for i := 0; i < maxSubscriptionNames; i += 2 {
		_, err := applySubscription(watch, &discoveryv3.DeltaDiscoveryRequest{
			ResourceNamesSubscribe: []string{fmt.Sprintf("name-%d", i), fmt.Sprintf("name-%d", i+1)},
		})
		if err != nil {
			t.Fatalf("subscription below limit rejected: %v", err)
		}
	}
	if len(watch.names) != maxSubscriptionNames {
		t.Fatalf("names = %d, want %d", len(watch.names), maxSubscriptionNames)
	}
	// Re-subscribing an existing name stays within the limit.
	if _, err := applySubscription(watch, &discoveryv3.DeltaDiscoveryRequest{
		ResourceNamesSubscribe: []string{"name-0"},
	}); err != nil {
		t.Fatalf("re-subscription of an existing name rejected: %v", err)
	}
	// A new name beyond the limit is refused.
	if _, err := applySubscription(watch, &discoveryv3.DeltaDiscoveryRequest{
		ResourceNamesSubscribe: []string{"one-name-too-many"},
	}); !errors.Is(err, errTooManySubscribedNames) {
		t.Fatalf("over-limit subscription error = %v, want errTooManySubscribedNames", err)
	}
	if watch.names.Contains("one-name-too-many") {
		t.Fatalf("over-limit name was recorded: %v", watch.names)
	}
	// Unsubscribing frees room again.
	if _, err := applySubscription(watch, &discoveryv3.DeltaDiscoveryRequest{
		ResourceNamesUnsubscribe: []string{"name-0"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := applySubscription(watch, &discoveryv3.DeltaDiscoveryRequest{
		ResourceNamesSubscribe: []string{"replacement-name"},
	}); err != nil {
		t.Fatalf("subscription after unsubscribe rejected: %v", err)
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
	if strings.Contains(logs, "resource_names=") || strings.Contains(logs, firstName) || strings.Contains(logs, secondName) {
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
			if !strings.Contains(line, "level=WARN") || !strings.Contains(line, "code=InvalidArgument") {
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
	for _, test := range []struct {
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
		if got := byteSize(test.bytes); got != test.want {
			t.Fatalf("byteSize(%d) = %q, want %q", test.bytes, got, test.want)
		}
	}
}
