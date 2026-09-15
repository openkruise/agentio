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

package debug

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/openkruise/agentio/pkg/krt"
	agentiolog "github.com/openkruise/agentio/pkg/log"
	"github.com/openkruise/agentio/pkg/model"
)

func TestLoggingHandlerGetsAndDynamicallyUpdatesLevel(t *testing.T) {
	previous := agentiolog.OutputLevel()
	previousKRT, found := agentiolog.ScopeOutputLevelName("krt")
	if !found {
		t.Fatal("krt logging scope is not registered")
	}
	t.Cleanup(func() {
		agentiolog.SetOutputLevel(previous)
		if err := agentiolog.SetScopeOutputLevelName("krt", previousKRT); err != nil {
			t.Errorf("restore krt logging level: %v", err)
		}
	})
	if err := agentiolog.SetOutputLevelName("info"); err != nil {
		t.Fatal(err)
	}
	fixture := newConfigDebugFixture(t, nil, true)
	handler := NewHandler(fixture.sources, fixture.compiler,
		&configDebugTestAuthenticator{err: errors.New("loopback must not authenticate")}, "agentio-system")

	get := serveDebugRequest(handler, http.MethodGet, LoggingPath, "127.0.0.1:41000", nil)
	if get.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want 200: %s", get.Code, get.Body.String())
	}
	var scopes []loggingInfo
	if err := json.Unmarshal(get.Body.Bytes(), &scopes); err != nil {
		t.Fatalf("decode logging scopes: %v", err)
	}
	before, found := findLoggingScope(scopes, "default")
	if !found || before.OutputLevel != "info" {
		t.Fatalf("default logging info = %+v, found=%t, want info", before, found)
	}

	put := serveDebugRequest(handler, http.MethodPut, LoggingPath+"/krt", "127.0.0.1:41000",
		[]byte(`{"output_level":"debug"}`))
	if put.Code != http.StatusAccepted {
		t.Fatalf("PUT status = %d, want 202: %s", put.Code, put.Body.String())
	}
	if got, found := agentiolog.ScopeOutputLevelName("krt"); !found || got != "debug" {
		t.Fatalf("krt output level = %q, found=%t, want debug", got, found)
	}
	if got := agentiolog.OutputLevelName(); got != "info" {
		t.Fatalf("krt update changed default output level to %q", got)
	}

	getKRT := serveDebugRequest(handler, http.MethodGet, LoggingPath+"/krt", "127.0.0.1:41000", nil)
	var krtScope loggingInfo
	if err := json.Unmarshal(getKRT.Body.Bytes(), &krtScope); err != nil {
		t.Fatalf("decode logging response: %v", err)
	}
	if getKRT.Code != http.StatusOK || krtScope.Name != "krt" || krtScope.OutputLevel != "debug" {
		t.Fatalf("krt logging info status=%d info=%+v, want 200/krt/debug", getKRT.Code, krtScope)
	}

	putDefault := serveDebugRequest(handler, http.MethodPut, LoggingPath, "127.0.0.1:41000",
		[]byte(`{"output_level":"error"}`))
	if putDefault.Code != http.StatusAccepted {
		t.Fatalf("default PUT status = %d, want 202: %s", putDefault.Code, putDefault.Body.String())
	}
	if got := agentiolog.OutputLevelName(); got != "error" {
		t.Fatalf("default output level = %q, want error", got)
	}
	if got, _ := agentiolog.ScopeOutputLevelName("krt"); got != "debug" {
		t.Fatalf("default update changed krt output level to %q", got)
	}
}

func TestLoggingHandlerRejectsInvalidOrUnauthenticatedUpdates(t *testing.T) {
	previous := agentiolog.OutputLevel()
	t.Cleanup(func() { agentiolog.SetOutputLevel(previous) })
	agentiolog.SetOutputLevel(slog.LevelWarn)
	fixture := newConfigDebugFixture(t, nil, true)

	loopback := NewHandler(fixture.sources, fixture.compiler,
		&configDebugTestAuthenticator{}, "agentio-system")
	invalid := serveDebugRequest(loopback, http.MethodPut, LoggingPath+"/default", "127.0.0.1:41000",
		[]byte(`{"output_level":"verbose"}`))
	if invalid.Code != http.StatusBadRequest || agentiolog.OutputLevelName() != "warn" {
		t.Fatalf("invalid update status=%d level=%q, want 400/warn", invalid.Code, agentiolog.OutputLevelName())
	}
	unknown := serveDebugRequest(loopback, http.MethodGet, LoggingPath+"/not-registered", "127.0.0.1:41000", nil)
	if unknown.Code != http.StatusBadRequest {
		t.Fatalf("unknown scope GET status=%d, want 400", unknown.Code)
	}

	unauthenticated := NewHandler(fixture.sources, fixture.compiler,
		&configDebugTestAuthenticator{err: errors.New("invalid token")}, "agentio-system")
	denied := serveDebugRequest(unauthenticated, http.MethodPut, LoggingPath+"/krt", "192.0.2.10:41000",
		[]byte(`{"output_level":"debug"}`))
	if denied.Code != http.StatusUnauthorized || agentiolog.OutputLevelName() != "warn" {
		t.Fatalf("unauthenticated update status=%d level=%q, want 401/warn", denied.Code, agentiolog.OutputLevelName())
	}
}

func findLoggingScope(scopes []loggingInfo, name string) (loggingInfo, bool) {
	for _, scope := range scopes {
		if scope.Name == name {
			return scope, true
		}
	}
	return loggingInfo{}, false
}

func TestConfigDebugHandlerAllowsLoopbackWithoutCredentials(t *testing.T) {
	fixture := newConfigDebugFixture(t, nil, true)
	authenticator := &configDebugTestAuthenticator{err: errors.New("must not authenticate loopback")}
	handler := NewHandler(fixture.sources, fixture.compiler, authenticator, "agentio-system")

	for _, remoteAddr := range []string{"127.0.0.1:41000", "[::1]:41001"} {
		recorder := serveConfigDebugRequest(handler, http.MethodGet, Path, remoteAddr)
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s response status = %d, want 200: %s", remoteAddr, recorder.Code, recorder.Body.String())
		}
	}
	if authenticator.calls != 0 {
		t.Fatalf("loopback invoked authenticator %d times, want 0", authenticator.calls)
	}
}

func TestConfigDebugHandlerAuthenticatesRemoteRootNamespaceServiceAccount(t *testing.T) {
	fixture := newConfigDebugFixture(t, nil, true)
	authenticator := &configDebugTestAuthenticator{peer: configDebugAuthorizedPeer("agentio-system")}
	handler := NewHandler(fixture.sources, fixture.compiler, authenticator, "agentio-system")
	req := httptest.NewRequest(http.MethodGet, Path, nil)
	req.RemoteAddr = "192.0.2.10:41000"
	req.Header.Add("Authorization", "Bearer first-token")
	req.Header.Add("Authorization", "Custom second-token")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("response status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	wantHeaders := []string{"Bearer first-token", "Custom second-token"}
	if !reflect.DeepEqual(authenticator.authorization, wantHeaders) {
		t.Fatalf("incoming authorization metadata = %v, want %v", authenticator.authorization, wantHeaders)
	}
}

func TestConfigDebugHandlerRejectsRemoteMissingOrInvalidCredentials(t *testing.T) {
	fixture := newConfigDebugFixture(t, nil, true)
	for _, test := range []struct {
		name       string
		remoteAddr string
	}{
		{name: "missing credentials", remoteAddr: "192.0.2.10:41000"},
		{name: "malformed remote address is not local", remoteAddr: "127.0.0.1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := NewHandler(fixture.sources, fixture.compiler,
				&configDebugTestAuthenticator{err: errors.New("credentials rejected")}, "agentio-system")
			recorder := serveConfigDebugRequest(handler, http.MethodGet, Path, test.remoteAddr)
			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("response status = %d, want 401: %s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestConfigDebugHandlerRejectsRemoteNonKubernetesOrWrongNamespaceIdentity(t *testing.T) {
	fixture := newConfigDebugFixture(t, nil, true)
	for _, test := range []struct {
		name string
		peer model.PeerIdentity
	}{
		{
			name: "non-kubernetes attestation",
			peer: func() model.PeerIdentity {
				peer := configDebugAuthorizedPeer("agentio-system")
				peer.AttestedBy = model.Attestation("firecracker")
				return peer
			}(),
		},
		{name: "wrong namespace", peer: configDebugAuthorizedPeer("application")},
		{
			name: "non-service-account principal",
			peer: func() model.PeerIdentity {
				peer := configDebugAuthorizedPeer("agentio-system")
				peer.Principal.Kind = model.PrincipalKind("user")
				return peer
			}(),
		},
		{
			name: "invalid service account principal",
			peer: model.PeerIdentity{
				AttestedBy: model.AttestationKubernetes,
				Principal: model.Principal{
					Kind:        model.PrincipalServiceAccount,
					TrustDomain: "cluster.local",
					ServiceAccount: model.ServiceAccountRef{
						Namespace: "agentio-system",
					},
				},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := NewHandler(fixture.sources, fixture.compiler,
				&configDebugTestAuthenticator{peer: test.peer}, "agentio-system")
			recorder := serveConfigDebugRequest(handler, http.MethodGet, Path, "192.0.2.10:41000")
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("response status = %d, want 403: %s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestConfigDebugHandlerDoesNotTrustForwardedFor(t *testing.T) {
	fixture := newConfigDebugFixture(t, nil, true)
	authenticator := &configDebugTestAuthenticator{err: errors.New("credentials rejected")}
	handler := NewHandler(fixture.sources, fixture.compiler, authenticator, "agentio-system")
	req := httptest.NewRequest(http.MethodGet, Path, nil)
	req.RemoteAddr = "192.0.2.10:41000"
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("response status = %d, want 401: %s", recorder.Code, recorder.Body.String())
	}
	if authenticator.calls != 1 {
		t.Fatalf("remote forwarded request invoked authenticator %d times, want 1", authenticator.calls)
	}
}

func TestConfigDebugHandlerValidatesMethod(t *testing.T) {
	fixture := newConfigDebugFixture(t, nil, true)
	handler := NewHandler(fixture.sources, fixture.compiler,
		&configDebugTestAuthenticator{err: errors.New("must not authenticate loopback")}, "agentio-system")

	recorder := serveConfigDebugRequest(handler, http.MethodPost, Path, "127.0.0.1:41000")

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("response status = %d, want 405: %s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Allow"); got != "GET, HEAD" {
		t.Fatalf("Allow header = %q, want %q", got, "GET, HEAD")
	}
}

func TestConfigDebugHandlerValidatesQuery(t *testing.T) {
	fixture := newConfigDebugFixture(t, nil, true)
	handler := NewHandler(fixture.sources, fixture.compiler,
		&configDebugTestAuthenticator{err: errors.New("must not authenticate loopback")}, "agentio-system")

	for _, rawQuery := range []string{
		"unknown=value",
		"kind=Unsupported",
		"kind=",
		"namespace=",
		"name=",
		"name=first&name=second",
		"pretty&pretty=yes",
	} {
		recorder := serveConfigDebugRequest(handler, http.MethodGet, Path+"?"+rawQuery, "127.0.0.1:41000")
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("query %q response status = %d, want 400: %s", rawQuery, recorder.Code, recorder.Body.String())
		}
	}

	request := httptest.NewRequest(http.MethodGet, Path, nil)
	request.RemoteAddr = "127.0.0.1:41000"
	request.URL.RawQuery = "kind=Gateway&name=%zz"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("malformed query response status = %d, want 400: %s", recorder.Code, recorder.Body.String())
	}
}

func TestConfigDebugHandlerFiltersAndPrettyPrints(t *testing.T) {
	fixture := newConfigDebugFixture(t, nil, true)
	handler := NewHandler(fixture.sources, fixture.compiler,
		&configDebugTestAuthenticator{err: errors.New("must not authenticate loopback")}, "agentio-system")
	recorder := serveConfigDebugRequest(handler, http.MethodGet,
		Path+"?pretty=ignored&kind=TrafficPolicy&namespace=demo&name=traffic", "127.0.0.1:41000")

	if recorder.Code != http.StatusOK {
		t.Fatalf("response status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	if !strings.Contains(recorder.Body.String(), "\n  \"generatedAt\"") {
		t.Fatalf("pretty response is not indented: %s", recorder.Body.String())
	}
	var response configDebugResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Items) != 1 || response.Items[0].Kind != "TrafficPolicy" || response.Items[0].Metadata.Name != "traffic" {
		t.Fatalf("filtered response items = %#v, want demo/traffic", response.Items)
	}
	wantCounts := map[string]int{"TrafficPolicy": 1}
	if !reflect.DeepEqual(response.CountsByKind, wantCounts) {
		t.Fatalf("filtered counts = %v, want %v", response.CountsByKind, wantCounts)
	}
}

func TestConfigDebugHandlerHEADMatchesGETWithoutBody(t *testing.T) {
	fixture := newConfigDebugFixture(t, nil, true)
	handler := NewHandler(fixture.sources, fixture.compiler,
		&configDebugTestAuthenticator{err: errors.New("must not authenticate loopback")}, "agentio-system")
	get := serveConfigDebugRequest(handler, http.MethodGet, Path+"?kind=Gateway", "127.0.0.1:41000")
	head := serveConfigDebugRequest(handler, http.MethodHead, Path+"?kind=Gateway", "127.0.0.1:41000")

	if head.Code != get.Code || head.Header().Get("Content-Type") != get.Header().Get("Content-Type") {
		t.Fatalf("HEAD status/content type = %d/%q, GET = %d/%q",
			head.Code, head.Header().Get("Content-Type"), get.Code, get.Header().Get("Content-Type"))
	}
	wantLength := strconv.Itoa(get.Body.Len())
	if get.Header().Get("Content-Length") != wantLength || head.Header().Get("Content-Length") != wantLength {
		t.Fatalf("GET/HEAD Content-Length = %q/%q, want %q",
			get.Header().Get("Content-Length"), head.Header().Get("Content-Length"), wantLength)
	}
	if head.Body.Len() != 0 {
		t.Fatalf("HEAD response body = %q, want empty", head.Body.String())
	}

	badHead := serveConfigDebugRequest(handler, http.MethodHead, Path+"?kind=Unsupported", "127.0.0.1:41000")
	if badHead.Code != http.StatusBadRequest || badHead.Body.Len() != 0 {
		t.Fatalf("invalid HEAD status/body = %d/%q, want 400 with no body", badHead.Code, badHead.Body.String())
	}
}

func TestConfigDebugHandlerAuditLogsDoNotExposeCredentials(t *testing.T) {
	fixture := newConfigDebugFixture(t, nil, true)
	logs := captureLogs(t)
	handler := NewHandler(fixture.sources, fixture.compiler,
		&configDebugTestAuthenticator{err: errors.New("TokenReview detail must stay private")}, "agentio-system")
	request := httptest.NewRequest(http.MethodGet, Path, nil)
	request.RemoteAddr = "192.0.2.10:41000"
	request.Header.Set("Authorization", "Bearer audit-secret-token")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("response status = %d, want 401", response.Code)
	}
	got := logs.String()
	for _, want := range []string{"path=/debug/configz", "remote=192.0.2.10:41000", "class=authentication_failed"} {
		if !strings.Contains(got, want) {
			t.Fatalf("audit log %q does not contain %q", got, want)
		}
	}
	for _, forbidden := range []string{"audit-secret-token", "TokenReview detail"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("audit log exposed %q: %s", forbidden, got)
		}
	}
}

func TestConfigDebugHandlerLogsConversionFailureWithoutLeakingDetailsToClient(t *testing.T) {
	fixture := newConfigDebugFixture(t, nil, true)
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	fixture.sources.GatewayPatches = krt.NewStaticCollection[model.GatewayPatch](nil, []model.GatewayPatch{{
		Namespace:      "demo",
		Name:           "invalid-any",
		Source:         "configmap/invalid-any",
		TargetGateways: []string{"agentio-system/egress"},
		Patches: []model.EnvoyPatch{{
			Operation: model.PatchAdd,
			Target: model.ExtensionConfigurationPatch{Value: &corev3.TypedExtensionConfig{
				Name: "invalid",
				TypedConfig: &anypb.Any{
					TypeUrl: "type.googleapis.com/example.UnknownDebugConfig",
					Value:   []byte("internal-protobuf-bytes"),
				},
			}},
		}},
	}}, krt.WithStop(stop))
	logs := captureLogs(t)
	handler := NewHandler(fixture.sources, fixture.compiler,
		&configDebugTestAuthenticator{err: errors.New("must not authenticate loopback")}, "agentio-system")
	response := serveConfigDebugRequest(handler, http.MethodGet, Path, "127.0.0.1:41000")

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("response status = %d, want 500: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(logs.String(), "class=snapshot_failed") || !strings.Contains(logs.String(), "UnknownDebugConfig") {
		t.Fatalf("conversion failure was not logged with detail: %s", logs.String())
	}
	for _, internal := range []string{"UnknownDebugConfig", "internal-protobuf-bytes"} {
		if strings.Contains(response.Body.String(), internal) {
			t.Fatalf("client response exposed %q: %s", internal, response.Body.String())
		}
	}
}

// capturedLogs also receives background collection logs while tests read it.
type capturedLogs struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (c *capturedLogs) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buffer.Write(p)
}

func (c *capturedLogs) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buffer.String()
}

func captureLogs(t *testing.T) *capturedLogs {
	t.Helper()
	output := &capturedLogs{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(output, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return output
}

type configDebugTestAuthenticator struct {
	peer          model.PeerIdentity
	err           error
	calls         int
	authorization []string
}

func (a *configDebugTestAuthenticator) Authenticate(ctx context.Context) (model.PeerIdentity, error) {
	a.calls++
	a.authorization = append([]string(nil), metadata.ValueFromIncomingContext(ctx, "authorization")...)
	return a.peer, a.err
}

func configDebugAuthorizedPeer(namespace string) model.PeerIdentity {
	return model.PeerIdentity{
		AttestedBy: model.AttestationKubernetes,
		Principal: model.Principal{
			Kind:        model.PrincipalServiceAccount,
			TrustDomain: "cluster.local",
			ServiceAccount: model.ServiceAccountRef{
				Namespace:      namespace,
				ServiceAccount: "debug-reader",
			},
		},
	}
}

func serveConfigDebugRequest(handler http.Handler, method, target, remoteAddr string) *httptest.ResponseRecorder {
	return serveDebugRequest(handler, method, target, remoteAddr, nil)
}

func serveDebugRequest(handler http.Handler, method, target, remoteAddr string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	req.RemoteAddr = remoteAddr
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	return recorder
}
