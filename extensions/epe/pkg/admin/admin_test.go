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
package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/ptr"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	agentsfake "github.com/openkruise/agents-api/client/clientset/versioned/fake"
	"istio.io/istio/extensions/epe/pkg/policy/profilestore"
	"istio.io/istio/extensions/epe/pkg/policy/securityprofile"
)

func testSP(name, namespace string, priority int32, matchLabels map[string]string) *v1alpha1.SecurityProfile {
	return &v1alpha1.SecurityProfile{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: v1alpha1.SecurityProfileSpec{
			Priority: ptr.To(priority),
			Selector: metav1.LabelSelector{MatchLabels: matchLabels},
		},
	}
}

func testGSP(name string, priority int32, matchLabels map[string]string) *v1alpha1.GlobalSecurityProfile {
	return &v1alpha1.GlobalSecurityProfile{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v1alpha1.SecurityProfileSpec{
			Priority: ptr.To(priority),
			Selector: metav1.LabelSelector{MatchLabels: matchLabels},
		},
	}
}

// newTestHandler builds an admin handler backed by a store seeded with the
// given profiles and a fake typed clientset containing the same objects.
func newTestHandler(t *testing.T, enableDebug bool, sps []*v1alpha1.SecurityProfile, gsps []*v1alpha1.GlobalSecurityProfile) http.Handler {
	t.Helper()
	store := profilestore.MakeFakeStore()
	objs := make([]runtime.Object, 0, len(sps)+len(gsps))
	for _, sp := range sps {
		store.ProfileSet(sp)
		objs = append(objs, sp)
	}
	for _, gsp := range gsps {
		store.GlobalProfileSet(gsp)
		objs = append(objs, gsp)
	}
	client := agentsfake.NewSimpleClientset(objs...)
	return NewHandler(Options{EnableDebug: enableDebug, Store: store, Client: client})
}

func TestHandleProfiles_MatchMode(t *testing.T) {
	sps := []*v1alpha1.SecurityProfile{testSP("sp-team", "default", 5, map[string]string{"app": "sleep"})}
	gsps := []*v1alpha1.GlobalSecurityProfile{testGSP("gsp-egress", 1, map[string]string{"app": "sleep"})}

	tests := []struct {
		name       string
		method     string
		target     string
		body       string
		wantStatus int
		wantNames  []string // expected profile names in order
		wantKinds  []string
		wantSpec   bool // whether profiles[0].spec should be populated
	}{
		{
			name:       "GET pod_labels triggers match mode, global then namespaced by priority",
			method:     http.MethodGet,
			target:     "/debug/profiles?namespace=default&pod_labels=app=sleep",
			wantStatus: http.StatusOK,
			wantNames:  []string{"gsp-egress", "sp-team"},
			wantKinds:  []string{kindGlobalSecurityProfile, kindSecurityProfile},
			wantSpec:   false,
		},
		{
			name:       "POST with JSON body match mode",
			method:     http.MethodPost,
			target:     "/debug/profiles",
			body:       `{"namespace":"default","pod_labels":{"app":"sleep"}}`,
			wantStatus: http.StatusOK,
			wantNames:  []string{"gsp-egress", "sp-team"},
			wantKinds:  []string{kindGlobalSecurityProfile, kindSecurityProfile},
		},
		{
			name:       "GET full mode populates spec",
			method:     http.MethodGet,
			target:     "/debug/profiles?namespace=default&pod_labels=app=sleep&full=true",
			wantStatus: http.StatusOK,
			wantNames:  []string{"gsp-egress", "sp-team"},
			wantSpec:   true,
		},
		{
			name:       "POST full mode populates spec",
			method:     http.MethodPost,
			target:     "/debug/profiles",
			body:       `{"namespace":"default","pod_labels":{"app":"sleep"},"full":true}`,
			wantStatus: http.StatusOK,
			wantNames:  []string{"gsp-egress", "sp-team"},
			wantSpec:   true,
		},
		{
			name:       "GET non-matching labels match nothing",
			method:     http.MethodGet,
			target:     "/debug/profiles?namespace=default&pod_labels=app=other",
			wantStatus: http.StatusOK,
			wantNames:  []string{},
		},
		{
			name:       "POST non-matching labels match nothing",
			method:     http.MethodPost,
			target:     "/debug/profiles",
			body:       `{"namespace":"default","pod_labels":{"app":"other"}}`,
			wantStatus: http.StatusOK,
			wantNames:  []string{},
		},
		{
			name:       "GET missing namespace with pod_labels is 400",
			method:     http.MethodGet,
			target:     "/debug/profiles?pod_labels=app=sleep",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "POST missing namespace with pod_labels is 400",
			method:     http.MethodPost,
			target:     "/debug/profiles",
			body:       `{"pod_labels":{"app":"sleep"}}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "POST invalid JSON is 400",
			method:     http.MethodPost,
			target:     "/debug/profiles",
			body:       `{not-json`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "PUT wrong method is 405",
			method:     http.MethodPut,
			target:     "/debug/profiles",
			wantStatus: http.StatusMethodNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newTestHandler(t, true, sps, gsps)
			var bodyReader *strings.Reader
			if tt.body != "" {
				bodyReader = strings.NewReader(tt.body)
			} else {
				bodyReader = strings.NewReader("")
			}
			req := httptest.NewRequest(tt.method, tt.target, bodyReader)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if tt.wantStatus != http.StatusOK {
				return
			}

			var resp ListResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if resp.Count != len(tt.wantNames) {
				t.Fatalf("count = %d, want %d", resp.Count, len(tt.wantNames))
			}
			for i, want := range tt.wantNames {
				if resp.Profiles[i].Name != want {
					t.Errorf("profiles[%d].name = %q, want %q", i, resp.Profiles[i].Name, want)
				}
			}
			for i, want := range tt.wantKinds {
				if resp.Profiles[i].Kind != want {
					t.Errorf("profiles[%d].kind = %q, want %q", i, resp.Profiles[i].Kind, want)
				}
			}
			if len(resp.Profiles) > 0 {
				gotSpec := resp.Profiles[0].Spec != nil
				if gotSpec != tt.wantSpec {
					t.Errorf("profiles[0].spec populated = %v, want %v", gotSpec, tt.wantSpec)
				}
				if !tt.wantSpec && resp.Profiles[0].CreationTimestamp != nil {
					t.Errorf("default mode should not populate creationTimestamp")
				}
			}
		})
	}
}

func TestHandleProfiles_ListMode(t *testing.T) {
	sps := []*v1alpha1.SecurityProfile{
		testSP("sp-b", "ns-a", 5, map[string]string{"app": "x"}),
		testSP("sp-a", "ns-a", 5, map[string]string{"app": "y"}),
		testSP("sp-c", "ns-b", 1, map[string]string{"app": "z"}),
	}
	gsps := []*v1alpha1.GlobalSecurityProfile{testGSP("gsp-1", 1, nil)}
	h := newTestHandler(t, true, sps, gsps)

	tests := []struct {
		name      string
		target    string
		wantNames []string
	}{
		{
			name:      "no params lists all profiles",
			target:    "/debug/profiles",
			wantNames: []string{"gsp-1", "sp-c", "sp-a", "sp-b"},
		},
		{
			name:      "namespace filter returns only matching namespace profiles",
			target:    "/debug/profiles?namespace=ns-a",
			wantNames: []string{"sp-a", "sp-b"},
		},
		{
			name:      "namespace filter is exact, excludes global profiles",
			target:    "/debug/profiles?namespace=ns-b",
			wantNames: []string{"sp-c"},
		},
		{
			name:      "namespace filter with no matches returns empty",
			target:    "/debug/profiles?namespace=ns-c",
			wantNames: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.target, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
			}
			var resp ListResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if resp.Count != len(tt.wantNames) {
				t.Fatalf("count = %d, want %d", resp.Count, len(tt.wantNames))
			}
			for i, want := range tt.wantNames {
				if resp.Profiles[i].Name != want {
					t.Errorf("profiles[%d].name = %q, want %q", i, resp.Profiles[i].Name, want)
				}
			}
		})
	}
}

func TestHandleProfiles_ListMode_POST(t *testing.T) {
	sps := []*v1alpha1.SecurityProfile{
		testSP("sp-a", "ns-a", 5, map[string]string{"app": "x"}),
		testSP("sp-b", "ns-a", 3, map[string]string{"app": "y"}),
	}
	gsps := []*v1alpha1.GlobalSecurityProfile{testGSP("gsp-1", 1, nil)}
	h := newTestHandler(t, true, sps, gsps)

	tests := []struct {
		name      string
		body      string
		wantNames []string
	}{
		{
			name:      "POST empty body lists all profiles",
			body:      `{}`,
			wantNames: []string{"gsp-1", "sp-b", "sp-a"},
		},
		{
			name:      "POST with namespace filter",
			body:      `{"namespace":"ns-a"}`,
			wantNames: []string{"sp-b", "sp-a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/debug/profiles", strings.NewReader(tt.body))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
			}
			var resp ListResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if resp.Count != len(tt.wantNames) {
				t.Fatalf("count = %d, want %d", resp.Count, len(tt.wantNames))
			}
			for i, want := range tt.wantNames {
				if resp.Profiles[i].Name != want {
					t.Errorf("profiles[%d].name = %q, want %q", i, resp.Profiles[i].Name, want)
				}
			}
		})
	}
}

func TestHandleProfiles_InlineProfiles(t *testing.T) {
	const rules = `[{"name":"trace","match":[{"domains":["*"]}],` +
		`"actions":{"headerManipulation":{"set":[{"name":"X-T","value":"v"}]}}}]`
	sbx := &v1alpha1.Sandbox{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "sbx-1",
			Namespace:   "sandboxes",
			Annotations: map[string]string{securityprofile.AnnotationSecurityRules: rules},
		},
	}
	sp := testSP("sp-team", "sandboxes", 5, map[string]string{"app": "sleep"})

	store := profilestore.MakeFakeStore()
	store.ProfileSet(sp)
	store.InlineProfileSet(sbx)
	client := agentsfake.NewSimpleClientset(sp)
	// NewSimpleClientset seeds objects under a guessed plural ("sandboxs"),
	// which does not match the typed client's "sandboxes"; seed the tracker
	// with the explicit resource instead.
	if err := client.Tracker().Create(
		schema.GroupVersionResource{Group: "agents.kruise.io", Version: "v1alpha1", Resource: "sandboxes"},
		sbx, sbx.Namespace); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}
	h := NewHandler(Options{EnableDebug: true, Store: store, Client: client})

	tests := []struct {
		name       string
		method     string
		target     string
		body       string
		wantStatus int
		wantNames  []string
		wantKinds  []string
	}{
		{
			name:       "GET pod_name appends the inline profile after selector matches",
			method:     http.MethodGet,
			target:     "/debug/profiles?namespace=sandboxes&pod_name=sbx-1&pod_labels=app=sleep",
			wantStatus: http.StatusOK,
			wantNames:  []string{"sp-team", "sbx-1"},
			wantKinds:  []string{kindSecurityProfile, kindSandbox},
		},
		{
			name:       "GET pod_name alone triggers match mode",
			method:     http.MethodGet,
			target:     "/debug/profiles?namespace=sandboxes&pod_name=sbx-1",
			wantStatus: http.StatusOK,
			wantNames:  []string{"sbx-1"},
			wantKinds:  []string{kindSandbox},
		},
		{
			name:       "POST pod_name in body",
			method:     http.MethodPost,
			target:     "/debug/profiles",
			body:       `{"namespace":"sandboxes","pod_name":"sbx-1"}`,
			wantStatus: http.StatusOK,
			wantNames:  []string{"sbx-1"},
			wantKinds:  []string{kindSandbox},
		},
		{
			name:       "list mode includes inline profiles",
			method:     http.MethodGet,
			target:     "/debug/profiles?namespace=sandboxes",
			wantStatus: http.StatusOK,
			wantNames:  []string{"sbx-1", "sp-team"},
			wantKinds:  []string{kindSandbox, kindSecurityProfile},
		},
		{
			name:       "GET pod_name without namespace is 400",
			method:     http.MethodGet,
			target:     "/debug/profiles?pod_name=sbx-1",
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.target, strings.NewReader(tt.body))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if tt.wantStatus != http.StatusOK {
				return
			}
			var resp ListResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if resp.Count != len(tt.wantNames) {
				t.Fatalf("count = %d, want %d (body: %s)", resp.Count, len(tt.wantNames), rec.Body.String())
			}
			for i := range tt.wantNames {
				if resp.Profiles[i].Name != tt.wantNames[i] || resp.Profiles[i].Kind != tt.wantKinds[i] {
					t.Errorf("profiles[%d] = %s/%s, want %s/%s", i,
						resp.Profiles[i].Kind, resp.Profiles[i].Name, tt.wantKinds[i], tt.wantNames[i])
				}
			}
		})
	}

	// Full mode decodes the annotation into the shared spec shape.
	req := httptest.NewRequest(http.MethodGet,
		"/debug/profiles?namespace=sandboxes&pod_name=sbx-1&full=true", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("full mode status = %d (body: %s)", rec.Code, rec.Body.String())
	}
	var resp ListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Count != 1 || resp.Profiles[0].Error != "" {
		t.Fatalf("full mode response = %s", rec.Body.String())
	}
	spec := resp.Profiles[0].Spec
	if spec == nil || len(spec.Rules) != 1 || spec.Rules[0].Name != "trace" {
		t.Fatalf("full mode spec = %+v, want the annotation's rule chain", spec)
	}
}

func TestDebugDisabled(t *testing.T) {
	h := newTestHandler(t, false, nil, nil)

	// Debug routes are not registered → index handler returns 404.
	req := httptest.NewRequest(http.MethodGet, "/debug/profiles", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("path /debug/profiles: status = %d, want 404", rec.Code)
	}

	// Index is always served.
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("index status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "disabled") {
		t.Errorf("index should report debug disabled, got: %s", rec.Body.String())
	}
}
