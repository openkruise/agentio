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
	"k8s.io/utils/ptr"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"

	"github.com/openkruise/agentio/extensions/epe/pkg/policy/profilestore"
	"github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"
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

func TestProfileInspectionOmittedWithoutLocalStore(t *testing.T) {
	handler := NewHandler(Options{EnableDebug: true})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/debug/profiles", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("profile inspection without local store: %d", response.Code)
	}
	index := httptest.NewRecorder()
	handler.ServeHTTP(index, httptest.NewRequest(http.MethodGet, "/", nil))
	if index.Code != http.StatusOK || strings.Contains(index.Body.String(), "/debug/profiles") {
		t.Fatalf("index advertised unavailable profile inspection: %s", index.Body.String())
	}
}

// newTestHandler builds an admin handler backed by a store seeded with the
// given profiles.
func newTestHandler(
	t *testing.T,
	enableDebug bool,
	sps []*v1alpha1.SecurityProfile,
	gsps []*v1alpha1.GlobalSecurityProfile,
) http.Handler {
	t.Helper()
	store := profilestore.MakeFakeStore()
	for _, sp := range sps {
		store.ProfileSet(sp)
	}
	for _, gsp := range gsps {
		store.GlobalProfileSet(gsp)
	}
	return NewHandler(Options{EnableDebug: enableDebug, Store: store})
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
			name:       "GET workload_labels triggers match mode, global then namespaced by priority",
			method:     http.MethodGet,
			target:     "/debug/profiles?namespace=default&workload_labels=app=sleep",
			wantStatus: http.StatusOK,
			wantNames:  []string{"gsp-egress", "sp-team"},
			wantKinds:  []string{kindGlobalSecurityProfile, kindSecurityProfile},
			wantSpec:   false,
		},
		{
			name:       "POST with JSON body match mode",
			method:     http.MethodPost,
			target:     "/debug/profiles",
			body:       `{"namespace":"default","workload_labels":{"app":"sleep"}}`,
			wantStatus: http.StatusOK,
			wantNames:  []string{"gsp-egress", "sp-team"},
			wantKinds:  []string{kindGlobalSecurityProfile, kindSecurityProfile},
		},
		{
			name:       "GET full mode populates spec",
			method:     http.MethodGet,
			target:     "/debug/profiles?namespace=default&workload_labels=app=sleep&full=true",
			wantStatus: http.StatusOK,
			wantNames:  []string{"gsp-egress", "sp-team"},
			wantSpec:   true,
		},
		{
			name:       "POST full mode populates spec",
			method:     http.MethodPost,
			target:     "/debug/profiles",
			body:       `{"namespace":"default","workload_labels":{"app":"sleep"},"full":true}`,
			wantStatus: http.StatusOK,
			wantNames:  []string{"gsp-egress", "sp-team"},
			wantSpec:   true,
		},
		{
			name:       "GET non-matching labels match nothing",
			method:     http.MethodGet,
			target:     "/debug/profiles?namespace=default&workload_labels=app=other",
			wantStatus: http.StatusOK,
			wantNames:  []string{},
		},
		{
			name:       "POST non-matching labels match nothing",
			method:     http.MethodPost,
			target:     "/debug/profiles",
			body:       `{"namespace":"default","workload_labels":{"app":"other"}}`,
			wantStatus: http.StatusOK,
			wantNames:  []string{},
		},
		{
			name:       "GET missing namespace with workload_labels is 400",
			method:     http.MethodGet,
			target:     "/debug/profiles?workload_labels=app=sleep",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "POST missing namespace with workload_labels is 400",
			method:     http.MethodPost,
			target:     "/debug/profiles",
			body:       `{"workload_labels":{"app":"sleep"}}`,
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

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHandler(t, true, sps, gsps)
			var bodyReader *strings.Reader
			if tc.body != "" {
				bodyReader = strings.NewReader(tc.body)
			} else {
				bodyReader = strings.NewReader("")
			}
			req := httptest.NewRequest(tc.method, tc.target, bodyReader)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if tc.wantStatus != http.StatusOK {
				return
			}

			var resp ListResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if resp.Count != len(tc.wantNames) {
				t.Fatalf("count = %d, want %d", resp.Count, len(tc.wantNames))
			}
			for i, want := range tc.wantNames {
				if resp.Profiles[i].Name != want {
					t.Errorf("profiles[%d].name = %q, want %q", i, resp.Profiles[i].Name, want)
				}
			}
			for i, want := range tc.wantKinds {
				if resp.Profiles[i].Kind != want {
					t.Errorf("profiles[%d].kind = %q, want %q", i, resp.Profiles[i].Kind, want)
				}
			}
			if len(resp.Profiles) > 0 {
				gotSpec := resp.Profiles[0].Spec != nil
				if gotSpec != tc.wantSpec {
					t.Errorf("profiles[0].spec populated = %v, want %v", gotSpec, tc.wantSpec)
				}
				if !tc.wantSpec && resp.Profiles[0].CreationTimestamp != nil {
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

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.target, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
			}
			var resp ListResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if resp.Count != len(tc.wantNames) {
				t.Fatalf("count = %d, want %d", resp.Count, len(tc.wantNames))
			}
			for i, want := range tc.wantNames {
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

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/debug/profiles", strings.NewReader(tc.body))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
			}
			var resp ListResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if resp.Count != len(tc.wantNames) {
				t.Fatalf("count = %d, want %d", resp.Count, len(tc.wantNames))
			}
			for i, want := range tc.wantNames {
				if resp.Profiles[i].Name != want {
					t.Errorf("profiles[%d].name = %q, want %q", i, resp.Profiles[i].Name, want)
				}
			}
		})
	}
}

func TestHandleProfiles_InlineProfiles(t *testing.T) {
	const rules = `[{"name":"trace","match":[{"domains":["*"]}],` +
		`"actions":{"headerManipulation":{"set":[{"name":"X-T","value":"{{pod.name}}"}]}}}]`
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
	store.SandboxProfileSet(sbx)
	h := NewHandler(Options{EnableDebug: true, Store: store})

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
			name:       "GET workload_name appends the inline profile after selector matches",
			method:     http.MethodGet,
			target:     "/debug/profiles?namespace=sandboxes&workload_name=sbx-1&workload_labels=app=sleep",
			wantStatus: http.StatusOK,
			wantNames:  []string{"sp-team", "sbx-1"},
			wantKinds:  []string{kindSecurityProfile, kindSandbox},
		},
		{
			name:       "GET workload_name alone triggers match mode",
			method:     http.MethodGet,
			target:     "/debug/profiles?namespace=sandboxes&workload_name=sbx-1",
			wantStatus: http.StatusOK,
			wantNames:  []string{"sbx-1"},
			wantKinds:  []string{kindSandbox},
		},
		{
			name:       "POST workload_name in body",
			method:     http.MethodPost,
			target:     "/debug/profiles",
			body:       `{"namespace":"sandboxes","workload_name":"sbx-1"}`,
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
			name:       "GET workload_name without namespace is 400",
			method:     http.MethodGet,
			target:     "/debug/profiles?workload_name=sbx-1",
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.target, strings.NewReader(tc.body))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if tc.wantStatus != http.StatusOK {
				return
			}
			var resp ListResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if resp.Count != len(tc.wantNames) {
				t.Fatalf("count = %d, want %d (body: %s)", resp.Count, len(tc.wantNames), rec.Body.String())
			}
			for i := range tc.wantNames {
				if resp.Profiles[i].Name != tc.wantNames[i] || resp.Profiles[i].Kind != tc.wantKinds[i] {
					t.Errorf("profiles[%d] = %s/%s, want %s/%s", i,
						resp.Profiles[i].Kind, resp.Profiles[i].Name, tc.wantKinds[i], tc.wantNames[i])
				}
			}
		})
	}

	// Full mode returns the installed annotation's original rule chain.
	req := httptest.NewRequest(http.MethodGet,
		"/debug/profiles?namespace=sandboxes&workload_name=sbx-1&full=true", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("full mode status = %d (body: %s)", rec.Code, rec.Body.String())
	}
	var resp ListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Count != 1 {
		t.Fatalf("full mode response = %s", rec.Body.String())
	}
	spec := resp.Profiles[0].Spec
	if spec == nil || len(spec.Rules) != 1 || spec.Rules[0].Name != "trace" {
		t.Fatalf("full mode spec = %+v, want the annotation's rule chain", spec)
	}
	if got := spec.Rules[0].Actions.HeaderManipulation.Set[0].Value; got != "{{pod.name}}" {
		t.Fatalf("full mode changed the original plaintext header: %q", got)
	}

	sbx.ResourceVersion = "8"
	sbx.Annotations[securityprofile.AnnotationSecurityRules] = "invalid"
	store.SandboxProfileSet(sbx)
	stale := httptest.NewRecorder()
	h.ServeHTTP(stale, req)
	if stale.Code != http.StatusOK || stale.Body.String() != rec.Body.String() {
		t.Fatalf("full mode must retain the installed Sandbox version: %s", stale.Body.String())
	}
}

func TestHandleProfilesFullUsesInstalledVersion(t *testing.T) {
	store := profilestore.MakeFakeStore()
	profile := testSP("example", "ns", 7, nil)
	profile.ResourceVersion = "1"
	profile.CreationTimestamp = metav1.Unix(1_700_000_000, 0)
	profile.Spec.Inputs = []v1alpha1.SecurityProfileInput{
		{Name: "config", Inline: map[string]string{"env": "test"}},
	}
	store.ProfileSet(profile)
	invalid := profile.DeepCopy()
	invalid.ResourceVersion = "2"
	invalid.Spec.Priority = ptr.To[int32](99)
	invalid.Spec.Selector.MatchExpressions = []metav1.LabelSelectorRequirement{
		{Key: "app", Operator: "invalid"},
	}
	store.ProfileSet(invalid)
	h := NewHandler(Options{EnableDebug: true, Store: store})
	for range 3 {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/debug/profiles?full=true", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
		}
		var resp ListResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if resp.Count != 1 || resp.Profiles[0].Spec == nil {
			t.Fatalf("missing installed profile spec: %s", rec.Body.String())
		}
		view := resp.Profiles[0]
		if view.Priority != 7 || ptr.Deref(view.Spec.Priority, 0) != 7 ||
			view.Spec.Inputs[0].Inline["env"] != "test" ||
			!profile.CreationTimestamp.Equal(view.CreationTimestamp) {
			t.Fatalf("full mode does not describe the installed version: %s", rec.Body.String())
		}
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
