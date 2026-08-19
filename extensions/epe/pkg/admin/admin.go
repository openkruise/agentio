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
// Package admin exposes the EPE admin HTTP surface. The admin
// server is always on; the debug endpoints under /debug are only registered
// when explicitly enabled, mirroring the Envoy/Istio admin convention.
package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"istio.io/istio/extensions/epe/pkg/policy/securityprofile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	log "sigs.k8s.io/controller-runtime/pkg/log"

	agentsclient "github.com/openkruise/agents-api/client/clientset/versioned"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"istio.io/istio/extensions/epe/pkg/policy/profilestore"
)

// Options configures the admin HTTP handler.
type Options struct {
	// EnableDebug toggles registration of the /debug endpoints.
	EnableDebug bool
	// Store provides the compiled profile snapshot used for matching.
	Store profilestore.Store
	// Client is a typed clientset used to fetch full CR content in
	// full mode. May be nil when EnableDebug is false.
	Client agentsclient.Interface
}

// handler holds the dependencies shared by the admin endpoints.
type handler struct {
	store       profilestore.Store
	client      agentsclient.Interface
	enableDebug bool
}

// NewHandler builds the admin HTTP handler. The index ("/") is always served;
// the debug endpoints are registered only when opts.EnableDebug is true.
func NewHandler(opts Options) http.Handler {
	h := &handler{
		store:       opts.Store,
		client:      opts.Client,
		enableDebug: opts.EnableDebug,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", h.handleIndex)
	if opts.EnableDebug {
		mux.HandleFunc("/debug/profiles", h.handleList)
	}
	return mux
}

// handleIndex serves a plain-text landing page listing available endpoints,
// and returns 404 for any unknown path.
func (h *handler) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "epe admin\n\n")
	fmt.Fprintf(w, "debug endpoints: %s\n", enabledText(h.enableDebug))
	if h.enableDebug {
		fmt.Fprintf(w, "  GET|POST /debug/profiles                          list all loaded profiles\n")
		fmt.Fprintf(w, "  GET|POST /debug/profiles?namespace=<ns>           filter by namespace\n")
		fmt.Fprintf(w, "  GET|POST /debug/profiles?namespace=<ns>&pod_labels=k=v,k=v  match profiles for pod labels\n")
		fmt.Fprintf(w, "  GET|POST /debug/profiles?namespace=<ns>&pod_name=<pod>      include the pod's inline rule profile\n")
		fmt.Fprintf(w, "  add ?full=true (POST: {\"full\":true}) for complete profile spec\n")
	}
}

func enabledText(enabled bool) string {
	if enabled {
		return "enabled"
	}
	return "disabled (start with --enable-debug)"
}

// toView builds the default (identity-only) view of a compiled profile.
func toView(p *securityprofile.Profile) ProfileView {
	kind := kindSecurityProfile
	switch {
	case p.Meta.Source == securityprofile.SourceInline:
		kind = kindSandbox
	case p.Meta.Namespace == "":
		kind = kindGlobalSecurityProfile
	}
	return ProfileView{
		Kind:      kind,
		Namespace: p.Meta.Namespace,
		Name:      p.Meta.Name,
		Priority:  p.Meta.Priority,
	}
}

// enrich fills the full-mode fields by fetching the live CR via the typed
// clientset. On failure it records the error on the view without aborting
// the response.
func (h *handler) enrich(ctx context.Context, v *ProfileView) {
	if h.client == nil {
		v.Error = "full content unavailable: no clientset configured"
		return
	}
	switch v.Kind {
	case kindGlobalSecurityProfile:
		gsp, err := h.client.AgentsV1alpha1().GlobalSecurityProfiles().Get(ctx, v.Name, metav1.GetOptions{})
		if err != nil {
			v.Error = err.Error()
			return
		}
		ct := gsp.CreationTimestamp
		v.CreationTimestamp = &ct
		v.Spec = &gsp.Spec
	case kindSandbox:
		sbx, err := h.client.AgentsV1alpha1().Sandboxes(v.Namespace).Get(ctx, v.Name, metav1.GetOptions{})
		if err != nil {
			v.Error = err.Error()
			return
		}
		var rules []v1alpha1.SecurityRule
		raw := sbx.Annotations[securityprofile.AnnotationSecurityRules]
		if err := json.Unmarshal([]byte(raw), &rules); err != nil {
			v.Error = fmt.Sprintf("decode %s annotation: %v", securityprofile.AnnotationSecurityRules, err)
			return
		}
		ct := sbx.CreationTimestamp
		v.CreationTimestamp = &ct
		// Inline rules have no CRD object; present them through the shared
		// spec shape with no selector (they match by identity only).
		v.Spec = &v1alpha1.SecurityProfileSpec{Rules: rules}
	default:
		sp, err := h.client.AgentsV1alpha1().SecurityProfiles(v.Namespace).Get(ctx, v.Name, metav1.GetOptions{})
		if err != nil {
			v.Error = err.Error()
			return
		}
		ct := sp.CreationTimestamp
		v.CreationTimestamp = &ct
		v.Spec = &sp.Spec
	}
}

// writeJSON serializes v as JSON with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Log.WithName("admin").Error(err, "failed to encode JSON response")
	}
}

// writeError writes a JSON error body with the given status code.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorResponse{Error: msg})
}
