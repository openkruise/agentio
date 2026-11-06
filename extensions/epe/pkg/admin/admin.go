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
	"encoding/json"
	"fmt"
	"net/http"

	"go.uber.org/zap"

	log "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/openkruise/agentio/extensions/epe/pkg/policy/profilestore"
	"github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"
)

// Options configures the admin HTTP handler.
type Options struct {
	// EnableDebug toggles registration of the /debug endpoints.
	EnableDebug bool
	// Store provides the compiled profile snapshot used for matching.
	Store profilestore.Store
	// Credentials invalidates the same client used by the filter chain. Nil omits
	// the cache endpoint; its registration is independent of EnableDebug.
	Credentials CredentialInvalidator
	// LogLevel controls the running process's logger. Nil omits /debug/logging.
	LogLevel *zap.AtomicLevel
}

// handler holds the dependencies shared by the admin endpoints.
type handler struct {
	store       profilestore.Store
	enableDebug bool
	logLevel    *zap.AtomicLevel
	credentials CredentialInvalidator
}

// NewHandler builds the admin HTTP handler. The index ("/") is always served;
// the debug endpoints are registered only when opts.EnableDebug is true.
func NewHandler(opts Options) http.Handler {
	h := &handler{
		store:       opts.Store,
		enableDebug: opts.EnableDebug,
		logLevel:    opts.LogLevel,
		credentials: opts.Credentials,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", h.handleIndex)
	if h.credentials != nil {
		mux.HandleFunc(credentialInvalidationPath, h.handleCredentialInvalidation)
	}
	if opts.EnableDebug {
		mux.HandleFunc("/debug/profiles", h.handleList)
		if h.logLevel != nil {
			mux.HandleFunc(loggingPath, h.handleLogging)
			mux.HandleFunc(loggingPath+"/", h.handleLogging)
		}
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
	if h.credentials != nil {
		if _, err := fmt.Fprintf(
			w,
			"  POST %s  invalidate local credential caches\n",
			credentialInvalidationPath,
		); err != nil {
			return
		}
	}
	fmt.Fprintf(w, "debug endpoints: %s\n", enabledText(h.enableDebug))
	if h.enableDebug {
		if h.logLevel != nil {
			if _, err := fmt.Fprintf(
				w,
				"  GET|HEAD|PUT /debug/logging[/default]             inspect or change the log level\n",
			); err != nil {
				return
			}
		}
		fmt.Fprintf(w, "  GET|POST /debug/profiles                          list all loaded profiles\n")
		fmt.Fprintf(w, "  GET|POST /debug/profiles?namespace=<ns>           filter by namespace\n")
		if _, err := fmt.Fprint(w,
			"  GET|POST /debug/profiles?namespace=<ns>&workload_labels=k=v,k=v  match profiles for workload labels\n"+
				"  GET|POST /debug/profiles?namespace=<ns>&workload_name=<name>     include the same-name Sandbox profile\n",
		); err != nil {
			log.Log.WithName("admin").Error(err, "failed to write admin index")
			return
		}
		fmt.Fprintf(w, "  add ?full=true (POST: {\"full\":true}) for complete profile spec\n")
	}
}

func enabledText(enabled bool) string {
	if enabled {
		return "enabled"
	}
	return "disabled (start with --enable-debug)"
}

// toView describes one installed profile, including its source spec in full mode.
func toView(p *securityprofile.Profile, full bool) ProfileView {
	kind := kindSecurityProfile
	switch {
	case p.Meta.Match == securityprofile.MatchSandbox:
		kind = kindSandbox
	case p.Meta.Namespace == "":
		kind = kindGlobalSecurityProfile
	}
	view := ProfileView{
		Kind:      kind,
		Namespace: p.Meta.Namespace,
		Name:      p.Meta.Name,
		Priority:  p.Meta.Priority,
	}
	if full {
		view.CreationTimestamp = &p.Meta.CreationTimestamp
		view.Spec = p.Spec
	}
	return view
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
