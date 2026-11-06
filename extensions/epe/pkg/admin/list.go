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

	"github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"

	"github.com/openkruise/agentio/extensions/epe/pkg/labels"
)

// maxBodyBytes caps POST request body size to prevent abuse.
const maxBodyBytes = 1 << 20 // 1 MiB

// handleList serves two modes based on the presence of workload_labels/workload_name:
//   - Without them: lists all profiles (optionally filtered by namespace)
//   - With workload_labels and/or workload_name: returns matched profiles in evaluation
//     order; workload_name additionally resolves the same-name Sandbox profile.
//
// Accepts GET with query params or POST with JSON body.
func (h *handler) handleList(w http.ResponseWriter, r *http.Request) {
	var namespace, workloadName, workloadLabelsRaw string
	var full bool

	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query()
		namespace = q.Get("namespace")
		workloadName = q.Get("workload_name")
		workloadLabelsRaw = q.Get("workload_labels")
		full = q.Get("full") == "true"
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		var req debugRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
			return
		}
		namespace = req.Namespace
		full = req.Full
		if len(req.WorkloadLabels) > 0 || req.WorkloadName != "" {
			h.handleMatch(w, r, req.WorkloadName, namespace, req.WorkloadLabels, full)
			return
		}
	default:
		w.Header().Set("Allow", "GET, POST")
		writeError(w, http.StatusMethodNotAllowed, "method not allowed; use GET or POST")
		return
	}

	if workloadLabelsRaw != "" || workloadName != "" {
		h.handleMatch(w, r, workloadName, namespace, labels.ParseLabelPairs(workloadLabelsRaw), full)
		return
	}

	// List mode: return all profiles (optionally filtered by namespace).
	all := h.store.List()
	// Filter by namespace first, then sort the raw models using the same
	// comparator as the profile store (priority → creationTimestamp → name → namespace) so
	// the listed order matches the real evaluation order.
	var filtered []*securityprofile.Profile
	for _, p := range all {
		if namespace != "" && p.Meta.Namespace != namespace {
			continue
		}
		filtered = append(filtered, p)
	}
	securityprofile.SortProfiles(filtered)
	views := make([]ProfileView, 0, len(filtered))
	for _, p := range filtered {
		v, err := toView(p, full)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		views = append(views, v)
	}

	writeJSON(w, http.StatusOK, ListResponse{Count: len(views), Profiles: views})
}

// handleMatch finds profiles matching the given workload identity and labels and
// writes the response. Called by both GET (after CSV label parsing) and POST
// (with pre-parsed map). A non-empty workloadName also resolves the same-name
// Sandbox profile, which is looked up by exact identity.
func (h *handler) handleMatch(
	w http.ResponseWriter,
	r *http.Request,
	workloadName, namespace string,
	labels map[string]string,
	full bool,
) {
	if namespace == "" {
		writeError(w, http.StatusBadRequest, "namespace is required when workload_labels or workload_name is provided")
		return
	}
	matched := h.store.ProfilesFor(
		subject.Subject{Workload: subject.Workload{Name: workloadName, Namespace: namespace, Labels: labels}},
	)
	views := make([]ProfileView, 0, len(matched))
	for _, p := range matched {
		v, err := toView(p, full)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		views = append(views, v)
	}
	writeJSON(w, http.StatusOK, ListResponse{Count: len(views), Profiles: views})
}
