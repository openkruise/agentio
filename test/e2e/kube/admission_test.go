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

package kube

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

func TestAdmitPodPreservesMutationWarningsAndRejection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/namespaces/test/pods" || r.URL.Query().Get("dryRun") != "All" {
			t.Errorf("unexpected admission request: %s %s", r.Method, r.URL)
			http.Error(w, "wrong request", http.StatusBadRequest)
			return
		}
		var pod corev1.Pod
		if err := json.NewDecoder(r.Body).Decode(&pod); err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Warning", `299 admission "CA path conflict"`)
		if pod.Name == "denied" {
			w.WriteHeader(http.StatusForbidden)
			if err := json.NewEncoder(w).Encode(metav1.Status{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: "Failure", Reason: metav1.StatusReasonForbidden, Code: 403, Message: "invalid client trust mount"}); err != nil {
				t.Error(err)
			}
			return
		}
		pod.Annotations = map[string]string{"admitted": "true"}
		w.WriteHeader(http.StatusCreated)
		if err := json.NewEncoder(w).Encode(pod); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	original := &admissionWarnings{}
	config := &rest.Config{Host: server.URL, ContentConfig: rest.ContentConfig{ContentType: "application/json", AcceptContentTypes: "application/json"}, WarningHandler: original}
	client := &Client{restConfig: config}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "accepted", Namespace: "test"}}
	admitted, warnings, err := client.AdmitPod(context.Background(), pod)
	if err != nil {
		t.Fatal(err)
	}
	if admitted.Annotations["admitted"] != "true" || !reflect.DeepEqual(warnings, []string{"CA path conflict"}) {
		t.Fatalf("lost admission result: %+v %v", admitted, warnings)
	}
	if len(pod.Annotations) != 0 || len(original.messages) != 0 || config.WarningHandler != original {
		t.Fatal("admission changed the caller's Pod or warning handler")
	}
	pod.Name = "denied"
	_, warnings, err = client.AdmitPod(context.Background(), pod)
	if !apierrors.IsForbidden(err) || !reflect.DeepEqual(warnings, []string{"CA path conflict"}) {
		t.Fatalf("lost denial or warning: %v %v", err, warnings)
	}
}
