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

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/httpstream"
	"k8s.io/apimachinery/pkg/util/httpstream/spdy"
	remoteconstants "k8s.io/apimachinery/pkg/util/remotecommand"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	clienttesting "k8s.io/client-go/testing"
)

func TestGeneratedTLS(t *testing.T) {
	data, err := tlsData(2)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(data["server.pem"], data["key.pem"])
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(data["ca.pem"]) {
		t.Fatal("invalid CA")
	}
	for _, host := range []string{"ads", "ads-0", "ads-1"} {
		if _, err = cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: host}); err != nil {
			t.Fatal(err)
		}
	}
	if cert.IsCA || len(data["token"]) != 48 {
		t.Fatal("invalid leaf or authentication token")
	}
}

func TestExistingNamespaceIsUntouched(t *testing.T) {
	client := fake.NewClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "existing", UID: "original"}})
	r := &runner{cfg: config{Namespace: "existing"}, kube: client}
	if err := r.create(t.Context()); !apierrors.IsAlreadyExists(err) {
		t.Fatalf("expected refusal, got %v", err)
	}
	if err := r.deleteNamespace(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(client.Actions()) != 1 || r.namespaceUID != "" {
		t.Fatalf("modified existing namespace: %v", client.Actions())
	}
}

func TestCanceledRunCleansOwnedNamespace(t *testing.T) {
	client := fake.NewClientset()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	client.PrependReactor("create", "namespaces", func(action clienttesting.Action) (bool, runtime.Object, error) {
		ns := action.(clienttesting.CreateAction).GetObject().(*corev1.Namespace)
		ns.UID = "owned"
		return false, nil, nil
	})
	client.PrependReactor("create", "secrets", func(clienttesting.Action) (bool, runtime.Object, error) {
		cancel()
		return true, nil, context.Canceled
	})
	client.PrependReactor("delete", "namespaces", func(action clienttesting.Action) (bool, runtime.Object, error) {
		options := action.(clienttesting.DeleteAction).GetDeleteOptions()
		if options.Preconditions == nil || options.Preconditions.UID == nil || *options.Preconditions.UID != "owned" {
			t.Error("cleanup lost namespace ownership precondition")
		}
		return false, nil, nil
	})
	r := &runner{cfg: config{Namespace: "test", Output: t.TempDir(), ControlPlanes: 2}, kube: client}
	if err := r.execute(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("lost original error: %v", err)
	}
	if _, err := client.CoreV1().
		Namespaces().
		Get(t.Context(), "test", metav1.GetOptions{}); !apierrors.IsNotFound(
		err,
	) {
		t.Fatalf("namespace remains after cancellation: %v", err)
	}
}

func TestExecStreamsAndExitStatus(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "failure"}[failed], func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.Method != "POST" || req.URL.Path != "/api/v1/namespaces/test/pods/porter-0/exec" ||
					req.URL.Query().Get("container") != "load" ||
					!reflect.DeepEqual(req.URL.Query()["command"], []string{"/bench", "client", "--requests=50000"}) {
					t.Errorf("unexpected exec request: %s %s", req.Method, req.URL)
				}
				if _, err := httpstream.Handshake(req, w, []string{remoteconstants.StreamProtocolV4Name}); err != nil {
					t.Error(err)
					return
				}
				type incoming struct {
					stream  httpstream.Stream
					replied <-chan struct{}
				}
				streams := make(chan incoming, 3)
				conn := spdy.NewResponseUpgrader().
					UpgradeResponse(w, req, func(s httpstream.Stream, reply <-chan struct{}) error {
						streams <- incoming{stream: s, replied: reply}
						return nil
					})
				if conn == nil {
					return
				}
				defer func() {
					if err := conn.Close(); err != nil {
						t.Error(err)
					}
				}()
				byType := map[string]httpstream.Stream{}
				for range 3 {
					select {
					case stream := <-streams:
						<-stream.replied
						byType[stream.stream.Headers().Get(corev1.StreamType)] = stream.stream
					case <-req.Context().Done():
						return
					}
				}
				if _, err := io.WriteString(byType[corev1.StreamTypeStdout], "result\n"); err != nil {
					t.Error(err)
				}
				if _, err := io.WriteString(byType[corev1.StreamTypeStderr], "LOAD_STARTED\n"); err != nil {
					t.Error(err)
				}
				status := metav1.Status{Status: metav1.StatusSuccess}
				if failed {
					status = metav1.Status{
						Status: metav1.StatusFailure,
						Reason: remoteconstants.NonZeroExitCodeReason,
						Details: &metav1.StatusDetails{
							Causes: []metav1.StatusCause{{Type: remoteconstants.ExitCodeCauseType, Message: "7"}},
						},
					}
				}
				if err := json.NewEncoder(byType[corev1.StreamTypeError]).Encode(status); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			cfg := &rest.Config{Host: server.URL}
			client, err := kubernetes.NewForConfig(cfg)
			if err != nil {
				t.Fatal(err)
			}
			r := &runner{cfg: config{Namespace: "test"}, kube: client, rest: cfg}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			var stdout, stderr bytes.Buffer
			err = r.exec(ctx, "porter-0", []string{"/bench", "client", "--requests=50000"}, &stdout, &stderr)
			if (err != nil) != failed || stdout.String() != "result\n" || stderr.String() != "LOAD_STARTED\n" {
				t.Fatalf("stdout=%q stderr=%q error=%v", &stdout, &stderr, err)
			}
		})
	}
}
