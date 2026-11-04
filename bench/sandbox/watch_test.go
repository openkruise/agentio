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
	"context"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestWatchReconnectReusesPodAndTokenUntilRenewal(t *testing.T) {
	kube := fake.NewClientset(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name:      "sandbox-000000",
		Namespace: "sandbox-scale-000",
		UID:       "pod-uid",
	}})
	tokens := 0
	kube.PrependReactor("create", "serviceaccounts", func(action ktesting.Action) (bool, runtime.Object, error) {
		if action.GetSubresource() != "token" {
			t.Fatal(action)
		}
		tokens++
		return true, &authenticationv1.TokenRequest{Status: authenticationv1.TokenRequestStatus{
			Token:               "test-token",
			ExpirationTimestamp: metav1.NewTime(time.Now().Add(time.Hour)),
		}}, nil
	})
	r := &runner{kube: kube, options: options{Action: "watch-sidecar", Prefix: "sandbox-scale"}}
	credentials := &watchCredentials{}
	for range 2 {
		// A rejected connection must not mint another projected token.
		if err := r.watchStream(
			context.Background(),
			0,
			x509.NewCertPool(),
			nil,
			credentials,
		); err == nil ||
			!strings.Contains(err.Error(), "target and node.id") {
			t.Fatalf("watchStream = %v", err)
		}
	}
	if tokens != 1 || len(kube.Actions()) != 2 {
		t.Fatalf("reconnect made %d token requests and %d total API calls", tokens, len(kube.Actions()))
	}
	credentials.token.Status.ExpirationTimestamp = metav1.NewTime(time.Now().Add(time.Minute))
	if err := r.watchStream(context.Background(), 0, x509.NewCertPool(), nil, credentials); err == nil {
		t.Fatal("expected missing target")
	}
	if tokens != 2 || len(kube.Actions()) != 3 {
		t.Fatalf("renewal made %d token requests and %d total API calls", tokens, len(kube.Actions()))
	}
}

func TestGrowingInventoryReusesVirtualNodesWithoutMovingOldPods(t *testing.T) {
	r := runner{options: options{Prefix: "scale", VirtualNodeCount: 2000}}
	for i, want := range map[int]string{0: "scale-node-0000", 199999: "scale-node-1999", 200000: "scale-node-0000", 299999: "scale-node-0999"} {
		if got := r.node(i); got != want {
			t.Fatalf("node(%d)=%s want=%s", i, got, want)
		}
	}
}
