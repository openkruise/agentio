// Copyright Istio Authors
// Modifications Copyright 2026 The Kruise Authors
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

package krt_test

import (
	"strconv"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"istio.io/istio/pkg/slices"
	"istio.io/istio/pkg/test/util/assert"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube"
)

func TestLookupFiltered(t *testing.T) {
	opts := testOptions(t)
	objects := []Named{{Namespace: "ns", Name: "a"}, {Namespace: "ns", Name: "b"}, {Namespace: "other", Name: "c"}}
	static := krt.NewStaticCollection[Named](nil, objects, opts.WithName("static")...)
	left := krt.NewStaticCollection[Named](nil, objects[:1], opts.WithName("left")...)
	right := krt.NewStaticCollection[Named](nil, objects[1:], opts.WithName("right")...)
	collections := map[string]krt.Collection[Named]{
		"static": static,
		"derived": krt.NewCollection(static, func(_ krt.HandlerContext, n Named) *Named {
			return &n
		}, opts.WithName("derived")...),
		"joined": krt.JoinCollection([]krt.Collection[Named]{left, right}, opts.WithName("joined")...),
		"merged": krt.JoinWithMergeCollection([]krt.Collection[Named]{left, right}, func(ns []Named) *Named {
			return &ns[0]
		}, opts.WithName("merged")...),
	}
	for name, col := range collections {
		t.Run(name, func(t *testing.T) {
			col.WaitUntilSynced(opts.Stop())
			checkLookupFiltered(t, col, func(n Named) string { return n.Namespace })
		})
	}
	t.Run("mapped", func(t *testing.T) {
		col := krt.MapCollection(
			static,
			func(n Named) SimplePod { return SimplePod{Named: n} },
			opts.WithName("mapped")...)
		col.WaitUntilSynced(opts.Stop())
		checkLookupFiltered(t, col, func(p SimplePod) string { return p.Namespace })
	})
	t.Run("informer", func(t *testing.T) {
		client := kube.NewFakeClient(
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "a"}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "b"}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "other", Name: "c"}},
		)
		col := krt.NewInformer[*corev1.ConfigMap](client, opts.WithName("informer")...)
		client.Run(opts.Stop())
		col.WaitUntilSynced(opts.Stop())
		checkLookupFiltered(t, col, func(n *corev1.ConfigMap) string { return n.Namespace })
	})
}

func checkLookupFiltered[T any](t *testing.T, col krt.Collection[T], namespace func(T) string) {
	t.Helper()
	idx := krt.NewIndex(col, "namespace", func(n T) []string { return []string{namespace(n)} })
	keys := func(objects []T) []string {
		return slices.Sort(slices.Map(objects, krt.GetKey[T]))
	}
	assert.Equal(t, keys(idx.LookupFiltered("ns", nil)), []string{"ns/a", "ns/b"})
	assert.Equal(t, keys(idx.LookupFiltered("ns", func(T) bool { return true })), []string{"ns/a", "ns/b"})
	assert.Equal(t, len(idx.LookupFiltered("ns", func(T) bool { return false })), 0)
	assert.Equal(t, len(idx.LookupFiltered("missing", func(T) bool {
		t.Fatal("filter called for missing key")
		return true
	})), 0)
	var calls int
	filter := func(obj T) bool {
		calls++
		assert.Equal(t, namespace(obj), "ns")
		return krt.GetKey(obj) == "ns/b"
	}
	assert.Equal(t, keys(idx.LookupFiltered("ns", filter)), []string{"ns/b"})
	assert.Equal(t, calls, 2)
	calls = 0
	assert.Equal(t, keys(krt.FetchOrList(nil, col, krt.FilterIndex(idx, "ns"), krt.FilterGeneric(func(obj any) bool {
		return filter(obj.(T))
	}))), []string{"ns/b"})
	assert.Equal(t, calls, 2)
	// Filtering must not change the index's stored results.
	assert.Equal(t, keys(idx.Lookup("ns")), []string{"ns/a", "ns/b"})
}

func TestIndexFetchFilteredUpdates(t *testing.T) {
	opts := testOptions(t)
	pod := SimplePod{Named: Named{Namespace: "ns", Name: "a"}, IP: "unmatched"}
	pods := krt.NewMutableCollection[SimplePod](nil, []SimplePod{pod}, opts.WithName("pods")...)
	idx := krt.NewIndex(pods.AsCollection(), "namespace", func(p SimplePod) []string { return []string{p.Namespace} })
	result := krt.NewSingleton(func(ctx krt.HandlerContext) *string {
		matches := idx.Fetch(
			ctx,
			"ns",
			krt.FilterGeneric(func(obj any) bool { return obj.(SimplePod).IP == "matched" }),
		)
		return new(strconv.Itoa(len(matches)))
	}, opts.WithName("result")...)
	result.AsCollection().WaitUntilSynced(opts.Stop())
	assert.Equal(t, result.Get(), new("0"))
	pod.IP = "matched"
	pods.UpdateObject(pod)
	assert.EventuallyEqual(t, result.Get, new("1"))
	pod.IP = "unmatched"
	pods.UpdateObject(pod)
	assert.EventuallyEqual(t, result.Get, new("0"))
}
