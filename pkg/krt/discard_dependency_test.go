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
	"github.com/openkruise/agentio/pkg/krt"
	"istio.io/istio/pkg/test"
	"istio.io/istio/pkg/test/util/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
)

type Static struct{ Value string }

func (s Static) ResourceName() string { return "static" }
func TestCollectionDiscardResultTracksDependencies(t *testing.T) {
	stop := test.NewStop(t)
	opts := testOptions(t)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "pod", Namespace: "ns", Labels: map[string]string{"config": "first"},
	}}
	pods := krt.NewStaticCollection(nil, []*corev1.Pod{pod}, opts.WithName("Pods")...)
	configs := krt.NewStaticCollection[*corev1.ConfigMap](nil, nil, opts.WithName("Configs")...)
	missing := assert.NewTracker[string](t)
	col := krt.NewCollection(pods, func(ctx krt.HandlerContext, p *corev1.Pod) *Static {
		key := p.Namespace + "/" + p.Labels["config"]
		config := krt.FetchOne(ctx, configs, krt.FilterKey(key))
		if config == nil {
			ctx.DiscardResult()
			missing.Record(key)
			return nil
		}
		return &Static{Value: (*config).Data["value"]}
	}, opts.WithName("Resolved")...)
	events := assert.NewTracker[string](t)
	col.Register(TrackerHandler[Static](events))
	assert.Equal(t, col.WaitUntilSynced(stop), true)
	missing.WaitOrdered("ns/first")
	assert.Equal(t, col.GetKey("static"), nil)

	// A missing dependency must wake the first computation without a parent update.
	first := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "first", Namespace: "ns"}, Data: map[string]string{"value": "first"}}
	configs.UpdateObject(first)
	events.WaitOrdered("add/static")
	assert.Equal(t, col.GetKey("static"), &Static{Value: "first"})

	// Switching to a missing dependency must keep the last output, but watch the
	// new key. Only the complete replacement may be published, with no deletion.
	pod = pod.DeepCopy()
	pod.Labels["config"] = "second"
	pods.UpdateObject(pod)
	missing.WaitOrdered("ns/second")
	assert.Equal(t, col.GetKey("static"), &Static{Value: "first"})
	second := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "second", Namespace: "ns"}, Data: map[string]string{"value": "second"}}
	configs.UpdateObject(second)
	events.WaitOrdered("update/static")
	assert.Equal(t, col.GetKey("static"), &Static{Value: "second"})

	second = second.DeepCopy()
	second.Data["value"] = "updated"
	configs.UpdateObject(second)
	events.WaitOrdered("update/static")
	assert.Equal(t, col.GetKey("static"), &Static{Value: "updated"})

	pods.DeleteObject("ns/pod")
	events.WaitOrdered("delete/static")
	assert.Equal(t, col.GetKey("static"), nil)
}
