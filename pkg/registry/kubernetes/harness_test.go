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

package kubernetes

import (
	"sort"
	"sync"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	podsource "github.com/openkruise/agentio/pkg/registry/kubernetes/pod"
)

func egressPod(namespace, name, gatewayName, address string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			Labels:    map[string]string{podsource.LabelGatewayName: gatewayName},
		},
		Spec:   corev1.PodSpec{ServiceAccountName: gatewayName, NodeName: "node-a"},
		Status: corev1.PodStatus{PodIP: address, PodIPs: []corev1.PodIP{{IP: address}}},
	}
}

type gatewayRecorder struct {
	mu      sync.Mutex
	changed sets.Set[string]
}

func newGatewayRecorder(gateways krt.EventStream[model.Gateway]) *gatewayRecorder {
	recorder := &gatewayRecorder{changed: sets.New[string]()}
	gateways.RegisterBatch(func(events []krt.Event[model.Gateway]) {
		recorder.mu.Lock()
		defer recorder.mu.Unlock()
		for _, event := range events {
			recorder.changed.Insert(event.Latest().ResourceName())
		}
	}, false)
	return recorder
}

func (r *gatewayRecorder) names() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]string, 0, len(r.changed))
	for name := range r.changed {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

func (r *gatewayRecorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.changed = sets.New[string]()
}

func gatewayNames(gateways []model.Gateway) []string {
	result := make([]string, 0, len(gateways))
	for _, gateway := range gateways {
		result = append(result, gateway.ResourceName())
	}
	return result
}
