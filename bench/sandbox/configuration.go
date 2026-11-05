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
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func (r *runner) configure(ctx context.Context) error {
	for n := 0; n < (r.Count+999)/1000; n++ {
		for group := range 10 {
			service := &corev1.Service{
				TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Service"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("sandbox-group-%d", group),
					Namespace: r.namespace(n * 1000),
					Labels:    map[string]string{"bench.agentio.io/run": r.Prefix},
				},
				Spec: corev1.ServiceSpec{
					Selector: map[string]string{
						"bench.agentio.io/run":     r.Prefix,
						"bench.agentio.io/service": fmt.Sprint(group),
					},
					Ports: []corev1.ServicePort{{Name: "http", Port: 80, TargetPort: intstr.FromInt32(8080)}},
				},
			}
			data, err := json.Marshal(service)
			if err != nil {
				return err
			}
			if _, err := r.kube.CoreV1().
				Services(service.Namespace).
				Patch(ctx, service.Name, types.ApplyPatchType, data, metav1.PatchOptions{FieldManager: "sandbox-scale-bench"}); err != nil {
				return err
			}
		}
	}
	return r.trafficPolicy(ctx)
}

func (r *runner) trafficPolicy(ctx context.Context) error {
	object := map[string]any{
		"apiVersion": "agents.kruise.io/v1alpha1",
		"kind":       "GlobalTrafficPolicy",
		"metadata":   map[string]any{"name": r.Prefix + "-traffic"},
		"spec": map[string]any{
			"priority": 10,
			"selector": map[string]any{"matchLabels": map[string]string{"bench.agentio.io/run": r.Prefix}},
			"egress": map[string]any{
				"rules": []any{
					map[string]any{
						"action": "reject",
						"to":     []any{map[string]any{"cidr": "192.0.2.0/24"}},
						"ports":  []any{map[string]any{"protocol": "TCP", "port": 10000 + r.Revision}},
					},
					map[string]any{
						"action": "allow",
						"to":     []any{map[string]any{"cidr": "0.0.0.0/0"}, map[string]any{"cidr": "::/0"}},
					},
				},
			},
		},
	}
	data, err := json.Marshal(object)
	if err != nil {
		return err
	}
	_, err = r.dynamic.Resource(schema.GroupVersionResource{Group: "agents.kruise.io", Version: "v1alpha1", Resource: "globaltrafficpolicies"}).
		Patch(ctx, r.Prefix+"-traffic", types.ApplyPatchType, data, metav1.PatchOptions{FieldManager: "sandbox-scale-bench", FieldValidation: "Strict"})
	return err
}
