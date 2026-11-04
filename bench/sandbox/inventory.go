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
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
)

var sandboxGVR = schema.GroupVersionResource{Group: "agents.kruise.io", Version: "v1alpha1", Resource: "sandboxes"}

func (r *runner) namespace(i int) string { return fmt.Sprintf("%s-%03d", r.Prefix, i/1000) }

func resourceName(i int) string { return fmt.Sprintf("sandbox-%06d", i) }

func (r *runner) node(i int) string {
	node := i / 100
	if r.VirtualNodeCount > 0 {
		node %= r.VirtualNodeCount
	}
	return fmt.Sprintf("%s-node-%04d", r.Prefix, node)
}

func (r *runner) seed(ctx context.Context) error {
	for i := r.Offset / 1000; i <= (r.Offset+r.Count-1)/1000; i++ {
		name := r.namespace(i * 1000)
		_, err := r.kube.CoreV1().
			Namespaces().
			Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{"bench.agentio.io/run": r.Prefix}}}, metav1.CreateOptions{})
		if err != nil && !apierrors.IsAlreadyExists(err) {
			return err
		}
		_, err = r.kube.CoreV1().
			ServiceAccounts(name).
			Create(ctx, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "sandbox"}}, metav1.CreateOptions{})
		if err != nil && !apierrors.IsAlreadyExists(err) {
			return err
		}
	}
	for i := r.Offset / 100; i <= (r.Offset+r.Count-1)/100; i++ {
		node := &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: r.node(i * 100),
				Labels: map[string]string{
					"bench.agentio.io/run":   r.Prefix,
					"kubernetes.io/hostname": r.node(i * 100),
					"kubernetes.io/os":       "linux",
					"kubernetes.io/arch":     "amd64",
				},
				Annotations: map[string]string{"kwok.x-k8s.io/node": "fake"},
			},
			Spec: corev1.NodeSpec{
				Taints: []corev1.Taint{
					{Key: "kwok.x-k8s.io/node", Value: "fake", Effect: corev1.TaintEffectNoSchedule},
				},
			},
		}
		_, err := r.kube.CoreV1().Nodes().Create(ctx, node, metav1.CreateOptions{})
		if err != nil && !apierrors.IsAlreadyExists(err) {
			return err
		}
	}
	return r.parallel(ctx, r.createPair)
}

func (r *runner) createPair(ctx context.Context, i int) error {
	ns, name := r.namespace(i), resourceName(i)
	sandbox := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "agents.kruise.io/v1alpha1",
			"kind":       "Sandbox",
			"metadata": map[string]any{
				"name":      name,
				"namespace": ns,
				"labels":    map[string]any{"bench.agentio.io/run": r.Prefix, "agents.kruise.io/sandbox-id": name},
			},
			"spec": map[string]any{},
		},
	}
	sb, err := r.dynamic.Resource(sandboxGVR).Namespace(ns).Create(ctx, sandbox, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	controller := true
	labels := map[string]string{
		"bench.agentio.io/run":     r.Prefix,
		"app":                      "sandbox",
		"bench.agentio.io/service": fmt.Sprint(i / 100 % 10),
		"revision":                 fmt.Sprint(r.Revision),
		"tenant":                   fmt.Sprintf("tenant-%03d", i%100),
	}
	for j := range 16 {
		labels[fmt.Sprintf("bench.agentio.io/label-%02d", j)] = fmt.Sprintf("value-%d-%d", i, j)
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Labels:    labels,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "agents.kruise.io/v1alpha1",
					Kind:       "Sandbox",
					Name:       name,
					UID:        sb.GetUID(),
					Controller: &controller,
				},
			},
		},
		Spec: corev1.PodSpec{
			NodeName:           r.node(i),
			ServiceAccountName: "sandbox",
			Containers:         []corev1.Container{{Name: "sandbox", Image: "registry.k8s.io/pause:3.10"}},
			Tolerations: []corev1.Toleration{
				{Key: "kwok.x-k8s.io/node", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
			},
		},
	}
	created, err := r.kube.CoreV1().Pods(ns).Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	patch, err := json.Marshal(
		map[string]any{
			"status": map[string]any{
				"podInfo": map[string]any{"podUID": string(created.UID)},
				"phase":   "Running",
			},
		},
	)
	if err != nil {
		return err
	}
	_, err = r.dynamic.Resource(sandboxGVR).
		Namespace(ns).
		Patch(ctx, name, types.MergePatchType, patch, metav1.PatchOptions{}, "status")
	return err
}

func (r *runner) updateLabels(ctx context.Context, i int) error {
	patch, err := json.Marshal(
		map[string]any{
			"metadata": map[string]any{
				"labels": map[string]string{
					"revision":                 fmt.Sprint(r.Revision),
					"bench.agentio.io/service": fmt.Sprint(i / 100 % 10),
				},
			},
		},
	)
	if err != nil {
		return err
	}
	_, err = r.kube.CoreV1().
		Pods(r.namespace(i)).
		Patch(ctx, resourceName(i), types.MergePatchType, patch, metav1.PatchOptions{})
	return err
}

func (r *runner) deletePair(ctx context.Context, i int) error {
	ns, name := r.namespace(i), resourceName(i)
	grace := int64(0)
	propagation := metav1.DeletePropagationBackground
	if err := r.dynamic.Resource(sandboxGVR).
		Namespace(ns).
		Delete(ctx, name, metav1.DeleteOptions{PropagationPolicy: &propagation}); err != nil {
		return err
	}
	// Pod deletion is explicit as well: the simulator does not run a sandbox runtime.
	if err := r.kube.CoreV1().
		Pods(ns).
		Delete(ctx, name, metav1.DeleteOptions{GracePeriodSeconds: &grace}); err != nil &&
		!apierrors.IsNotFound(err) {
		return err
	}
	return wait.PollUntilContextTimeout(
		ctx,
		20*time.Millisecond,
		30*time.Second,
		true,
		func(ctx context.Context) (bool, error) {
			_, e := r.kube.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
			if e == nil {
				return false, nil
			}
			if !apierrors.IsNotFound(e) {
				return false, e
			}
			_, e = r.dynamic.Resource(sandboxGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
			if e == nil {
				return false, nil
			}
			if apierrors.IsNotFound(e) {
				return true, nil
			}
			return false, e
		},
	)
}
