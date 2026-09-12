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
	"errors"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// AdmitPod runs a server-side dry-run, returning the mutated Pod and admission
// warnings without persisting a resource or changing the client's warning handler.
func (c *Client) AdmitPod(ctx context.Context, pod *corev1.Pod) (*corev1.Pod, []string, error) {
	if c == nil || c.restConfig == nil {
		return nil, nil, errors.New("Pod admission requires a REST configuration")
	}
	config := rest.CopyConfig(c.restConfig)
	warnings := &admissionWarnings{}
	config.WarningHandler = warnings
	config.WarningHandlerWithContext = nil
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, nil, err
	}
	admitted, err := client.CoreV1().Pods(pod.Namespace).Create(ctx, pod, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
	return admitted, warnings.messages, err
}

type admissionWarnings struct{ messages []string }

func (w *admissionWarnings) HandleWarningHeader(code int, _ string, message string) {
	if code == 299 {
		w.messages = append(w.messages, message)
	}
}
