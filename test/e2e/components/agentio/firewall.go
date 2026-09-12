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

package agentio

import (
	"context"
	"errors"
	"fmt"
	"slices"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/openkruise/agentio/test/e2e"
)

// VerifyFirewallBackend proves that the selected profile received the
// requested backend instead of relying only on the Helm input value.
func VerifyFirewallBackend(ctx context.Context, environment *e2e.Environment, config Config) error {
	if environment == nil || environment.Cluster == nil || environment.Cluster.Kube == nil {
		return errors.New("firewall backend verification requires a typed Kubernetes client")
	}
	return verifyFirewallBackend(ctx, environment.Cluster.Kube, config)
}

func verifyFirewallBackend(ctx context.Context, client kubernetes.Interface, config Config) error {
	switch config.Profile {
	case ProfileSidecar:
		namespaces, err := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{
			LabelSelector: DataplaneModeLabel + "=" + ProfileSidecar,
		})
		if err != nil {
			return fmt.Errorf("list sidecar dataplane namespaces: %w", err)
		}
		verified := 0
		for _, namespace := range namespaces.Items {
			pods, err := client.CoreV1().Pods(namespace.Name).List(ctx, metav1.ListOptions{})
			if err != nil {
				return fmt.Errorf("list sidecar dataplane Pods in namespace %q: %w", namespace.Name, err)
			}
			count, err := verifyPodFirewallBackend(pods.Items, "agentio-proxy", config.FirewallBackend)
			if err != nil {
				return err
			}
			verified += count
		}
		if verified == 0 {
			return errors.New("no agentio-proxy container found in a sidecar dataplane namespace")
		}
		return nil
	case ProfileAmbient:
		pods, err := client.CoreV1().Pods(config.Namespace).List(ctx, metav1.ListOptions{
			LabelSelector: "app.kubernetes.io/name=ztunnel",
		})
		if err != nil {
			return fmt.Errorf("list ambient ztunnel Pods: %w", err)
		}
		verified, err := verifyPodFirewallBackend(pods.Items, "ztunnel", config.FirewallBackend)
		if err != nil {
			return err
		}
		if verified == 0 {
			return errors.New("no ztunnel container found in the ambient dataplane")
		}
		return nil
	default:
		return fmt.Errorf("unsupported Agentio dataplane profile %q", config.Profile)
	}
}

func verifyPodFirewallBackend(pods []corev1.Pod, containerName, want string) (int, error) {
	verified := 0
	for _, pod := range pods {
		for _, container := range slices.Concat(pod.Spec.Containers, pod.Spec.InitContainers) {
			if container.Name != containerName {
				continue
			}
			backend, found := containerEnvironment(container, "FIREWALL_BACKEND")
			if !found {
				return 0, fmt.Errorf("Pod %s/%s container %s has no FIREWALL_BACKEND", pod.Namespace, pod.Name, containerName)
			}
			if backend != want {
				return 0, fmt.Errorf("Pod %s/%s container %s has FIREWALL_BACKEND=%q, want %q",
					pod.Namespace, pod.Name, containerName, backend, want)
			}
			verified++
		}
	}
	return verified, nil
}

func containerEnvironment(container corev1.Container, name string) (string, bool) {
	for _, variable := range container.Env {
		if variable.Name == name {
			return variable.Value, true
		}
	}
	return "", false
}
