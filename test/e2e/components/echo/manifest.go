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

package echo

import (
	"errors"
	"fmt"
	"regexp"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/validation"
)

var immutableImage = regexp.MustCompile(`^[^[:space:]@]+@sha256:[0-9a-f]{64}$`)

func manifests(input Config) ([]*unstructured.Unstructured, error) {
	config := normalizedConfig(input)
	if len(validation.IsDNS1123Label(config.Name)) != 0 || len(validation.IsDNS1123Label(config.Namespace)) != 0 {
		return nil, errors.New("echo name and namespace must be DNS-1123 labels")
	}
	if !immutableImage.MatchString(config.Image) {
		return nil, errors.New("echo image must be an immutable repository@sha256 digest reference")
	}
	if err := validatePorts(config.Ports); err != nil {
		return nil, err
	}
	labels := map[string]any{"app": config.Name}
	for key, value := range config.Labels {
		labels[key] = value
	}
	annotations := make(map[string]any, len(config.PodAnnotations))
	for key, value := range config.PodAnnotations {
		annotations[key] = value
	}
	serviceAccount := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1", "kind": "ServiceAccount",
		"metadata": map[string]any{"name": config.Name, "namespace": config.Namespace, "labels": labels},
	}}
	servicePorts := make([]any, 0, len(config.Ports))
	containerPorts := make([]any, 0, len(config.Ports))
	serverArgs := []any{"--metrics=15014", "--cluster=Kubernetes", "--version=v1"}
	for _, port := range config.Ports {
		transport := "TCP"
		switch port.Protocol {
		case HTTPS:
			// Istio's echo server treats --tls as an attribute of a declared
			// HTTP/GRPC/TCP port, not as a port declaration by itself.
			serverArgs = append(serverArgs, fmt.Sprintf("--port=%d", port.WorkloadPort))
			serverArgs = append(serverArgs, fmt.Sprintf("--tls=%d", port.WorkloadPort))
		case GRPC:
			serverArgs = append(serverArgs, fmt.Sprintf("--grpc=%d", port.WorkloadPort))
		case TCP:
			serverArgs = append(serverArgs, fmt.Sprintf("--tcp=%d", port.WorkloadPort))
			if port.ServerFirst {
				serverArgs = append(serverArgs, fmt.Sprintf("--server-first=%d", port.WorkloadPort))
			}
		case UDP:
			transport = "UDP"
			serverArgs = append(serverArgs, fmt.Sprintf("--udp=%d", port.WorkloadPort))
		default:
			serverArgs = append(serverArgs, fmt.Sprintf("--port=%d", port.WorkloadPort))
		}
		servicePorts = append(servicePorts, map[string]any{
			"name": port.Name, "port": int64(port.ServicePort), "targetPort": int64(port.WorkloadPort), "protocol": transport,
		})
		containerPorts = append(containerPorts, map[string]any{
			"name": port.Name, "containerPort": int64(port.WorkloadPort), "protocol": transport,
		})
	}
	serverArgs = append(serverArgs, "--crt=/cert.crt", "--key=/cert.key", "--ca=/root-cert.pem")
	service := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1", "kind": "Service",
		"metadata": map[string]any{"name": config.Name, "namespace": config.Namespace, "labels": labels},
		"spec":     map[string]any{"selector": map[string]any{"app": config.Name}, "ports": servicePorts},
	}}
	container := map[string]any{
		"name":            "app",
		"image":           config.Image,
		"imagePullPolicy": "IfNotPresent",
		"args":            serverArgs,
		"ports":           containerPorts,
		"readinessProbe":  readinessProbe(config.Ports),
	}
	if len(config.Capabilities) > 0 {
		capabilities := make([]any, len(config.Capabilities))
		for index, capability := range config.Capabilities {
			capabilities[index] = string(capability)
		}
		container["securityContext"] = map[string]any{
			"capabilities": map[string]any{"add": capabilities},
		}
	}
	deployment := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": map[string]any{"name": config.Name, "namespace": config.Namespace, "labels": labels},
		"spec": map[string]any{
			"replicas": int64(config.Replicas),
			"selector": map[string]any{"matchLabels": map[string]any{"app": config.Name}},
			"template": map[string]any{
				"metadata": map[string]any{"labels": labels, "annotations": annotations},
				"spec":     map[string]any{"serviceAccountName": config.Name, "containers": []any{container}},
			},
		},
	}}
	return []*unstructured.Unstructured{serviceAccount, service, deployment}, nil
}

func validatePorts(ports []Port) error {
	if len(ports) == 0 {
		return errors.New("echo requires at least one port")
	}
	names := make(map[string]struct{}, len(ports))
	servicePorts := make(map[int]struct{}, len(ports))
	workloadPorts := make(map[int]struct{}, len(ports))
	for _, port := range ports {
		if len(validation.IsValidPortName(port.Name)) != 0 {
			return fmt.Errorf("invalid port name %q", port.Name)
		}
		if _, found := names[port.Name]; found {
			return fmt.Errorf("duplicate port name %q", port.Name)
		}
		names[port.Name] = struct{}{}
		if port.ServicePort < 1 || port.ServicePort > 65535 {
			return fmt.Errorf("port %q has invalid service port %d", port.Name, port.ServicePort)
		}
		if _, found := servicePorts[port.ServicePort]; found {
			return fmt.Errorf("duplicate service port %d", port.ServicePort)
		}
		servicePorts[port.ServicePort] = struct{}{}
		if port.WorkloadPort < 1 || port.WorkloadPort > 65535 {
			return fmt.Errorf("port %q has invalid workload port %d", port.Name, port.WorkloadPort)
		}
		if _, found := workloadPorts[port.WorkloadPort]; found {
			return fmt.Errorf("duplicate workload port %d", port.WorkloadPort)
		}
		workloadPorts[port.WorkloadPort] = struct{}{}
		switch port.Protocol {
		case HTTP, HTTPS, HTTP2, GRPC, TCP, UDP:
		default:
			return fmt.Errorf("port %q has unsupported protocol %q", port.Name, port.Protocol)
		}
		if port.TLS && port.Protocol != HTTPS {
			return fmt.Errorf("port %q TLS requires HTTPS protocol", port.Name)
		}
		if port.Protocol == HTTPS && !port.TLS {
			return fmt.Errorf("port %q HTTPS requires TLS", port.Name)
		}
	}
	return nil
}

func readinessProbe(ports []Port) map[string]any {
	probe := map[string]any{
		"tcpSocket":           map[string]any{"port": int64(ports[0].WorkloadPort)},
		"initialDelaySeconds": int64(1), "periodSeconds": int64(2), "failureThreshold": int64(10),
	}
	for _, port := range ports {
		if port.Protocol != HTTP && port.Protocol != HTTP2 {
			continue
		}
		delete(probe, "tcpSocket")
		probe["httpGet"] = map[string]any{"path": "/", "port": int64(port.WorkloadPort)}
		break
	}
	return probe
}
