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

// This file rewrites Kubernetes app probes to route through the proxy status
// port. The required status constants are defined locally.

package inject

import (
	"encoding/json"
	"fmt"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"istio.io/istio/pkg/slices"
)

// KubeAppProberEnvName identifies the environment variable containing the
// rewritten probe map read by the proxy.
const KubeAppProberEnvName = "ISTIO_KUBE_APP_PROBERS"

// formatProberURL builds the well-known per-container proxy paths.
func formatProberURL(container string) (string, string, string, string, string) {
	return fmt.Sprintf("/app-health/%v/readyz", container),
		fmt.Sprintf("/app-health/%v/livez", container),
		fmt.Sprintf("/app-health/%v/startupz", container),
		fmt.Sprintf("/app-lifecycle/%v/prestopz", container),
		fmt.Sprintf("/app-lifecycle/%v/poststartz", container)
}

// ShouldRewriteAppHTTPProbers returns if we should rewrite apps' probers config.
func ShouldRewriteAppHTTPProbers(annotations map[string]string, specSetting bool) bool {
	if annotations != nil {
		if value, ok := annotations[rewriteAppProbersAnnotation]; ok {
			if isSetInAnnotation, err := strconv.ParseBool(value); err == nil {
				return isSetInAnnotation
			}
		}
	}
	return specSetting
}

// FindSidecar returns the preferred Agentio proxy or its legacy Istio-named alias.
func FindSidecar(pod *corev1.Pod) *corev1.Container {
	return FindContainerFromPod(proxyContainerName(pod.Spec), pod)
}

// FindContainerFromPod returns the pointer to the first container whose name matches in init containers or regular containers
func FindContainerFromPod(name string, pod *corev1.Pod) *corev1.Container {
	if c := FindContainer(name, pod.Spec.Containers); c != nil {
		return c
	}
	return FindContainer(name, pod.Spec.InitContainers)
}

// FindContainer returns the pointer to the first container whose name matches.
func FindContainer(name string, containers []corev1.Container) *corev1.Container {
	for i := range containers {
		if containers[i].Name == name {
			return &containers[i]
		}
	}
	return nil
}

// convertAppProber returns an overwritten `Probe` for the sidecar probe handler to serve.
func convertAppProber(probe *corev1.Probe, newURL string, statusPort int) *corev1.Probe {
	if probe == nil {
		return nil
	}
	if probe.HTTPGet != nil {
		return convertAppProberHTTPGet(probe, newURL, statusPort)
	} else if probe.TCPSocket != nil {
		return convertAppProberTCPSocket(probe, newURL, statusPort)
	} else if probe.GRPC != nil {
		return convertAppProberGRPC(probe, newURL, statusPort)
	}

	return nil
}

// rewriteHTTPGetAction rewrites a HTTPGet action with given URL and port.
// Also rewrites the scheme to HTTP if the scheme is HTTPS
// as the sidecar probe handler uses HTTPS to request the application endpoint.
func rewriteHTTPGetAction(action *corev1.HTTPGetAction, url string, port int) {
	action.Port = intstr.FromInt32(int32(port))
	action.Path = url
	// Kubelet -> HTTP -> Sidecar probe handler -> HTTPS -> Application
	if action.Scheme == corev1.URISchemeHTTPS {
		action.Scheme = corev1.URISchemeHTTP
	}
}

// convertAppLifecycleHandler returns an overwritten `LifecycleHandler` for the sidecar probe handler to serve.
func convertAppLifecycleHandler(lifecycleHandler *corev1.LifecycleHandler, newURL string, statusPort int) *corev1.LifecycleHandler {
	if lifecycleHandler == nil {
		return nil
	}
	if lifecycleHandler.HTTPGet != nil {
		return convertAppLifecycleHandlerHTTPGet(lifecycleHandler, newURL, statusPort)
	}
	if lifecycleHandler.TCPSocket != nil {
		return convertAppLifecycleHandlerTCPSocket(lifecycleHandler, newURL, statusPort)
	}
	return nil
}

// convertAppLifecycleHandlerHTTPGet returns an overwritten `LifecycleHandler` with HTTPGet for the sidecar probe handler to serve.
func convertAppLifecycleHandlerHTTPGet(lifecycleHandler *corev1.LifecycleHandler, newURL string, statusPort int) *corev1.LifecycleHandler {
	lh := lifecycleHandler.DeepCopy()
	rewriteHTTPGetAction(lh.HTTPGet, newURL, statusPort)
	return lh
}

// convertAppLifecycleHandlerTCPSocket returns an overwritten `LifecycleHandler` with TCPSocket for the sidecar probe handler to serve.
func convertAppLifecycleHandlerTCPSocket(lifecycleHandler *corev1.LifecycleHandler, newURL string, statusPort int) *corev1.LifecycleHandler {
	lh := lifecycleHandler.DeepCopy()
	// the sidecar intercepts all tcp connections, so we change it to a HTTP probe and the sidecar will check tcp
	lh.HTTPGet = &corev1.HTTPGetAction{}
	rewriteHTTPGetAction(lh.HTTPGet, newURL, statusPort)
	lh.TCPSocket = nil
	return lh
}

// convertAppProberHTTPGet returns an overwritten `Probe` (HttpGet) for the sidecar probe handler to serve.
func convertAppProberHTTPGet(probe *corev1.Probe, newURL string, statusPort int) *corev1.Probe {
	p := probe.DeepCopy()
	rewriteHTTPGetAction(p.HTTPGet, newURL, statusPort)
	return p
}

// convertAppProberTCPSocket returns an overwritten `Probe` (TcpSocket) for the sidecar probe handler to serve.
func convertAppProberTCPSocket(probe *corev1.Probe, newURL string, statusPort int) *corev1.Probe {
	p := probe.DeepCopy()
	// the sidecar intercepts all tcp connections, so we change it to a HTTP probe and the sidecar will check tcp
	p.HTTPGet = &corev1.HTTPGetAction{}
	rewriteHTTPGetAction(p.HTTPGet, newURL, statusPort)
	p.TCPSocket = nil
	return p
}

// convertAppProberGRPC returns an overwritten `Probe` (gRPC) for the sidecar probe handler to serve.
func convertAppProberGRPC(probe *corev1.Probe, newURL string, statusPort int) *corev1.Probe {
	p := probe.DeepCopy()
	// the sidecar intercepts all gRPC connections, so we change it to a HTTP probe and the sidecar will check gRPC
	p.HTTPGet = &corev1.HTTPGetAction{}
	rewriteHTTPGetAction(p.HTTPGet, newURL, statusPort)
	// For gRPC prober, we change to HTTP,
	// and the sidecar probe handler uses gRPC to request the application endpoint.
	// Kubelet -> HTTP -> Sidecar probe handler -> gRPC -> Application
	p.GRPC = nil
	return p
}

type KubeAppProbers map[string]*Prober

// Prober represents a single container prober
type Prober struct {
	HTTPGet        *corev1.HTTPGetAction   `json:"httpGet,omitempty"`
	TCPSocket      *corev1.TCPSocketAction `json:"tcpSocket,omitempty"`
	GRPC           *corev1.GRPCAction      `json:"grpc,omitempty"`
	TimeoutSeconds int32                   `json:"timeoutSeconds,omitempty"`
}

// DumpAppProbers returns a json encoded string as `KubeAppProbers`.
// Also update the probers so that all usages of named port will be resolved to integer.
func DumpAppProbers(pod *corev1.Pod, targetPort int32) string {
	out := KubeAppProbers{}
	updateNamedPort := func(p *Prober, portMap map[string]int32) *Prober {
		if p == nil {
			return nil
		}
		if p.GRPC != nil {
			// don't need to update for gRPC probe port as it only supports integer
			return p
		}
		if p.HTTPGet == nil && p.TCPSocket == nil {
			return nil
		}

		var probePort *intstr.IntOrString
		if p.HTTPGet != nil {
			probePort = &p.HTTPGet.Port
		} else {
			probePort = &p.TCPSocket.Port
		}

		if probePort.Type == intstr.String {
			port, exists := portMap[probePort.StrVal]
			if !exists {
				return nil
			}
			*probePort = intstr.FromInt32(port)
		} else if probePort.IntVal == targetPort {
			// Already is rewritten
			return nil
		}
		return p
	}
	for _, c := range allContainers(pod) {
		if isProxyContainerName(c.Name) {
			continue
		}
		readyz, livez, startupz, prestopz, poststartz := formatProberURL(c.Name)
		portMap := map[string]int32{}
		for _, p := range c.Ports {
			if p.Name != "" {
				portMap[p.Name] = p.ContainerPort
			}
		}
		if h := updateNamedPort(kubeProbeToInternalProber(c.ReadinessProbe), portMap); h != nil {
			out[readyz] = h
		}
		if h := updateNamedPort(kubeProbeToInternalProber(c.LivenessProbe), portMap); h != nil {
			out[livez] = h
		}
		if h := updateNamedPort(kubeProbeToInternalProber(c.StartupProbe), portMap); h != nil {
			out[startupz] = h
		}
		if c.Lifecycle != nil {
			if h := updateNamedPort(kubeLifecycleHandlerToInternalProber(c.Lifecycle.PreStop), portMap); h != nil {
				out[prestopz] = h
			}
			if h := updateNamedPort(kubeLifecycleHandlerToInternalProber(c.Lifecycle.PostStart), portMap); h != nil {
				out[poststartz] = h
			}
		}
	}
	// prevent generate '{}'
	if len(out) == 0 {
		return ""
	}
	b, err := json.Marshal(out)
	if err != nil {
		log.Error("serialize app prober configuration", "error", err)
		return ""
	}
	return string(b)
}

func allContainers(pod *corev1.Pod) []corev1.Container {
	return append(slices.Clone(pod.Spec.InitContainers), pod.Spec.Containers...)
}

// patchRewriteProbe generates the patch for webhook.
func patchRewriteProbe(annotations map[string]string, pod *corev1.Pod, defaultPort int32) {
	statusPort := int(defaultPort)
	if v, f := annotations[statusPortAnnotation]; f {
		p, err := strconv.Atoi(v)
		if err != nil {
			log.Error("invalid annotation", "annotation", statusPortAnnotation,
				"value", v, "error", err)
		}
		statusPort = p
	}
	for i, c := range pod.Spec.Containers {
		// Skip sidecar container.
		if isProxyContainerName(c.Name) {
			continue
		}
		convertProbe(&c, statusPort)
		pod.Spec.Containers[i] = c
	}
	for i, c := range pod.Spec.InitContainers {
		// Skip sidecar container.
		if isProxyContainerName(c.Name) {
			continue
		}
		convertProbe(&c, statusPort)
		pod.Spec.InitContainers[i] = c
	}
}

func convertProbe(c *corev1.Container, statusPort int) {
	readyz, livez, startupz, prestopz, poststartz := formatProberURL(c.Name)
	if probePatch := convertAppProber(c.ReadinessProbe, readyz, statusPort); probePatch != nil {
		c.ReadinessProbe = probePatch
	}
	if probePatch := convertAppProber(c.LivenessProbe, livez, statusPort); probePatch != nil {
		c.LivenessProbe = probePatch
	}
	if probePatch := convertAppProber(c.StartupProbe, startupz, statusPort); probePatch != nil {
		c.StartupProbe = probePatch
	}
	if c.Lifecycle != nil {
		if lifecycleHandlerPatch := convertAppLifecycleHandler(c.Lifecycle.PreStop, prestopz, statusPort); lifecycleHandlerPatch != nil {
			c.Lifecycle.PreStop = lifecycleHandlerPatch
		}
		if lifecycleHandlerPatch := convertAppLifecycleHandler(c.Lifecycle.PostStart, poststartz, statusPort); lifecycleHandlerPatch != nil {
			c.Lifecycle.PostStart = lifecycleHandlerPatch
		}
	}
}

// kubeProbeToInternalProber converts a Kubernetes Probe to the sidecar probe configuration
func kubeProbeToInternalProber(probe *corev1.Probe) *Prober {
	if probe == nil {
		return nil
	}

	if probe.HTTPGet != nil {
		return &Prober{
			HTTPGet:        probe.HTTPGet,
			TimeoutSeconds: probe.TimeoutSeconds,
		}
	}

	if probe.TCPSocket != nil {
		return &Prober{
			TCPSocket:      probe.TCPSocket,
			TimeoutSeconds: probe.TimeoutSeconds,
		}
	}

	if probe.GRPC != nil {
		return &Prober{
			GRPC:           probe.GRPC,
			TimeoutSeconds: probe.TimeoutSeconds,
		}
	}

	return nil
}

// kubeLifecycleHandlerToInternalProber converts a Kubernetes LifecycleHandler to the sidecar probe configuration
func kubeLifecycleHandlerToInternalProber(lifecycelHandler *corev1.LifecycleHandler) *Prober {
	if lifecycelHandler == nil {
		return nil
	}
	if lifecycelHandler.HTTPGet != nil {
		return &Prober{
			HTTPGet: lifecycelHandler.HTTPGet,
		}
	}
	if lifecycelHandler.TCPSocket != nil {
		return &Prober{
			TCPSocket: lifecycelHandler.TCPSocket,
		}
	}

	return nil
}
