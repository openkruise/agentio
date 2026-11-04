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

package agentgateway

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/openkruise/agentio/test/e2e"
	"github.com/openkruise/agentio/test/e2e/components/echo"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/retry"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const gatewayName = "egress-gateway"
const Marker = "x-agentio-e2e-gateway"

var gateways = schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gateways"}

func object(namespace, kind, name string, fields map[string]any) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": kind, "metadata": map[string]any{"name": name, "namespace": namespace}}}
	for k, v := range fields {
		u.Object[k] = v
	}
	return u
}

func Gateway(namespace, name string) *unstructured.Unstructured {
	u := object(namespace, "Gateway", name, map[string]any{"spec": map[string]any{
		"gatewayClassName": "agentio-agentgateway",
		"infrastructure":   map[string]any{"parametersRef": map[string]any{"group": "", "kind": "ConfigMap", "name": name + "-config"}},
		"listeners":        []any{map[string]any{"name": "mesh", "protocol": "HBONE", "port": int64(15008)}, map[string]any{"name": "http", "protocol": "HTTP", "port": int64(8080)}},
	}})
	u.SetAPIVersion("gateway.networking.k8s.io/v1")
	return u
}

func NativeConfig(version string, extProc map[string]any) string {
	target := `string(destination.address) + ":" + string(destination.port)`
	policies := map[string]any{"requestHeaderModifier": map[string]any{"set": map[string]any{Marker: "agentgateway"}}, "responseHeaderModifier": map[string]any{"set": map[string]any{Marker: "agentgateway"}}}
	if extProc != nil {
		policies["extProc"] = extProc
	}
	binds := []any{
		map[string]any{"port": 8080, "listeners": []any{map[string]any{"protocol": "HTTP", "routes": []any{map[string]any{"policies": map[string]any{"directResponse": map[string]any{"status": 200, "body": version}}}}}}},
		map[string]any{"port": 15008, "tunnelProtocol": "hboneGateway", "listeners": []any{map[string]any{"protocol": "HBONE"}}},
	}
	listeners := []any{
		map[string]any{"protocol": "HTTP", "routes": []any{map[string]any{"policies": policies, "backends": []any{map[string]any{"dynamic": map[string]any{"target": target}}}}}},
		map[string]any{"protocol": "TLS", "hostname": "*", "tcpRoutes": []any{map[string]any{"backends": []any{map[string]any{"dynamic": map[string]any{"target": target}}}}}},
		map[string]any{"protocol": "TCP", "tcpRoutes": []any{map[string]any{"backends": []any{map[string]any{"dynamic": map[string]any{"target": target}}}}}},
	}
	// Unlike generic CONNECT, v1.7.0's native HBONE gateway requires a bind
	// for each destination port; it does not fall back to an internal wildcard.
	// Cover both Service and directly addressed workload ports of the fixture.
	seen := map[int]bool{8080: true, 15008: true}
	for _, port := range echo.DefaultPorts() {
		if port.Protocol == echo.UDP {
			continue
		}
		for _, destination := range []int{port.ServicePort, port.WorkloadPort} {
			if seen[destination] {
				continue
			}
			seen[destination] = true
			binds = append(binds, map[string]any{"port": destination, "mode": "internal", "protocol": "AUTO", "listeners": listeners})
		}
	}
	data := map[string]any{"config": map[string]any{"adminAddr": "127.0.0.1:15000"}, "binds": binds}
	b, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func Configuration(namespace, name, content string) *unstructured.Unstructured {
	return object(namespace, "ConfigMap", name+"-config", map[string]any{"data": map[string]any{"config.yaml": content}})
}

// Setup provisions the native gateway fixture. The gateway requests its own
// workload certificate from Agentiod using its projected ServiceAccount token.
func Setup(namespace, content string) e2e.SetupFunc {
	return func(ctx context.Context, env *e2e.Environment) (e2e.CleanupFunc, error) {
		scope := kube.NewResourceScope(env.Kube)
		for _, u := range []*unstructured.Unstructured{Configuration(namespace, gatewayName, content), Gateway(namespace, gatewayName)} {
			if _, err := scope.Apply(ctx, u, kube.CreateOnly); err != nil {
				return nil, err
			}
		}
		if err := WaitReady(ctx, env, namespace, gatewayName, content); err != nil {
			return nil, err
		}
		return func(ctx context.Context) error {
			if env.Retaining() {
				return nil
			}
			return scope.DeleteReverse(ctx)
		}, nil
	}
}

func ExtProc(host string, attrs map[string]string) map[string]any {
	p := map[string]any{"host": host, "failureMode": "failClosed", "processingOptions": map[string]any{"requestBodyMode": "none", "responseBodyMode": "none", "responseHeaderMode": "send", "requestTrailerMode": "skip", "responseTrailerMode": "skip", "allowModeOverride": true}}
	if attrs != nil {
		p["requestAttributes"] = attrs
	}
	return p
}
func WaitGateway(ctx context.Context, env *e2e.Environment, namespace, name, accepted, programmed string) error {
	return retry.UntilSuccess(ctx, retry.Policy{Timeout: 2 * time.Minute, Delay: time.Second, Converge: 1}, func() error {
		gw, err := env.Kube.Get(ctx, gateways, namespace, name)
		if err != nil {
			return err
		}
		conditions, _, _ := unstructured.NestedSlice(gw.Object, "status", "conditions")
		found := 0
		for _, c := range conditions {
			v := c.(map[string]any)
			want := ""
			switch v["type"] {
			case "Accepted":
				want = accepted
			case "Programmed":
				want = programmed
			}
			if want != "" && v["status"] == want && v["observedGeneration"] == gw.GetGeneration() {
				found++
			}
		}
		if found != 2 {
			return fmt.Errorf("Gateway %s conditions not converged: %v", name, conditions)
		}
		return nil
	})
}

func WaitReady(ctx context.Context, env *e2e.Environment, namespace, name, content string) error {
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(content)))
	return WaitReadyHash(ctx, env, namespace, name, hash)
}

// WaitReadyHash also supports generated file-watched configurations, whose mode hash is stable.
func WaitReadyHash(ctx context.Context, env *e2e.Environment, namespace, name, hash string) error {
	if err := retry.UntilSuccess(ctx, retry.Policy{Timeout: 2 * time.Minute, Delay: time.Second, Converge: 1}, func() error {
		d, err := env.Cluster.Kube.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if d.Spec.Template.Annotations["gateway.agentio.kruise.io/config-hash"] != hash || d.Status.ObservedGeneration < d.Generation || d.Status.UpdatedReplicas != *d.Spec.Replicas || d.Status.AvailableReplicas != *d.Spec.Replicas || d.Status.Replicas != *d.Spec.Replicas {
			return fmt.Errorf("%s rollout has not converged to %s: %+v", name, hash, d.Status)
		}
		return nil
	}); err != nil {
		return err
	}
	return WaitGateway(ctx, env, namespace, name, "True", "True")
}
