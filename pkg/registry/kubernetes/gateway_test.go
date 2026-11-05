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
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/openkruise/agentio/internal/testutil"
	"github.com/openkruise/agentio/pkg/model"
)

// Gateways are configured identities, not a projection of currently running Pods.
func TestGatewaysDeriveConfiguredIdentitiesWithoutPods(t *testing.T) {
	ctx := t.Context()
	config := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "agentio-system",
			Name:      "agentio-config",
		},
		Data: map[string]string{"config": `sandboxExtProc:
  service: epe.agentio-system.svc.cluster.local
  port: 9002
egressGateways:
- namespace: demo
  name: egress-a
- namespace: other
  name: egress-b
`},
	}
	r := newTestRegistry(t, ctx, []runtime.Object{config}, nil)

	testutil.Eventually(
		t,
		func() bool { return len(r.Gateways.List()) == 2 },
		"configured gateways derived without Pods",
	)
	for _, key := range []string{"demo/egress-a", "other/egress-b"} {
		gateway := r.Gateways.GetKey(key)
		if gateway == nil {
			t.Fatalf("configured gateway %s missing; have %v", key, gatewayNames(r.Gateways.List()))
		}
		if gateway.Source != model.GatewaySourceAgentioConfig {
			t.Fatalf("gateway %s source state = %+v", key, gateway)
		}
		if gateway.Config == nil || gateway.Config.GetNamespace() != "" || gateway.Config.GetName() != "" {
			t.Fatalf("gateway %s normalized config = %+v", key, gateway.Config)
		}
	}
}

// Gateway projections must own their selected protobuf fragments.
func TestGatewayProjectionDoesNotAliasEffectiveConfiguration(t *testing.T) {
	ctx := t.Context()
	config := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "agentio-system",
			Name:      "agentio-config",
		},
		Data: map[string]string{"config": `sandboxExtProc:
  service: epe.agentio-system.svc.cluster.local
  port: 9002
egressGateways:
- namespace: demo
  name: egress-a
  tlsTermination:
    includeHosts: ["a.example.com"]
- namespace: demo
  name: egress-b
`},
	}
	r := newTestRegistry(t, ctx, []runtime.Object{config}, nil)
	testutil.Eventually(t, func() bool { return len(r.Gateways.List()) == 2 }, "configured gateways")

	a := r.Gateways.GetKey("demo/egress-a")
	b := r.Gateways.GetKey("demo/egress-b")
	a.Config.TlsTermination.IncludeHosts[0] = "mutated.invalid"

	if got := r.AgentioConfig.GetKey("effective").Value.GetSandboxExtProc().GetService(); got != "epe.agentio-system.svc.cluster.local" {
		t.Fatalf("mutating gateway projection changed effective sandbox ext_proc to %q", got)
	}
	if b.Config.GetTlsTermination() != nil {
		t.Fatalf("mutating egress-a projection changed egress-b config to %+v", b.Config)
	}
	if got := r.AgentioConfig.GetKey("effective").Value.GetEgressGateways()[0].GetTlsTermination().GetIncludeHosts()[0]; got != "a.example.com" {
		t.Fatalf("mutating gateway projection changed effective egress entry to %q", got)
	}
}

// sandbox_ext_proc remains a separate global compiler input. Changing it must
// not duplicate the fallback into, or emit changes from, the Gateway source.
func TestSharedGatewayFallbackChangeDoesNotChangeGatewaySource(t *testing.T) {
	ctx := t.Context()
	config := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "agentio-system",
			Name:      "agentio-config",
		},
		Data: map[string]string{"config": `sandboxExtProc:
  service: epe-old.agentio-system.svc.cluster.local
  port: 9002
egressGateways:
- namespace: demo
  name: egress-a
- namespace: demo
  name: egress-b
`},
	}
	r := newTestRegistry(t, ctx, []runtime.Object{config}, nil)
	testutil.Eventually(t, func() bool { return len(r.Gateways.List()) == 2 }, "configured gateways")
	recorder := newGatewayRecorder(r.Gateways)

	config.Data["config"] = `sandboxExtProc:
  service: epe-new.agentio-system.svc.cluster.local
  port: 9002
egressGateways:
- namespace: demo
  name: egress-a
- namespace: demo
  name: egress-b
`
	if _, err := r.client.CoreV1().ConfigMaps(config.Namespace).Update(ctx, config, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	testutil.Eventually(t, func() bool {
		return r.AgentioConfig.GetKey("effective").Value.GetSandboxExtProc().GetService() ==
			"epe-new.agentio-system.svc.cluster.local"
	}, "shared fallback updates independently")
	time.Sleep(200 * time.Millisecond)
	if got := recorder.names(); len(got) != 0 {
		t.Fatalf("shared fallback changed Gateway source entries %v", got)
	}
}

// Duplicate configured identities collapse to one explicit conflict value so
// every downstream consumer fails the same key closed.
func TestGatewayProjectionMarksDuplicateConfiguredEntriesAsConflict(t *testing.T) {
	ctx := t.Context()
	config := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "agentio-system",
			Name:      "agentio-config",
		},
		Data: map[string]string{"config": `egressGateways:
- namespace: demo
  name: egress
- namespace: demo
  name: egress
  tlsTermination:
    includeHosts: ["*.example.com"]
`},
	}
	r := newTestRegistry(t, ctx, []runtime.Object{config}, nil)
	testutil.Eventually(t, func() bool {
		gateway := r.Gateways.GetKey("demo/egress")
		return gateway != nil && gateway.Source == model.GatewaySourceConflict && gateway.Config == nil
	}, "duplicate configured gateway conflict")
}

// A gateway add, update, or delete publishes only that namespace/name gateway.
func TestGatewayConfigChangesAffectOnlyItsIdentity(t *testing.T) {
	ctx := t.Context()
	config := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "agentio-system",
			Name:      "agentio-config",
		},
		Data: map[string]string{"config": `egressGateways:
- namespace: demo
  name: egress-a
`},
	}
	r := newTestRegistry(t, ctx, []runtime.Object{config}, nil)
	testutil.Eventually(
		t,
		func() bool { return r.Gateways.GetKey("demo/egress-a") != nil },
		"initial configured gateway",
	)
	recorder := newGatewayRecorder(r.Gateways)

	config.Data["config"] = `egressGateways:
- namespace: demo
  name: egress-a
- namespace: demo
  name: egress-b
`
	if _, err := r.client.CoreV1().ConfigMaps(config.Namespace).Update(ctx, config, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	testutil.Eventually(
		t,
		func() bool { return r.Gateways.GetKey("demo/egress-b") != nil },
		"gateway configuration add",
	)
	time.Sleep(200 * time.Millisecond)
	if got := recorder.names(); len(got) != 1 || got[0] != "demo/egress-b" {
		t.Fatalf("gateway add changed %v, want only demo/egress-b", got)
	}

	recorder.reset()
	config.Data["config"] = `egressGateways:
- namespace: demo
  name: egress-a
- namespace: demo
  name: egress-b
  tlsTermination:
    includeHosts: ["*.example.com"]
`
	if _, err := r.client.CoreV1().ConfigMaps(config.Namespace).Update(ctx, config, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	testutil.Eventually(t, func() bool {
		gateway := r.Gateways.GetKey("demo/egress-b")
		return gateway != nil && len(gateway.Config.GetTlsTermination().GetIncludeHosts()) == 1
	}, "gateway configuration update")
	time.Sleep(200 * time.Millisecond)
	if got := recorder.names(); len(got) != 1 || got[0] != "demo/egress-b" {
		t.Fatalf("gateway update changed %v, want only demo/egress-b", got)
	}

	recorder.reset()
	config.Data["config"] = `egressGateways:
- namespace: demo
  name: egress-a
`
	if _, err := r.client.CoreV1().ConfigMaps(config.Namespace).Update(ctx, config, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	testutil.Eventually(
		t,
		func() bool { return r.Gateways.GetKey("demo/egress-b") == nil },
		"gateway configuration delete",
	)
	time.Sleep(200 * time.Millisecond)
	if got := recorder.names(); len(got) != 1 || got[0] != "demo/egress-b" {
		t.Fatalf("gateway delete changed %v, want only demo/egress-b", got)
	}
}

// Pod lifecycle is not a gateway graph input.
func TestUnrelatedGatewayPodChangeDoesNotInvalidateConfiguredGraphs(t *testing.T) {
	ctx := t.Context()
	config := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "agentio-system",
			Name:      "agentio-config",
		},
		Data: map[string]string{"config": `egressGateways:
- namespace: demo
  name: egress-a
- namespace: demo
  name: egress-b
`},
	}
	r := newTestRegistry(t, ctx, []runtime.Object{config}, nil)
	testutil.Eventually(t, func() bool { return len(r.Gateways.List()) == 2 }, "configured gateways")
	recorder := newGatewayRecorder(r.Gateways)

	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "unrelated"}}
	if _, err := r.client.CoreV1().Pods(pod.Namespace).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	testutil.Eventually(
		t,
		func() bool { return r.Pods.GetKey("demo/unrelated") != nil },
		"unrelated Pod reaches identity cache",
	)
	time.Sleep(200 * time.Millisecond)
	if got := recorder.names(); len(got) != 0 {
		t.Fatalf("unrelated Pod changed gateway graphs %v", got)
	}
}
