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

package clienttrust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/openkruise/agentio/test/e2e"
	"github.com/openkruise/agentio/test/e2e/components/namespace"
	e2econfig "github.com/openkruise/agentio/test/e2e/config"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

func TestClientTrustSourceUpdates(t *testing.T) {
	s := newScenario(t)
	pod := s.pod("bundle-updates")
	pod.Spec.InitContainers = nil
	ready := s.createPod(t, pod)
	baseline := s.bundle(t)
	certificate := publicCA(t)
	source := "client-trust-source-" + s.namespace
	e2econfig.New(s.scope).Eval(rig.Config.Namespace, map[string]any{"Name": source, "CA": certificate}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .Name }}
data:
  ca.crt: {{ printf "%q" .CA }}
`).ApplyOrFail(t, kube.CreateOnly)
	bundleConfig := s.values["clientTrustBundle"].(map[string]any)
	bundleConfig["sources"] = append(bundleConfig["sources"].([]any), map[string]any{"configMap": map[string]any{
		"namespace": rig.Config.Namespace, "name": source, "key": "ca.crt",
	}})
	s.publish(t)
	s.waitBundle(t, func(data string) bool { return strings.Contains(data, strings.TrimSpace(certificate)) })
	merged := s.bundle(t)
	if strings.Count(merged, "BEGIN CERTIFICATE") != strings.Count(baseline, "BEGIN CERTIFICATE")+1 {
		t.Fatal("additional CA did not join the public and MITM bundle")
	}
	// Verify projection into an already-running Pod, independently of process reload.
	harness.RetryAssertion(t, 2*time.Minute, time.Second, func() error {
		ctx, cancel := e2e.Context(t, 10*time.Second)
		defer cancel()
		stdout, stderr, err := s.env.Kube.Exec(ctx, ready.Namespace, ready.Name, "app-main", []string{"cat", defaultBundlePath}, nil)
		if err != nil {
			return fmt.Errorf("read mounted bundle: %w; %s", err, stderr)
		}
		if stdout != merged {
			return fmt.Errorf("mounted bundle has not caught up with target ConfigMap")
		}
		return nil
	})
	before := s.failureEvents(t)
	e2econfig.New(s.scope).Eval(rig.Config.Namespace, map[string]any{"Name": source}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .Name }}
data:
  ca.crt: invalid PEM
`).ApplyOrFail(t, kube.ReconcileOwned)
	harness.RetryAssertion(t, time.Minute, time.Second, func() error {
		ctx, cancel := e2e.Context(t, 10*time.Second)
		defer cancel()
		events, err := s.env.Cluster.Kube.CoreV1().Events(rig.Config.Namespace).List(ctx, metav1.ListOptions{FieldSelector: "reason=ClientTrustReconcileFailed"})
		if err != nil {
			return err
		}
		for _, event := range events.Items {
			if strings.Contains(event.Message, "non-certificate data") && max(event.Count, 1) > before[event.UID] {
				return nil
			}
		}
		return fmt.Errorf("invalid CA has not produced a new failure event")
	})
	if s.bundle(t) != merged {
		t.Fatal("invalid source replaced last complete bundle")
	}
	s.configure(t, baseSettings())
	s.waitBundle(t, func(data string) bool { return data == baseline })
	s.save(t, "source-updates", map[string]any{"sourceMerge": true, "mountedFileUpdate": true, "invalidSourceRetention": true, "sourceRemoval": true,
		"baselineCertificates": strings.Count(baseline, "BEGIN CERTIFICATE"), "mergedCertificates": strings.Count(merged, "BEGIN CERTIFICATE")})
}

func (s *scenario) failureEvents(t *testing.T) map[types.UID]int32 {
	t.Helper()
	ctx, cancel := e2e.Context(t, 10*time.Second)
	defer cancel()
	events, err := s.env.Cluster.Kube.CoreV1().Events(rig.Config.Namespace).List(ctx, metav1.ListOptions{FieldSelector: "reason=ClientTrustReconcileFailed"})
	if err != nil {
		t.Fatal(err)
	}
	counts := map[types.UID]int32{}
	for _, event := range events.Items {
		counts[event.UID] = max(event.Count, 1)
	}
	return counts
}

func (s *scenario) targetBundle(ctxT *testing.T) (*corev1.ConfigMap, error) {
	ctx, cancel := e2e.Context(ctxT, 10*time.Second)
	defer cancel()
	return s.env.Cluster.Kube.CoreV1().ConfigMaps(s.namespace).Get(ctx, "agentio-client-ca", metav1.GetOptions{})
}

func (s *scenario) bundle(t *testing.T) string {
	t.Helper()
	cm, err := s.targetBundle(t)
	if err != nil {
		t.Fatal(err)
	}
	return cm.Data["ca-bundle.pem"]
}

func (s *scenario) waitBundle(t *testing.T, expected func(string) bool) {
	t.Helper()
	harness.RetryAssertion(t, time.Minute, time.Second, func() error {
		cm, err := s.targetBundle(t)
		if err != nil {
			return err
		}
		if !expected(cm.Data["ca-bundle.pem"]) {
			return fmt.Errorf("CA bundle has not converged")
		}
		return nil
	})
}

func publicCA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Client Trust Update Test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestClientTrustNamespaceDistribution(t *testing.T) {
	s := newScenario(t)
	ns := namespace.Create(t, s.env, namespace.Config{Prefix: "client-trust-no-pods"})
	var original *corev1.ConfigMap
	harness.RetryAssertion(t, time.Minute, time.Second, func() error {
		ctx, cancel := e2e.Context(t, 10*time.Second)
		defer cancel()
		cm, err := s.env.Cluster.Kube.CoreV1().ConfigMaps(ns.Name()).Get(ctx, "agentio-client-ca", metav1.GetOptions{})
		if err != nil {
			return err
		}
		if strings.Count(cm.Data["ca-bundle.pem"], "BEGIN CERTIFICATE") < 50 {
			return fmt.Errorf("public CA bundle is not ready")
		}
		original = cm
		return nil
	})
	ctx, cancel := e2e.Context(t, 20*time.Second)
	defer cancel()
	pods, err := s.env.Cluster.Kube.CoreV1().Pods(ns.Name()).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(pods.Items) != 0 {
		t.Fatal("namespace distribution unexpectedly required a Pod")
	}
	if err = s.env.Cluster.Kube.CoreV1().ConfigMaps(ns.Name()).Delete(ctx, original.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	harness.RetryAssertion(t, time.Minute, time.Second, func() error {
		ctx, cancel := e2e.Context(t, 10*time.Second)
		defer cancel()
		cm, err := s.env.Cluster.Kube.CoreV1().ConfigMaps(ns.Name()).Get(ctx, original.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if cm.UID == original.UID || cm.Data["ca-bundle.pem"] != original.Data["ca-bundle.pem"] {
			return fmt.Errorf("deleted target has not been repaired")
		}
		return nil
	})
	s.save(t, "namespace-distribution", map[string]any{"namespace": ns.Name(), "withoutPods": true, "deletedTargetRepaired": true})
}

func TestClientTrustSecretSourceUpdates(t *testing.T) {
	s := newScenario(t)
	s.waitBundle(t, func(data string) bool { return strings.Count(data, "BEGIN CERTIFICATE") >= 50 })
	baseline := s.bundle(t)
	first, second, additional := publicCA(t), publicCA(t), publicCA(t)
	name := "client-trust-secret-" + s.namespace
	otherName := name + "-other"
	apply := func(sourceName string, certificate string, mode kube.Mode) {
		t.Helper()
		e2econfig.New(s.scope).Eval(rig.Config.Namespace, map[string]any{"Name": sourceName, "CA": certificate}, `
apiVersion: v1
kind: Secret
metadata:
  name: {{ .Name }}
type: Opaque
stringData:
  ca.crt: {{ printf "%q" .CA }}
`).ApplyOrFail(t, mode)
	}
	apply(name, first, kube.CreateOnly)
	apply(otherName, additional, kube.CreateOnly)
	bundle := s.values["clientTrustBundle"].(map[string]any)
	baselineSources := slices.Clone(bundle["sources"].([]any))
	firstSource := map[string]any{"secret": map[string]any{
		"namespace": rig.Config.Namespace, "name": name, "key": "ca.crt",
	}}
	otherSource := map[string]any{"secret": map[string]any{
		"namespace": rig.Config.Namespace, "name": otherName, "key": "ca.crt",
	}}
	bundle["sources"] = append(slices.Clone(baselineSources), firstSource, otherSource)
	s.publish(t)
	s.waitBundle(t, func(data string) bool {
		return strings.Contains(data, strings.TrimSpace(first)) && strings.Contains(data, strings.TrimSpace(additional))
	})
	apply(name, second, kube.ReconcileOwned)
	s.waitBundle(t, func(data string) bool {
		return strings.Contains(data, strings.TrimSpace(second)) && strings.Contains(data, strings.TrimSpace(additional)) && !strings.Contains(data, strings.TrimSpace(first))
	})
	// Removing one reference must leave the other Secret's watch and updates working.
	bundle["sources"] = append(slices.Clone(baselineSources), otherSource)
	s.publish(t)
	s.waitBundle(t, func(data string) bool {
		return strings.Contains(data, strings.TrimSpace(additional)) && !strings.Contains(data, strings.TrimSpace(second))
	})
	apply(otherName, first, kube.ReconcileOwned)
	s.waitBundle(t, func(data string) bool {
		return strings.Contains(data, strings.TrimSpace(first)) && !strings.Contains(data, strings.TrimSpace(additional))
	})
	s.configure(t, baseSettings())
	s.waitBundle(t, func(data string) bool { return data == baseline })
	s.save(t, "secret-source-updates", map[string]any{"multipleSources": true, "sourceUpdated": true, "remainingSourceUpdated": true, "sourcesRemoved": true})
}

func TestClientTrustSecretNamespaceIsolation(t *testing.T) {
	s := newScenario(t)
	s.waitBundle(t, func(data string) bool { return strings.Count(data, "BEGIN CERTIFICATE") >= 50 })
	baseline := s.bundle(t)
	certificate := publicCA(t)
	name := "client-trust-healthy-" + s.namespace
	e2econfig.New(s.scope).Eval(rig.Config.Namespace, map[string]any{"Name": name, "CA": certificate}, `
apiVersion: v1
kind: Secret
metadata:
  name: {{ .Name }}
type: Opaque
stringData:
  ca.crt: {{ printf "%q" .CA }}
`).ApplyOrFail(t, kube.CreateOnly)
	bundle := s.values["clientTrustBundle"].(map[string]any)
	healthySources := append(slices.Clone(bundle["sources"].([]any)), map[string]any{"secret": map[string]any{
		"namespace": rig.Config.Namespace, "name": name, "key": "ca.crt",
	}})
	// Default agentiod RBAC cannot read Secrets in the business namespace.
	bundle["sources"] = append(slices.Clone(healthySources), map[string]any{"secret": map[string]any{
		"namespace": s.namespace, "name": name, "key": "ca.crt",
	}})
	before := s.failureEvents(t)
	s.publish(t)
	harness.RetryAssertion(t, time.Minute, time.Second, func() error {
		ctx, cancel := e2e.Context(t, 10*time.Second)
		defer cancel()
		events, err := s.env.Cluster.Kube.CoreV1().Events(rig.Config.Namespace).List(ctx, metav1.ListOptions{FieldSelector: "reason=ClientTrustReconcileFailed"})
		if err != nil {
			return err
		}
		for _, event := range events.Items {
			if strings.Contains(event.Message, "Secret "+s.namespace+"/"+name+" is unavailable") && max(event.Count, 1) > before[event.UID] {
				return nil
			}
		}
		return fmt.Errorf("source outside the shared Secret cache has not produced a new failure event")
	})
	if s.bundle(t) != baseline {
		t.Fatal("unavailable namespace replaced the last complete bundle")
	}
	bundle["sources"] = healthySources
	s.publish(t)
	s.waitBundle(t, func(data string) bool { return strings.Contains(data, strings.TrimSpace(certificate)) })
	s.save(t, "secret-namespace-isolation", map[string]any{"unauthorizedNamespace": s.namespace, "lastBundleRetained": true, "configurationRecovered": true})
}
