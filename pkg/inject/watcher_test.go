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

package inject

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/internal/testutil"
	"github.com/openkruise/agentio/pkg/kube"
)

func TestWatcherLoadsAndKeepsLastKnownGoodConfig(t *testing.T) {
	template, err := os.ReadFile("testdata/ztunnel-injection-template.yaml")
	if err != nil {
		t.Fatal(err)
	}
	values, err := os.ReadFile("testdata/values.json")
	if err != nil {
		t.Fatal(err)
	}
	injectorConfig := "policy: enabled\ndefaultTemplates: [ztunnel]\ntemplates:\n  ztunnel: |\n" + indentLines(string(template), "    ")

	client := kube.NewFakeClient(
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "agentio-sidecar-injector", Namespace: "agentio-system"},
			Data:       map[string]string{"config": injectorConfig, "values": string(values)},
		},
	)
	webhook, err := NewWebhook(WebhookParameters{Mux: http.NewServeMux(), NativeSidecarMode: NativeSidecarModeDisabled})
	if err != nil {
		t.Fatal(err)
	}
	watcher, err := NewWatcher(client, webhook, WatcherOptions{
		Namespace:             "agentio-system",
		InjectorConfigMapName: "agentio-sidecar-injector",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go watcher.Run(ctx.Done())

	configLoaded := func() bool {
		webhook.mu.RLock()
		defer webhook.mu.RUnlock()
		return webhook.config != nil && len(webhook.config.Templates) == 1
	}
	testutil.Eventually(t, configLoaded, "injection configuration to load")

	// An unparsable update must not replace the last known good config.
	broken := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "agentio-sidecar-injector",
			Namespace:       "agentio-system",
			ResourceVersion: "broken",
		},
		Data: map[string]string{"config": "templates:\n  ztunnel: '{{ not closed'", "values": "{"},
	}
	if _, err := client.Kube().CoreV1().ConfigMaps("agentio-system").Update(ctx, broken, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	// The queue retries then drops the broken revision; the loaded config stays.
	time.Sleep(200 * time.Millisecond)
	if !configLoaded() {
		t.Fatal("broken ConfigMap update replaced the last known good configuration")
	}
}

func TestInjectorConfigCarriesZTunnelAndGatewayTemplates(t *testing.T) {
	ztunnel, err := os.ReadFile("testdata/ztunnel-injection-template.yaml")
	if err != nil {
		t.Fatal(err)
	}
	egressGateway, err := os.ReadFile("../gatewaydeployer/templates/egress-gateway.yaml")
	if err != nil {
		t.Fatal(err)
	}
	agentgateway, err := os.ReadFile("../gatewaydeployer/templates/agentgateway.yaml")
	if err != nil {
		t.Fatal(err)
	}
	raw := "defaultTemplates: [ztunnel]\ntemplates:\n" +
		"  ztunnel: |\n" + indentLines(string(ztunnel), "    ") +
		"  egress-gateway: |\n" + indentLines(string(egressGateway), "    ") +
		"  agentgateway: |\n" + indentLines(string(agentgateway), "    ")
	config, err := UnmarshalConfig([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(config.RawTemplates) != 3 || config.RawTemplates["ztunnel"] == "" || config.RawTemplates["egress-gateway"] == "" || config.RawTemplates["agentgateway"] == "" {
		t.Fatalf("injector templates = %v, want ztunnel, egress-gateway and agentgateway", config.RawTemplates)
	}
	if _, found := config.RawTemplates["waypoint"]; found {
		t.Fatal("injector config unexpectedly carries a waypoint template")
	}
}

func indentLines(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return prefix + strings.Join(lines, "\n"+prefix) + "\n"
}

func TestCABundlePatcher(t *testing.T) {
	webhookConfig := &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "agentio-sidecar-injector-agentio-system"},
		Webhooks: []admissionregistrationv1.MutatingWebhook{
			{Name: "rev.namespace.sidecar-injector.istio.io"},
			{Name: "rev.object.sidecar-injector.istio.io"},
		},
	}
	client := kube.NewFakeClient(webhookConfig)
	bundle := []byte("root-one")
	patcher, err := NewCABundlePatcher(client, webhookConfig.Name, func() []byte { return bundle })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go patcher.Run(ctx.Done())

	expectBundle := func(want string) func() bool {
		return func() bool {
			current, err := client.Kube().AdmissionregistrationV1().MutatingWebhookConfigurations().Get(ctx, webhookConfig.Name, metav1.GetOptions{})
			if err != nil {
				return false
			}
			for _, wh := range current.Webhooks {
				if string(wh.ClientConfig.CABundle) != want {
					return false
				}
			}
			return len(current.Webhooks) == 2
		}
	}
	testutil.Eventually(t, expectBundle("root-one"), "initial caBundle patch")

	// A rotation commit notifies the patcher through Sync.
	bundle = []byte("root-two")
	patcher.Sync()
	testutil.Eventually(t, expectBundle("root-two"), "caBundle refresh after rotation")
}
