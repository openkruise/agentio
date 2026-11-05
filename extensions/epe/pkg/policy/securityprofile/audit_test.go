// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package securityprofile

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agents-api/agents/v1alpha1"

	"github.com/openkruise/agentio/extensions/epe/pkg/audit"
)

func auditActionWithTimeout(d *metav1.Duration) *v1alpha1.AuditAction {
	return &v1alpha1.AuditAction{
		Name: "a",
		Webhook: &v1alpha1.AuditWebhook{
			URL:     "http://hook.example.com/audit",
			Timeout: d,
		},
	}
}

// compileAudit resolves the timeout once, at profile load, so nothing
// downstream needs a second default. Pinning it to the shared constant keeps
// that from drifting back into a per-layer literal.
func TestCompileAudit_TimeoutResolvedAtLoad(t *testing.T) {
	tests := []struct {
		name    string
		timeout *metav1.Duration
		want    time.Duration
	}{
		{"omitted uses the shared default", nil, audit.DefaultWebhookTimeout},
		{"zero uses the shared default", &metav1.Duration{}, audit.DefaultWebhookTimeout},
		{"negative uses the shared default", &metav1.Duration{Duration: -1}, audit.DefaultWebhookTimeout},
		{"configured value is kept", &metav1.Duration{Duration: 7 * time.Second}, 7 * time.Second},
		{"over the cap is clamped", &metav1.Duration{Duration: time.Hour}, audit.MaxRequestTimeout},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := compileAudit(auditActionWithTimeout(tc.timeout))
			if err != nil {
				t.Fatalf("compileAudit: %v", err)
			}
			if got.Webhook.Timeout != tc.want {
				t.Errorf("Timeout = %v, want %v", got.Webhook.Timeout, tc.want)
			}
			if got.Webhook.Timeout <= 0 {
				t.Error("a compiled timeout must always be positive; " +
					"downstream relies on it rather than re-defaulting")
			}
		})
	}
}
