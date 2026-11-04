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

package config_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/config"
	"github.com/openkruise/agentio/pkg/krt"
)

func TestCollectionDefaultsOverlaysAndLastGood(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	cm := func(name, selected string) *corev1.ConfigMap {
		return &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "system"},
			Data: map[string]string{
				"settings": fmt.Sprintf("defaultProviders: {credentialProvider: %s}", selected),
				"config":   "ignored: true",
			},
		}
	}
	opts := krt.NewOptionsBuilder(ctx.Done(), "test", nil)
	sources := krt.NewMutableCollection(
		nil,
		[]*corev1.ConfigMap{cm("base", "base"), cm("primary", "reject")},
		opts.WithName("Sources")...)
	defaults := &configv1.EPEConfig{
		DefaultProviders: &configv1.DefaultExtensionProviders{CredentialProvider: "default"},
	}
	rejected := make(chan struct{}, 2)
	col := config.NewCollection(sources.AsCollection(), config.Options[*configv1.EPEConfig]{
		Namespace: "system",
		Names:     []string{"base", "", "primary"},
		Key:       "settings",
		Defaults:  defaults,
		Apply: func(content string, base *configv1.EPEConfig) (*configv1.EPEConfig, error) {
			value, err := config.Apply(content, base)
			if err != nil {
				rejected <- struct{}{}
			}
			return value, err
		},
		Validate: func(value *configv1.EPEConfig) error {
			if value.GetDefaultProviders().GetCredentialProvider() == "reject" {
				rejected <- struct{}{}
				return fmt.Errorf("rejected selection")
			}
			return nil
		},
	}, opts.WithName("Configuration")...)
	// Construction owns a snapshot of defaults, independent of caller mutation.
	defaults.DefaultProviders.CredentialProvider = "modified"
	events := make(chan string, 10)
	registration := col.AsCollection().Register(func(event krt.Event[config.Config[*configv1.EPEConfig]]) {
		events <- event.Latest().Value.GetDefaultProviders().GetCredentialProvider()
	})
	if !registration.WaitUntilSynced(ctx.Done()) {
		t.Fatal("configuration did not sync")
	}
	wantEvent := func(want string) {
		t.Helper()
		select {
		case got := <-events:
			if got != want {
				t.Fatalf("published selection = %q, want %q", got, want)
			}
		case <-ctx.Done():
			t.Fatalf("waiting for selection %q: %v", want, ctx.Err())
		}
	}
	waitRejection := func() {
		t.Helper()
		select {
		case <-rejected:
		case <-ctx.Done():
			t.Fatal("invalid configuration was not evaluated")
		}
	}
	wantEvent("default") // An invalid initial primary must not publish a partial base.
	waitRejection()
	sources.UpdateObject(cm("primary", "first"))
	wantEvent("first")
	sources.UpdateObject(cm("primary", "reject"))
	waitRejection()
	malformed := cm("primary", "unused")
	malformed.Data["settings"] = "futureOption: true\ndefaultProviders: {credentialProvider: []}"
	sources.UpdateObject(malformed)
	waitRejection()
	recovered := cm("primary", "recovered")
	recovered.Data["settings"] += "\nfutureOption: true"
	sources.UpdateObject(recovered)
	// No defaults or partial base may be published between the two valid versions.
	wantEvent("recovered")
	sources.DeleteObject("system/primary")
	wantEvent("base")
	sources.DeleteObject("system/base")
	wantEvent("default")
	sources.UpdateObject(cm("primary", "created"))
	wantEvent("created") // Missing sources remain dependencies.
	empty := cm("primary", "unused")
	empty.Data = nil
	sources.UpdateObject(empty)
	wantEvent("default")
}
