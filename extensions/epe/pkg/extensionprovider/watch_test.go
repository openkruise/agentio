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

package extensionprovider

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/certs/certstest"
	"github.com/openkruise/agentio/extensions/epe/pkg/credential/credentialtest"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/tokentransform"
	"github.com/openkruise/agentio/extensions/epe/pkg/testing/testsupport"
	"github.com/openkruise/agentio/pkg/config"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/kube/kclient"
)

// watch mirrors main.go: build the collection, register the registry, run the
// informers, then block on the initial application.
func watch(
	t testing.TB,
	client kube.Client,
	namespace string,
	names []string,
	registry *Registry,
	stop <-chan struct{},
	defaults ...*configv1.EPEConfig,
) krt.HandlerRegistration {
	t.Helper()
	cfg := &configv1.EPEConfig{}
	if len(defaults) != 0 {
		cfg = defaults[0]
	}
	cms := kclient.NewFiltered[*corev1.ConfigMap](client, kclient.Filter{})
	cms.Start(stop)
	configMaps := krt.WrapClient(cms, krt.WithStop(stop))
	configs := config.NewCollection(
		configMaps,
		config.Options[*configv1.EPEConfig]{
			Namespace: namespace,
			Names:     names,
			Defaults:  cfg,
			Apply:     ApplyConfig,
			Validate:  Validate,
		},
		krt.WithStop(stop),
	)
	reg := registry.RegisterCollection(NewCollection(client, namespace, configs.AsCollection(), configMaps, nil, stop))
	client.Run(stop)
	return reg
}

func TestWatchInitialConfiguration(t *testing.T) {
	for _, tt := range []struct {
		name   string
		absent bool
		data   map[string]string
	}{
		{name: "absent", absent: true},
		{name: "missing key"},
		{name: "empty value", data: map[string]string{"config": " \n"}},
		{name: "invalid YAML", data: map[string]string{"config": "extensionProviders: ["}},
		{name: "invalid provider", data: map[string]string{"config": "extensionProviders: [{name: a}]"}},
		{name: "empty registry", data: map[string]string{"config": "extensionProviders: []"}},
		{
			name: "missing Secret",
			data: map[string]string{"config": `extensionProviders:
- name: a
  credentialProvider:
    url: https://provider.example
    tls:
      caSecretRef: {name: missing}
`},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			var objects []runtime.Object
			if !tt.absent {
				objects = append(objects, &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "epe", Namespace: "system"},
					Data:       tt.data,
				})
			}
			client := kube.NewFakeClient(objects...)
			environment := credentialtest.NewAPIKeyProvider(t, "environment")
			registry := &Registry{}
			t.Cleanup(registry.Close)
			reg := watch(
				t,
				client,
				"system",
				[]string{"epe"},
				registry,
				ctx.Done(),
				defaultConfig(environment.Server.URL),
			)
			if !reg.WaitUntilSynced(ctx.Done()) {
				t.Fatal("initial sync did not complete")
			}
			if tt.name == "empty registry" {
				if _, err := registry.Fetch(ctx, tokentransform.Ref{}); err == nil {
					t.Fatal("cleared defaults still available")
				}
			} else if token(t, registry, ctx, "") != "environment" {
				t.Fatal("initial configuration must use the defaults")
			}
			if tt.name == "missing Secret" {
				registry.mu.Lock()
				defer registry.mu.Unlock()
				if provider := registry.current.providers["a"]; provider == nil || provider.err == nil {
					t.Fatal("initial sync must install the unavailable provider before serving")
				}
			}
		})
	}
}

func TestWatchConfigMapLayersOverrideDefaults(t *testing.T) {
	environment := credentialtest.NewAPIKeyProvider(t, "environment")
	dynamic := credentialtest.NewAPIKeyProvider(t, "dynamic")
	registry := &Registry{}
	defer registry.Close()
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "epe", Namespace: "system"},
		Data: map[string]string{"config": fmt.Sprintf(`extensionProviders:
- name: additional
  credentialProvider: {url: %q}
defaultProviders: {credentialProvider: additional}
`, dynamic.Server.URL)},
	}
	client := kube.NewFakeClient()
	reg := watch(
		t,
		client,
		"system",
		[]string{"epe", "epe-primary"},
		registry,
		t.Context().Done(),
		defaultConfig(environment.Server.URL),
	)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if !reg.WaitUntilSynced(ctx.Done()) {
		t.Fatal("initial sync did not complete")
	}
	if token(t, registry, t.Context(), "") != "environment" {
		t.Fatal("absent ConfigMap must use the environment provider")
	}
	if _, err := client.Kube().CoreV1().ConfigMaps("system").Create(ctx, cm, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	testsupport.Eventually(t, 5*time.Second, func() error {
		registry.mu.Lock()
		defer registry.mu.Unlock()
		if registry.current.defaultCredential != "additional" {
			return fmt.Errorf("created ConfigMap has not selected the dynamic provider")
		}
		return nil
	})
	if token(t, registry, t.Context(), "") != "dynamic" {
		t.Fatal("base did not replace defaults")
	}
	if token(t, registry, ctx, "default") != "environment" || environment.Calls.Load() != 1 {
		t.Fatal("adding a provider must preserve the environment provider and its cache")
	}
	primary := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "epe-primary", Namespace: "system"},
		Data: map[string]string{"config": fmt.Sprintf(`extensionProviders:
- name: default
  credentialProvider: {url: %q}
defaultProviders: {credentialProvider: default}
`, dynamic.Server.URL)},
	}
	if _, err := client.Kube().CoreV1().ConfigMaps("system").Create(ctx, primary, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	testsupport.Eventually(t, 5*time.Second, func() error {
		registry.mu.Lock()
		defer registry.mu.Unlock()
		if registry.current.defaultCredential != "default" {
			return fmt.Errorf("primary default selection has not applied")
		}
		return nil
	})
	if token(t, registry, ctx, "") != "dynamic" {
		t.Fatal("primary must be able to define an ordinary provider named default")
	}
	if err := client.Kube().
		CoreV1().
		ConfigMaps("system").
		Delete(ctx, primary.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	testsupport.Eventually(t, 5*time.Second, func() error {
		registry.mu.Lock()
		defer registry.mu.Unlock()
		if registry.current.defaultCredential != "additional" {
			return fmt.Errorf("deleting primary has not restored the base")
		}
		return nil
	})
	if token(t, registry, ctx, "default") != "environment" {
		t.Fatal("deleting primary must restore the lower provider with the same name")
	}
	if err := client.Kube().
		CoreV1().
		ConfigMaps("system").
		Delete(t.Context(), "epe", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	testsupport.Eventually(t, 5*time.Second, func() error {
		registry.mu.Lock()
		defer registry.mu.Unlock()
		if len(registry.current.providers) != 1 || registry.current.defaultCredential != "default" {
			return fmt.Errorf("ConfigMap layer has not been removed")
		}
		return nil
	})
	if token(t, registry, t.Context(), "") != "environment" {
		t.Fatal("ConfigMap deletion removed the environment provider")
	}
}

func TestWatchSwitchesSecretDependencies(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ca := certstest.New(t)
	raw := func(secret string) string {
		return fmt.Sprintf(`extensionProviders:
- name: a
  httpCallout:
    url: https://provider.example
    tls:
      caSecretRef: {name: %s}
`, secret)
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "epe", Namespace: "system"},
		Data:       map[string]string{"config": raw("first")},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "first", Namespace: "system"},
		Data:       map[string][]byte{"ca.crt": ca.CAPEM()},
	}
	client := kube.NewFakeClient(cm, secret)
	registry := &Registry{}
	t.Cleanup(registry.Close)
	reg := watch(t, client, "system", []string{"epe"}, registry, ctx.Done())
	waitCtx, waitCancel := context.WithTimeout(ctx, 5*time.Second)
	defer waitCancel()
	if !reg.WaitUntilSynced(waitCtx.Done()) {
		t.Fatal("initial sync did not complete")
	}
	registry.mu.Lock()
	first := registry.current.providers["a"]
	registry.mu.Unlock()
	if first == nil || first.err != nil {
		t.Fatalf("initial provider unavailable: %+v", first)
	}

	// A valid reference to a missing Secret installs an unavailable provider,
	// then its creation must wake the dependency without another config change.
	cm.Data["config"] = raw("second")
	if _, err := client.Kube().CoreV1().ConfigMaps("system").Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	testsupport.Eventually(t, 5*time.Second, func() error {
		registry.mu.Lock()
		defer registry.mu.Unlock()
		if provider := registry.current.providers["a"]; provider == nil || provider == first || provider.err == nil {
			return fmt.Errorf("missing replacement Secret has not invalidated the provider")
		}
		return nil
	})
	secret = secret.DeepCopy()
	secret.Name = "second"
	if _, err := client.Kube().CoreV1().Secrets("system").Create(ctx, secret, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	testsupport.Eventually(t, 5*time.Second, func() error {
		registry.mu.Lock()
		defer registry.mu.Unlock()
		if provider := registry.current.providers["a"]; provider == nil || provider == first || provider.err != nil {
			return fmt.Errorf("replacement Secret has not recovered the provider")
		}
		return nil
	})

	// The owner closes the registry after stopping the watch. Queued events cannot reopen it.
	for i := range 10 {
		cm.Data["config"] = raw([]string{"first", "second"}[i%2])
		if _, err := client.Kube().CoreV1().ConfigMaps("system").Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	cancel()
	registry.Close()
	testsupport.Eventually(t, 5*time.Second, func() error {
		registry.mu.Lock()
		defer registry.mu.Unlock()
		if len(registry.current.providers) != 0 {
			return fmt.Errorf("registry still owns providers after shutdown")
		}
		return nil
	})
}

func defaultConfig(endpoint string) *configv1.EPEConfig {
	return &configv1.EPEConfig{
		ExtensionProviders: []*configv1.ExtensionProvider{{
			Name: "default",
			Provider: &configv1.ExtensionProvider_CredentialProvider{
				CredentialProvider: &configv1.CredentialProvider{Url: endpoint},
			},
		}},
		DefaultProviders: &configv1.DefaultExtensionProviders{CredentialProvider: "default"},
	}
}

// Files and cross-namespace Secrets both enter the effective config's material
// snapshot, so rotation changes the provider instance and invalidates its cache.
func TestWatchCertificateSources(t *testing.T) {
	for _, source := range []string{"files", "secret"} {
		t.Run(source, func(t *testing.T) {
			cert, key := certstest.SelfSigned(t, 7001)
			ca := certstest.New(t).CAPEM()
			tlsConfig := &configv1.ClientTLS{}
			client := kube.NewFakeClient()
			var rotate func()
			switch source {
			case "files":
				dir := t.TempDir()
				tlsConfig.CaSource = &configv1.ClientTLS_CaCertificateFile{
					CaCertificateFile: filepath.Join(dir, "ca.crt"),
				}
				files := &configv1.ProviderClientCertificateFiles{
					CertificateFile: filepath.Join(dir, "client.crt"),
					PrivateKeyFile:  filepath.Join(dir, "client.key"),
				}
				tlsConfig.ClientCertificateSource = &configv1.ClientTLS_ClientCertificateFiles{
					ClientCertificateFiles: files,
				}
				write := func(path string, data []byte) {
					t.Helper()
					if err := os.WriteFile(path, data, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				write(tlsConfig.GetCaCertificateFile(), ca)
				write(files.CertificateFile, cert)
				write(files.PrivateKeyFile, key)
				rotate = func() { write(tlsConfig.GetCaCertificateFile(), []byte("revoked")) }
			case "secret":
				tlsConfig.CaSource = &configv1.ClientTLS_CaSecretRef{
					CaSecretRef: &configv1.TargetReference{Name: "client", Namespace: "other"},
				}
				tlsConfig.ClientCertificateSource = &configv1.ClientTLS_ClientCertificateSecretRef{
					ClientCertificateSecretRef: &configv1.TargetReference{
						Name:      "client",
						Namespace: "other",
					},
				}
				sec := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "client", Namespace: "other"},
					Data:       map[string][]byte{"ca.crt": ca, corev1.TLSCertKey: cert, corev1.TLSPrivateKeyKey: key},
				}
				client = kube.NewFakeClient(sec)
				rotate = func() {
					sec = sec.DeepCopy()
					sec.Data["ca.crt"] = []byte("revoked")
					if _, err := client.Kube().
						CoreV1().
						Secrets("other").
						Update(t.Context(), sec, metav1.UpdateOptions{}); err != nil {
						t.Fatal(err)
					}
				}
			}
			defaults := defaultConfig("https://credentials.example")
			defaults.ExtensionProviders[0].GetCredentialProvider().Tls = tlsConfig
			registry := &Registry{}
			t.Cleanup(registry.Close)
			reg := watch(t, client, "system", []string{"epe"}, registry, t.Context().Done(), defaults)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			if !reg.WaitUntilSynced(ctx.Done()) {
				t.Fatal("initial sync failed")
			}
			first := liveProvider(registry, "default")
			if first == nil || first.err != nil {
				t.Fatalf("initial TLS material unavailable: %+v", first)
			}
			rotate()
			testsupport.Eventually(t, 15*time.Second, func() error {
				next := liveProvider(registry, "default")
				if next == nil || next == first || next.err == nil {
					return fmt.Errorf("revoked CA did not invalidate the provider")
				}
				return nil
			})

			// Removing every provider stops the file watch; deleting the layer starts
			// it again from Defaults without retaining the removed instance.
			_, err := client.Kube().CoreV1().ConfigMaps("system").Create(t.Context(), &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "epe", Namespace: "system"},
				Data:       map[string]string{"config": "extensionProviders: []"},
			}, metav1.CreateOptions{})
			if err != nil {
				t.Fatal(err)
			}
			testsupport.Eventually(t, 5*time.Second, func() error {
				if liveProvider(registry, "default") != nil {
					return fmt.Errorf("provider not removed")
				}
				return nil
			})
			if err := client.Kube().
				CoreV1().
				ConfigMaps("system").
				Delete(t.Context(), "epe", metav1.DeleteOptions{}); err != nil {
				t.Fatal(err)
			}
			testsupport.Eventually(t, 5*time.Second, func() error {
				if liveProvider(registry, "default") == nil {
					return fmt.Errorf("default not restored")
				}
				return nil
			})
		})
	}
}

func TestWatchCertificateFilePaths(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "late-volume")
	firstPath := filepath.Join(dir, "ca.crt")
	configFor := func(path string) string {
		return fmt.Sprintf(`extensionProviders:
- name: files
  httpCallout:
    url: https://callout.example
    tls:
      caCertificateFile: %q
`, path)
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "epe", Namespace: "system"},
		Data:       map[string]string{"config": configFor(firstPath)},
	}
	client := kube.NewFakeClient(cm)
	registry := &Registry{}
	t.Cleanup(registry.Close)
	reg := watch(t, client, "system", []string{"epe"}, registry, t.Context().Done())
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if !reg.WaitUntilSynced(ctx.Done()) {
		t.Fatal("missing file must not block initial sync")
	}
	if provider := liveProvider(registry, "files"); provider == nil || provider.err == nil {
		t.Fatal("missing CA must make the provider unavailable")
	}
	write := func(path string, data []byte) {
		t.Helper()
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	write(firstPath, certstest.New(t).CAPEM())
	// The directory did not exist when the watch was installed. Polling must
	// recover the provider even without a filesystem notification.
	testsupport.Eventually(t, 15*time.Second, func() error {
		if provider := liveProvider(registry, "files"); provider == nil || provider.err != nil {
			return fmt.Errorf("late certificate file did not restore the provider")
		}
		return nil
	})
	first := liveProvider(registry, "files")
	secondPath := filepath.Join(t.TempDir(), "ca.crt")
	write(secondPath, certstest.New(t).CAPEM())
	cm = cm.DeepCopy()
	cm.Data["config"] = configFor(secondPath)
	if _, err := client.Kube().
		CoreV1().
		ConfigMaps("system").
		Update(t.Context(), cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	testsupport.Eventually(t, 5*time.Second, func() error {
		if provider := liveProvider(registry, "files"); provider == nil || provider == first || provider.err != nil {
			return fmt.Errorf("configured path did not switch the provider")
		}
		return nil
	})
	write(secondPath, []byte("invalid CA"))
	testsupport.Eventually(t, 5*time.Second, func() error {
		if provider := liveProvider(registry, "files"); provider == nil || provider.err == nil {
			return fmt.Errorf("new certificate path is not watched")
		}
		return nil
	})
}
