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
package extensionprovider

import (
	"errors"
	"maps"
	"os"
	"slices"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/certs/certsource"
	"github.com/openkruise/agentio/pkg/config"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/kube/kclient"
)

// Configuration is the layered EPEConfig together with its resolved certificate material.
type Configuration struct {
	config.Config[*configv1.EPEConfig]
	Materials map[string]TLSMaterial
}

// Equals compares the configuration and certificate contents, ignoring unrelated resource updates.
func (c Configuration) Equals(other Configuration) bool {
	return c.Config.Equals(other.Config) &&
		maps.EqualFunc(c.Materials, other.Materials, krt.Equal[TLSMaterial])
}

// NewCollection resolves provider Secrets, CA ConfigMaps, and certificate files
// downstream of the validated EPEConfig collection. Call before client.Run.
func NewCollection(
	client kube.Client,
	namespace string,
	configs krt.Collection[config.Config[*configv1.EPEConfig]],
	configMaps krt.Collection[*corev1.ConfigMap],
	debugger *krt.DebugHandler,
	stop <-chan struct{},
) krt.Collection[Configuration] {
	opts := krt.NewOptionsBuilder(stop, "epe-providers", debugger)
	secretClient := kclient.NewFiltered[*corev1.Secret](client, kclient.Filter{})
	secretClient.Start(stop)
	secrets := krt.WrapClient(secretClient, opts.WithName("Secrets")...)

	files := newFileDependencies(stop, opts.WithName("CertificateFiles")...)
	return krt.NewCollection(
		configs,
		func(ctx krt.HandlerContext, cfg config.Config[*configv1.EPEConfig]) *Configuration {
			var paths []string
			for _, provider := range cfg.Value.GetExtensionProviders() {
				_, _, tlsCfg := settings(provider)
				paths = append(paths, certificateFiles(tlsCfg)...)
			}
			files.watch(ctx, paths)
			resolved := &Configuration{Config: cfg, Materials: map[string]TLSMaterial{}}
			fetched := map[string]*corev1.Secret{}
			lookup := func(key string) *corev1.Secret {
				if secret, ok := fetched[key]; ok {
					return secret
				}
				// Fetch also tracks missing dependencies, so creation restores the provider.
				if secret := krt.FetchOne(ctx, secrets, krt.FilterKey(key)); secret != nil {
					fetched[key] = *secret
					return *secret
				}
				fetched[key] = nil
				return nil
			}
			fetchedConfigMaps := map[string]*corev1.ConfigMap{}
			lookupConfigMap := func(key string) *corev1.ConfigMap {
				if cm, ok := fetchedConfigMaps[key]; ok {
					return cm
				}
				if cm := krt.FetchOne(ctx, configMaps, krt.FilterKey(key)); cm != nil {
					fetchedConfigMaps[key] = *cm
					return *cm
				}
				fetchedConfigMaps[key] = nil
				return nil
			}
			contents := map[string]fileContent{}
			readFile := func(path string) ([]byte, string) {
				if content, found := contents[path]; found {
					return content.data, content.readError
				}
				data, err := os.ReadFile(path)
				content := fileContent{data: data}
				if err != nil {
					content.data = nil
					content.readError = err.Error()
				}
				contents[path] = content
				return content.data, content.readError
			}
			for _, provider := range cfg.Value.GetExtensionProviders() {
				_, _, tlsCfg := settings(provider)
				resolved.Materials[provider.Name] = resolveTLSMaterial(
					tlsCfg, namespace, lookup, lookupConfigMap, readFile)
			}
			return resolved
		},
		opts.WithName("ResolvedProviders")...)
}

// RegisterCollection applies every configuration the collection emits. The
// returned registration's WaitUntilSynced gates readiness on the initial
// configuration having been applied. Stopping the collection does not close
// the registry.
func (r *Registry) RegisterCollection(configs krt.Collection[Configuration]) krt.HandlerRegistration {
	return configs.Register(func(event krt.Event[Configuration]) {
		cfg := event.Latest()
		err := r.Apply(cfg.Value, cfg.Materials)
		if err != nil && !errors.Is(err, ErrClosed) {
			log.Log.WithName("epe-config").Error(err, "EPEConfig application failed")
		}
	})
}

type fileContent struct {
	data      []byte
	readError string
}

// fileDependencies watches only paths referenced by the effective configuration.
// Its periodic reload also covers optional volumes whose directory is absent.
type fileDependencies struct {
	trigger *krt.RecomputeTrigger
	paths   []string
	cancel  func()
	stop    <-chan struct{}
}

func newFileDependencies(stop <-chan struct{}, opts ...krt.CollectionOption) *fileDependencies {
	return &fileDependencies{trigger: krt.NewRecomputeTrigger(true, opts...), stop: stop}
}

// watch is called by the single effective-configuration transformation.
func (f *fileDependencies) watch(ctx krt.HandlerContext, paths []string) {
	slices.Sort(paths)
	paths = slices.Compact(paths)
	if len(paths) != 0 {
		f.trigger.MarkDependant(ctx)
	}
	if slices.Equal(paths, f.paths) {
		return
	}
	if f.cancel != nil {
		f.cancel()
		f.cancel = nil
	}
	f.paths = paths
	if len(paths) == 0 {
		return
	}
	stop := make(chan struct{})
	f.cancel = func() { close(stop) }
	done := make(chan struct{})
	events := certsource.WatchFiles(done, paths...)
	go func() {
		defer close(done)
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-f.stop:
				return
			case <-stop:
				return
			case <-events:
			case <-ticker.C:
			}
			f.trigger.TriggerRecomputation()
		}
	}()
}
