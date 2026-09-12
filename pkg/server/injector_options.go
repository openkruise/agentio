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

package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/openkruise/agentio/pkg/inject"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/kube/kclient"
	"github.com/openkruise/agentio/pkg/security/ca"
	"github.com/openkruise/agentio/pkg/security/mitm"
)

// SidecarInjectorOptions carries the injector wiring configuration assembled at
// the server composition root so tests can build the same components directly.
type SidecarInjectorOptions struct {
	// EnableClientTrust gates client CA distribution and injection at startup.
	// The injector's clientTrust.enabled setting must also be true.
	EnableClientTrust bool
	// Secrets is the registry's shared cache used by client CA Secret sources.
	Secrets krt.Collection[*corev1.Secret]
	// MITMTrustBundle exposes the signer's public CA updates for agentioMITM sources.
	// It may be nil when only other CA sources are configured.
	MITMTrustBundle krt.Singleton[mitm.TrustBundle]
	// ClientTrustPackagePath is the public CA package JSON file used by
	// defaultCAs sources.
	ClientTrustPackagePath string
	// Address is the HTTPS listen address; the chart's Service maps 443 to it.
	Address string
	// Namespace holds the injector ConfigMap.
	Namespace string
	// ConfigMapName carries the injection templates and values.
	ConfigMapName string
	// DiscoveryAddress is the Agentio xDS/CA endpoint placed into the ztunnel
	// template when injector values do not override it.
	DiscoveryAddress string
	// WebhookConfigName is the MutatingWebhookConfiguration whose caBundle is
	// kept in sync with the workload root; empty disables patching.
	WebhookConfigName string
	// NativeSidecarMode is true, false, or auto.
	NativeSidecarMode string
	// ReadHeaderTimeout bounds slow client headers.
	ReadHeaderTimeout time.Duration
}

func (o SidecarInjectorOptions) defaults() SidecarInjectorOptions {
	if o.Address == "" {
		o.Address = ":15017"
	}
	if o.ReadHeaderTimeout == 0 {
		o.ReadHeaderTimeout = 30 * time.Second
	}
	return o
}

// setupSidecarInjector wires the injection webhook, its ConfigMap watcher,
// the caBundle patcher, and the HTTPS server. KRT handler and server lifetimes
// are tied directly to ctx; the caller runs the returned serve function in its
// own goroutine so serve errors reach the process error channel.
func setupSidecarInjector(
	ctx context.Context,
	client kube.Client,
	authority *ca.Authority,
	options SidecarInjectorOptions,
) (func() error, error) {
	options = options.defaults()
	webhookMux := http.NewServeMux()
	nodes := kclient.NewFiltered[*corev1.Node](client, kclient.Filter{})
	injectionWebhook, err := inject.NewWebhook(inject.WebhookParameters{
		EnableClientTrust: options.EnableClientTrust,
		Nodes:             nodes,
		KrtOptions:        krt.NewOptionsBuilder(ctx.Done(), "", nil),
		NativeSidecarMode: inject.NativeSidecarMode(options.NativeSidecarMode),
		Mux:               webhookMux,
		DiscoveryAddress:  options.DiscoveryAddress,
	})
	if err != nil {
		return nil, err
	}
	injectorWatcher, err := inject.NewWatcher(client, injectionWebhook, inject.WatcherOptions{
		Namespace:             options.Namespace,
		InjectorConfigMapName: options.ConfigMapName,
	})
	if err != nil {
		return nil, err
	}
	go injectorWatcher.Run(ctx.Done())
	if options.EnableClientTrust {
		distributor, err := ca.NewClientTrustDistributor(client, ca.ClientTrustOptions{
			Namespace:       options.Namespace,
			PackagePath:     options.ClientTrustPackagePath,
			Configuration:   injectionWebhook.ClientTrustConfiguration(),
			MITMTrustBundle: options.MITMTrustBundle,
			Secrets:         options.Secrets,
		})
		if err != nil {
			return nil, err
		}
		go distributor.Run(ctx)
	}

	if options.WebhookConfigName != "" {
		caBundlePatcher, err := inject.NewCABundlePatcher(client, options.WebhookConfigName, authority.RootPEM)
		if err != nil {
			return nil, err
		}
		rotationWatch := authority.TrustBundles().Register(func(krt.Event[ca.TrustBundle]) {
			caBundlePatcher.Sync()
		})
		go func() {
			<-ctx.Done()
			rotationWatch.UnregisterHandler()
		}()
		go caBundlePatcher.Run(ctx.Done())
	}

	webhookTLS := authority.TLSConfig()
	webhookTLS.NextProtos = []string{"h2", "http/1.1"}
	webhookServer := &http.Server{
		Addr:              options.Address,
		Handler:           webhookMux,
		TLSConfig:         webhookTLS,
		ReadHeaderTimeout: options.ReadHeaderTimeout,
	}
	nodes.Start(ctx.Done())
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = webhookServer.Shutdown(shutdownCtx)
	}()
	serve := func() error {
		// Native-sidecar auto-detection reads the node cache; an empty
		// unsynced cache would report support on clusters without it, so the
		// listener waits for the initial node sync before accepting.
		if !kube.WaitForCacheSync("injection node cache", ctx.Done(), nodes.HasSynced) {
			return nil
		}
		if err := webhookServer.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
	return serve, nil
}
