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
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	securityapi "istio.io/api/security/v1alpha1"
	"k8s.io/client-go/rest"

	"github.com/openkruise/agentio/pkg/compiler"
	resolverdns "github.com/openkruise/agentio/pkg/dns"
	"github.com/openkruise/agentio/pkg/features"
	"github.com/openkruise/agentio/pkg/gatewaydeployer"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/metrics"
	"github.com/openkruise/agentio/pkg/model"
	kubernetesregistry "github.com/openkruise/agentio/pkg/registry/kubernetes"
	"github.com/openkruise/agentio/pkg/security/attestation"
	"github.com/openkruise/agentio/pkg/security/ca"
	"github.com/openkruise/agentio/pkg/security/mitm"
	"github.com/openkruise/agentio/pkg/server/debug"
	"github.com/openkruise/agentio/pkg/xds"
	xdsstore "github.com/openkruise/agentio/pkg/xds/store"
)

func Run(ctx context.Context, options Options, opts ...Option) error {
	return withRunContext(ctx, func(runCtx context.Context) error {
		return run(runCtx, options, opts...)
	})
}

func withRunContext(parent context.Context, run func(context.Context) error) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	return run(ctx)
}

func grpcServerKeepaliveParameters() keepalive.ServerParameters {
	return keepalive.ServerParameters{
		MaxConnectionAge:      features.MaxServerConnectionAge,
		MaxConnectionAgeGrace: 10 * time.Second,
		MaxConnectionIdle:     30 * time.Minute,
		Time:                  2 * time.Hour,
		Timeout:               20 * time.Second,
	}
}

func kubernetesRESTConfig(kubeconfigPath string) (*rest.Config, error) {
	config, err := kube.LoadConfig(kubeconfigPath)
	if err != nil {
		return nil, err
	}
	config.QPS = float32(features.KubernetesAPIQPS)
	config.Burst = features.KubernetesAPIBurst
	return config, nil
}

func run(ctx context.Context, options Options, opts ...Option) error {
	started := time.Now()
	composition := applyOptions(opts)
	if err := options.Validate(); err != nil {
		return err
	}
	if err := features.Validate(); err != nil {
		return err
	}
	ztunnelAccount, err := trustedNodeServiceAccount(options.RootNamespace, features.ZTunnelAccount)
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return nil
	}
	logStartup(options)
	config, err := kubernetesRESTConfig(options.Kubeconfig)
	if err != nil {
		return err
	}
	kubeClient, err := kube.NewClient(config)
	if err != nil {
		return err
	}
	kubeClient = kube.EnableCrdWatcher(kubeClient, kube.CrdWatcherOptions{
		IgnoreResources:  features.IgnoreResources,
		IncludeResources: features.IncludeResources,
	})
	kubeCoreClient := kubeClient.Kube()
	krtBuilder := krt.NewOptionsBuilder(ctx.Done(), "", nil)
	tokenReviewer, err := attestation.NewTokenReviewer(kubeCoreClient, options.TrustDomain, []string{features.TokenAudience})
	if err != nil {
		return err
	}
	authenticatorChain := mergeAuthenticators(
		attestation.AuthenticatorChain{tokenReviewer}, composition.authenticators)
	// The registered attestation set is the scope-function key set; the
	// functions themselves are composed later, once the registry exists.
	registeredAttestations := []model.Attestation{model.AttestationKubernetes}
	for attestation := range composition.scopeFuncs {
		if attestation != model.AttestationKubernetes {
			registeredAttestations = append(registeredAttestations, attestation)
		}
	}
	authenticator, err := attestation.NewRegisteredAttestationAuthenticator(
		authenticatorChain, registeredAttestations)
	if err != nil {
		return err
	}
	authority, err := ca.LoadOrCreateAuthority(ctx, kubeClient, authenticator, ca.AuthorityOptions{
		Namespace:                 options.RootNamespace,
		SecretName:                features.CASecretName,
		ConfigMapName:             features.CAConfigMapName,
		ServiceName:               features.ServiceName,
		TrustedNodeServiceAccount: ztunnelAccount,
		LeafLifetime:              features.WorkloadCertLifetime,
		LeafRenewBefore:           features.WorkloadCertRenewBefore,
		LeaseName:                 features.CALeaseName,
		RootLifetime:              features.CARootLifetime,
		RenewBefore:               features.CARenewBefore,
		RotationCheckInterval:     features.CARotationCheckInterval,
		KrtOptions:                krtBuilder,
	})
	if err != nil {
		return err
	}
	trustBundleDistributor, err := ca.NewTrustBundleDistributor(kubeClient, authority, ca.TrustBundleDistributorOptions{
		Namespace:     options.RootNamespace,
		ConfigMapName: features.TrustBundleConfigMapName,
		LeaseName:     features.TrustBundleLeaseName,
	})
	if err != nil {
		return err
	}
	registry, err := kubernetesregistry.New(kubeClient, kubernetesregistry.Options{
		SandboxMode:           features.SandboxMode,
		ClusterID:             options.ClusterID,
		TrustDomain:           options.TrustDomain,
		RootNamespace:         options.RootNamespace,
		ZTunnelServiceAccount: ztunnelAccount,
		ScopedSecrets:         features.ScopedSecrets,
		AgentioConfigMaps: &kubernetesregistry.AgentioConfigMapOptions{
			BaseName:    features.AgentioConfigMapName,
			PrimaryName: features.PrimaryAgentioConfigMapName,
		},
		ClusterDomain: options.ClusterDomain,
		DebounceAfter: features.KRTDebounceAfter,
		DebounceMax:   features.KRTDebounceMax,
	}, ctx.Done())
	if err != nil {
		return err
	}
	krtOptions := []krt.CollectionOption{krt.WithStop(ctx.Done())}
	sources, err := applySourceCollectionTransforms(SourceCollections{
		Sandboxes:                  registry.Sandboxes,
		Workloads:                  registry.Workloads,
		Services:                   registry.Services,
		Endpoints:                  registry.Endpoints,
		Gateways:                   registry.Gateways,
		TrafficPolicies:            registry.TrafficPolicies,
		SecurityProfiles:           registry.SecurityProfiles,
		GatewayPatches:             registry.GatewayPatches,
		Telemetry:                  registry.Telemetry,
		TelemetryProviderOverrides: registry.TelemetryProviderOverrides,
		AgentioConfig:              registry.AgentioConfig,
	}, composition.sourceCollectionTransforms)
	if err != nil {
		return err
	}
	delegatedAuthorizers := mergeDelegatedAuthorizers(attestation.DelegatedIdentityAuthorizers{
		model.AttestationKubernetes: registry.DelegatedIdentityAuthorizer(),
	}, composition.delegatedIdentityAuthorizers)
	authority.UseDelegatedIdentityAuthorizer(delegatedAuthorizers)
	go trustBundleDistributor.Run(ctx)

	if features.EnableGatewayDeployer {
		deployer, err := gatewaydeployer.New(kubeClient, gatewaydeployer.Options{
			ClusterID:             options.ClusterID,
			SystemNamespace:       options.RootNamespace,
			InjectorConfigMapName: features.InjectorConfigMapName,
			TrustDomain:           options.TrustDomain,
			ClusterDomain:         options.ClusterDomain,
			CAAddress:             fmt.Sprintf("%s.%s.svc:15012", features.ServiceName, options.RootNamespace),
			LeaseName:             features.GatewayLeaseName,
		})
		if err != nil {
			return err
		}
		go deployer.Run(ctx)
	}

	resolver, err := resolverdns.New(ctx, resolverdns.Options{}, nil, append(krtOptions, krt.WithName("dns-results"))...)
	if err != nil {
		return err
	}
	// Resolve results are normal krt objects keyed by hostname. The separate
	// reference collection keeps refresh work bounded to names still used by a
	// TrafficPolicy or AgentioConfig.
	dnsReferences := resolverdns.NewReferences(sources.TrafficPolicies, sources.AgentioConfig, krtOptions...)
	dnsReferenceRegistration := resolver.Track(dnsReferences)
	defer dnsReferenceRegistration.UnregisterHandler()
	resourceCompiler, err := compiler.New(compiler.Inputs{
		SandboxMode:                features.SandboxMode,
		ClusterID:                  options.ClusterID,
		RootNamespace:              options.RootNamespace,
		Sandboxes:                  sources.Sandboxes,
		Workloads:                  sources.Workloads,
		Pods:                       registry.Pods,
		KubernetesServices:         registry.KubernetesServices,
		EndpointSlices:             registry.EndpointSlices,
		Services:                   sources.Services,
		Endpoints:                  sources.Endpoints,
		Gateways:                   sources.Gateways,
		TrafficPolicies:            sources.TrafficPolicies,
		SecurityProfiles:           sources.SecurityProfiles,
		GatewayPatches:             sources.GatewayPatches,
		Telemetry:                  sources.Telemetry,
		TelemetryProviderOverrides: sources.TelemetryProviderOverrides,
		AgentioConfig:              sources.AgentioConfig,
		Resolve:                    resolver.Resolve,
		DiscoveryAddress:           features.ServiceName + ":15012",
		TrustDomain:                options.TrustDomain,
	}, krtBuilder)
	if err != nil {
		return err
	}
	empty, err := model.NewResourceSet(nil)
	if err != nil {
		return err
	}
	store := xdsstore.New(empty)
	var domainSigner mitm.DomainSignerSource
	if composition.domainSigner == nil {
		mitmSecretNamespace := strings.TrimSpace(features.MITMCASecretNamespace)
		if mitmSecretNamespace == "" {
			mitmSecretNamespace = options.RootNamespace
		}
		builtInSigner, err := mitm.NewMITMSigner(ctx, kubeClient, mitm.MITMSignerOptions{
			Mode:                  mitm.MITMSignMode(features.MITMSignMode),
			Namespace:             mitmSecretNamespace,
			SecretName:            features.MITMCASecretName,
			RootLifetime:          features.MITMRootLifetime,
			RootRenewBefore:       features.MITMRootRenewBefore,
			RotationCheckInterval: features.MITMRotationCheckInterval,
			LeafExpiryMargin:      features.MITMRenewBefore,
			KrtOptions:            krtBuilder,
		})
		if err != nil {
			return err
		}
		domainSigner = mitm.DomainSignerSource{
			Signer:      builtInSigner,
			State:       builtInSigner.State(),
			TrustBundle: builtInSigner.TrustBundles(),
		}
	} else {
		domainSigner = *composition.domainSigner
	}
	onDemandIssuer, err := mitm.NewOnDemandIssuer(ctx, domainSigner,
		kubernetesregistry.NewGatewayCertificateAuthorizer(resourceCompiler.Gateways()), mitm.OnDemandOptions{
			LeafLifetime:    features.MITMLeafLifetime,
			RenewBefore:     features.MITMRenewBefore,
			CacheMaxAge:     features.MITMCacheMaxAge,
			CacheMaxEntries: features.MITMCacheMaxEntries,
			SignConcurrency: features.MITMSignConcurrency,
			KrtOptions:      krtBuilder,
		})
	if err != nil {
		return err
	}
	secretChanges := onDemandIssuer.Changes().AsCollection().RegisterBatch(
		func([]krt.Event[mitm.CertificateGeneration]) { store.NotifyType(model.SecretType) }, false)
	defer secretChanges.UnregisterHandler()
	controller, err := xds.NewController(resourceCompiler, store, features.PushDebounceAfter, features.PushDebounceMax)
	if err != nil {
		return err
	}
	var ready atomic.Bool
	scopeFuncs, err := mergeScopeFuncs(xds.ScopeFuncs{
		model.AttestationKubernetes: xds.KubernetesScopeFunc(registry.PodScopeResolver(sources.Workloads)),
	}, composition.scopeFuncs)
	if err != nil {
		return err
	}

	workloadGenerator := xds.WorkloadGenerator{}
	sdsGenerator, err := xds.NewSDSGenerator(onDemandIssuer)
	if err != nil {
		return err
	}
	discoveryServer, err := xds.NewServer(
		authenticator,
		scopeFuncs,
		store,
		ready.Load,
		features.ClientQueueSize,
		map[string]xds.ResourceGenerator{
			model.AddressType:               workloadGenerator,
			model.WorkloadType:              workloadGenerator,
			model.WorkloadAuthorizationType: xds.AuthorizationGenerator{},
			model.SandboxType:               xds.SandboxGenerator{},
			model.SecretType:                sdsGenerator,
		},
		features.PushConcurrency,
		features.RequestRateLimit,
	)
	if err != nil {
		return err
	}
	defer discoveryServer.Close()
	grpcServer := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(authority.TLSConfig())),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             30 * time.Second,
			PermitWithoutStream: true,
		}),
		// MaxConnectionAge forces periodic reconnect and re-authentication;
		// MaxConnectionIdle alone never fires while a stream is open.
		grpc.KeepaliveParams(grpcServerKeepaliveParameters()),
	)
	discoveryv3.RegisterAggregatedDiscoveryServiceServer(grpcServer, discoveryServer)
	securityapi.RegisterIstioCertificateServiceServer(grpcServer, authority)

	discoveryListener, err := net.Listen("tcp", options.DiscoveryAddress)
	if err != nil {
		return fmt.Errorf("listen for xDS: %w", err)
	}
	defer discoveryListener.Close()
	var debugHandler http.Handler
	if features.EnableDebugOnHTTP {
		debugHandler = debug.NewHandler(debug.Sources{
			AgentioConfig:    sources.AgentioConfig,
			TrafficPolicies:  sources.TrafficPolicies,
			SecurityProfiles: sources.SecurityProfiles,
			Gateways:         sources.Gateways,
			GatewayPatches:   sources.GatewayPatches,
			Telemetry:        sources.Telemetry,
		}, resourceCompiler, authenticator, options.RootNamespace)
	}
	healthServer := &http.Server{
		Addr:              options.MonitoringAddress,
		Handler:           newMonitoringHandler(ready.Load, debugHandler),
		ReadHeaderTimeout: 5 * time.Second,
	}
	defer func() { _ = healthServer.Shutdown(context.Background()) }()
	var injectorServe func() error
	if features.EnableSidecarInjector {
		injectorOptions := SidecarInjectorOptions{
			EnableClientTrust:      features.EnableClientTrustDistributor,
			Secrets:                registry.Secrets,
			MITMTrustBundle:        domainSigner.TrustBundle,
			ClientTrustPackagePath: features.ClientTrustPackagePath,
			Namespace:              options.RootNamespace,
			ConfigMapName:          features.InjectorConfigMapName,
			WebhookConfigName:      features.InjectionWebhookConfigName,
			NativeSidecarMode:      features.NativeSidecarMode,
			DiscoveryAddress:       fmt.Sprintf("%s.%s.svc.%s:15012", features.ServiceName, options.RootNamespace, options.ClusterDomain),
		}
		serve, err := setupSidecarInjector(ctx, kubeClient, authority, injectorOptions)
		if err != nil {
			return err
		}
		injectorServe = serve
	}

	errorsChannel := make(chan error, 4)
	// Start the process-wide Kubernetes client only after every source and
	// controller has had a chance to register its shared informers. Registry is
	// one consumer of this client; it does not own the client lifecycle.
	kubeClient.Run(ctx.Done())
	go func() {
		if err := healthServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errorsChannel <- fmt.Errorf("serve health endpoint: %w", err)
		}
	}()

	if injectorServe != nil {
		go func() {
			if err := injectorServe(); err != nil {
				errorsChannel <- fmt.Errorf("serve sidecar injection webhook: %w", err)
			}
		}()
	}

	// The derived collections are filled asynchronously, so the compiler has its
	// own sync barrier beyond the informer caches. Publishing before it is
	// reached would ship a partial configuration.
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	nextSyncLog := time.Now().Add(10 * time.Second)
	for !registry.HasSynced() || !resourceCompiler.HasSynced() {
		select {
		case <-ctx.Done():
			_ = healthServer.Shutdown(context.Background())
			return nil
		case err := <-errorsChannel:
			return err
		case <-ticker.C:
		}
		if time.Now().After(nextSyncLog) {
			log.Info("waiting for initial configuration sync", "elapsed", time.Since(started),
				"registry_synced", registry.HasSynced(), "compiler_synced", resourceCompiler.HasSynced())
			nextSyncLog = time.Now().Add(10 * time.Second)
		}
	}
	initial, err := resourceCompiler.Snapshot()
	if err != nil {
		return fmt.Errorf("compile initial configuration: %w", err)
	}
	store.Replace(initial)
	ready.Store(true)
	go func() { errorsChannel <- controller.Run(ctx) }()
	go func() {
		if err := grpcServer.Serve(discoveryListener); err != nil {
			errorsChannel <- fmt.Errorf("serve xDS: %w", err)
		}
	}()
	log.Info("agentiod ready", "xds_address", options.DiscoveryAddress,
		"monitoring_address", options.MonitoringAddress, "snapshot", initial.Version(),
		"startup_duration", time.Since(started), "resources", initial.Len(), "resources_by_type", initial.CountsByType())

	select {
	case <-ctx.Done():
		ready.Store(false)
		shutdown(grpcServer, healthServer)
		return nil
	case err := <-errorsChannel:
		ready.Store(false)
		shutdown(grpcServer, healthServer)
		if err == nil && ctx.Err() != nil {
			return nil
		}
		return err
	}
}

func newMonitoringHandler(ready func() bool, debugHandler http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/ready", func(response http.ResponseWriter, _ *http.Request) {
		if !ready() {
			http.Error(response, "not ready", http.StatusServiceUnavailable)
			return
		}
		response.WriteHeader(http.StatusOK)
	})
	mux.Handle("/metrics", metrics.Default)
	if debugHandler != nil {
		mux.Handle(debug.Path, debugHandler)
		mux.Handle(debug.LoggingPath, debugHandler)
		mux.Handle(debug.LoggingPath+"/", debugHandler)
	}
	return mux
}

func shutdown(grpcServer *grpc.Server, healthServer *http.Server) {
	done := make(chan struct{})
	go func() {
		grpcServer.GracefulStop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		grpcServer.Stop()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = healthServer.Shutdown(ctx)
}
