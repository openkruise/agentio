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
	"math"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	securityapi "istio.io/api/security/v1alpha1"
	corev1 "k8s.io/api/core/v1"

	"github.com/openkruise/agentio/pkg/clienttrust"
	"github.com/openkruise/agentio/pkg/compiler"
	resolverdns "github.com/openkruise/agentio/pkg/dns/controller"
	"github.com/openkruise/agentio/pkg/features"
	"github.com/openkruise/agentio/pkg/gatewaydeployer"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/metrics"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/policystatus"
	kubernetesregistry "github.com/openkruise/agentio/pkg/registry/kubernetes"
	"github.com/openkruise/agentio/pkg/security/attestation"
	"github.com/openkruise/agentio/pkg/security/ca"
	"github.com/openkruise/agentio/pkg/security/mitm"
	"github.com/openkruise/agentio/pkg/server/debug"
	"github.com/openkruise/agentio/pkg/xds"
	xdsstore "github.com/openkruise/agentio/pkg/xds/store"
)

// Run starts the Agentio control plane and serves until shutdown or a server error.
func Run(shutdownCtx context.Context, options Options, opts ...Option) error {
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
	if shutdownCtx.Err() != nil {
		return nil
	}
	ctx, finishStartup, cancel := newRunContext(shutdownCtx)
	defer cancel()
	logStartup(options)
	gatewayTrustBundle, err := loadGatewayTrustBundle(features.ClientTrustPackagePath)
	if err != nil {
		return err
	}
	plane, err := newControlPlane(ctx, options, composition, ztunnelAccount, started)
	if err != nil {
		return err
	}
	if features.EnableGatewayDeployer {
		if err := plane.startGatewayDeployer(ctx, gatewayTrustBundle); err != nil {
			return err
		}
	}

	krtOptions := []krt.CollectionOption{krt.WithStop(ctx.Done())}
	resolver, err := resolverdns.New(
		ctx,
		resolverdns.Options{},
		nil,
		append(krtOptions, krt.WithName("dns-results"))...)
	if err != nil {
		return err
	}
	// Resolve results are normal krt objects keyed by hostname. The separate
	// reference collection keeps refresh work bounded to names still used by a
	// TrafficPolicy or AgentioConfig.
	dnsReferences := resolverdns.NewReferences(
		plane.sources.TrafficPolicies,
		plane.sources.AgentioConfig,
		krtOptions...)
	dnsReferenceRegistration := resolver.Track(dnsReferences)
	defer dnsReferenceRegistration.UnregisterHandler()
	plane.compiler, err = plane.newResourceCompiler(resolver, gatewayTrustBundle)
	if err != nil {
		return err
	}
	if features.EnablePolicyStatus {
		statusController, err := policystatus.New(plane.kubeClient, plane.registry, options.RootNamespace,
			features.ScopedSecrets, resolver.Resolve, ctx.Done())
		if err != nil {
			return err
		}
		go statusController.Run(ctx)
	}
	return plane.serve(ctx, shutdownCtx, finishStartup, cancel)
}

type controlPlane struct {
	options              Options
	composition          composition
	kubeClient           kube.Client
	registry             *kubernetesregistry.Registry
	sources              SourceCollections
	krtBuilder           krt.OptionsBuilder
	authenticator        attestation.Authenticator
	authenticationSynced func() bool
	authority            *ca.Authority
	compiler             *compiler.Compiler
	started              time.Time
	ready                atomic.Bool
}

func newRunContext(shutdown context.Context) (context.Context, func() bool, func()) {
	ctx, cancel := context.WithCancel(context.WithoutCancel(shutdown))
	cancelStartup := context.AfterFunc(shutdown, cancel)
	// Once serving, keep dependencies alive until gRPC drains.
	finishStartup := func() bool { return cancelStartup() && shutdown.Err() == nil }
	stop := func() {
		cancelStartup()
		cancel()
	}
	return ctx, finishStartup, stop
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

func loadGatewayTrustBundle(packagePath string) (string, error) {
	data, err := os.ReadFile(packagePath)
	if err != nil {
		return "", fmt.Errorf("read gateway trust package: %w", err)
	}
	p, err := clienttrust.ParsePackage(data)
	if err != nil {
		return "", fmt.Errorf("parse gateway trust package: %w", err)
	}
	return p.Bundle, nil
}

func newControlPlane(
	ctx context.Context,
	options Options,
	composition composition,
	ztunnelAccount string,
	started time.Time,
) (*controlPlane, error) {
	kubeClient, registry, err := newKubernetesRegistry(ctx, options, ztunnelAccount)
	if err != nil {
		return nil, err
	}
	authenticator, authenticationSynced, err := newWorkloadAuthenticator(ctx, kubeClient, registry, composition)
	if err != nil {
		return nil, err
	}
	krtBuilder := krt.NewOptionsBuilder(ctx.Done(), "", nil)
	authority, err := ca.LoadOrCreateAuthority(ctx, kubeClient, authenticator, ca.AuthorityOptions{
		TrustDomain:           options.TrustDomain,
		ClusterDomain:         options.ClusterDomain,
		Namespace:             options.RootNamespace,
		SecretName:            features.CASecretName,
		ConfigMapName:         features.CAConfigMapName,
		ServiceName:           features.ServiceName,
		LeafLifetime:          features.WorkloadCertLifetime,
		LeafRenewBefore:       features.WorkloadCertRenewBefore,
		LeaseName:             features.CALeaseName,
		RootLifetime:          features.CARootLifetime,
		RenewBefore:           features.CARenewBefore,
		RotationCheckInterval: features.CARotationCheckInterval,
		KrtOptions:            krtBuilder,
	})
	if err != nil {
		return nil, err
	}
	trustBundleDistributor, err := ca.NewTrustBundleDistributor(kubeClient, authority, ca.TrustBundleDistributorOptions{
		Namespace:     options.RootNamespace,
		ConfigMapName: features.TrustBundleConfigMapName,
		LeaseName:     features.TrustBundleLeaseName,
	})
	if err != nil {
		return nil, err
	}
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
		return nil, err
	}
	delegatedAuthorizers := mergeDelegatedAuthorizers(attestation.DelegatedIdentityAuthorizers{
		model.AttestationKubernetes: registry.DelegatedIdentityAuthorizer(),
	}, composition.delegatedIdentityAuthorizers)
	authority.UseDelegatedIdentityAuthorizer(delegatedAuthorizers)
	go trustBundleDistributor.Run(ctx)
	return &controlPlane{
		options:              options,
		composition:          composition,
		kubeClient:           kubeClient,
		registry:             registry,
		sources:              sources,
		krtBuilder:           krtBuilder,
		authenticator:        authenticator,
		authenticationSynced: authenticationSynced,
		authority:            authority,
		started:              started,
	}, nil
}

func newKubernetesRegistry(
	ctx context.Context,
	options Options,
	ztunnelAccount string,
) (kube.Client, *kubernetesregistry.Registry, error) {
	config, err := kube.LoadConfig(options.Kubeconfig)
	if err != nil {
		return nil, nil, err
	}
	kubeClient, err := kube.NewClient(config)
	if err != nil {
		return nil, nil, err
	}
	kubeClient = kube.EnableCrdWatcher(kubeClient, kube.CrdWatcherOptions{
		IgnoreResources:  features.IgnoreResources,
		IncludeResources: features.IncludeResources,
	})
	registry, err := kubernetesregistry.New(kubeClient, kubernetesregistry.Options{
		EnableKruise:          features.SandboxMode,
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
		return nil, nil, err
	}
	return kubeClient, registry, nil
}

func newWorkloadAuthenticator(
	ctx context.Context,
	kubeClient kube.Client,
	registry *kubernetesregistry.Registry,
	composition composition,
) (attestation.Authenticator, func() bool, error) {
	var err error
	var kubernetesAuthenticator attestation.Authenticator
	authenticationSynced := func() bool { return true }
	if features.KubernetesWorkloadAuthMode == "local" {
		accounts := krt.NewInformer[*corev1.ServiceAccount](
			kubeClient,
			krt.WithStop(ctx.Done()),
			krt.WithName("authentication-serviceaccounts"),
		)
		kubernetesAuthenticator, err = attestation.NewLocalJWTAuthenticator(
			ctx,
			kubeClient.Kube().CoreV1().RESTClient(),
			registry.Pods,
			accounts,
			features.TokenAudience,
		)
		authenticationSynced = accounts.HasSynced
	} else {
		kubernetesAuthenticator, err = attestation.NewTokenReviewer(kubeClient.Kube(), []string{features.TokenAudience})
	}
	if err != nil {
		return nil, nil, err
	}
	authenticatorChain := mergeAuthenticators(
		attestation.AuthenticatorChain{kubernetesAuthenticator}, composition.authenticators)
	// The registered attestation set is the scope-function key set; the
	// functions themselves are composed later, once the registry exists.
	registeredAttestations := []model.Attestation{model.AttestationKubernetes}
	for attestation := range composition.scopeFuncs {
		if attestation != model.AttestationKubernetes {
			registeredAttestations = append(registeredAttestations, attestation)
		}
	}
	authenticator, err := attestation.NewRegisteredAttestationAuthenticator(authenticatorChain, registeredAttestations)
	return authenticator, authenticationSynced, err
}

func (p *controlPlane) startGatewayDeployer(ctx context.Context, gatewayTrustBundle string) error {
	options := p.options
	deployer, err := gatewaydeployer.New(p.kubeClient, gatewaydeployer.Options{
		ClusterID:             options.ClusterID,
		SystemNamespace:       options.RootNamespace,
		InjectorConfigMapName: features.InjectorConfigMapName,
		TrustDomain:           options.TrustDomain,
		ClusterDomain:         options.ClusterDomain,
		CAAddress:             fmt.Sprintf("%s.%s.svc:15012", features.ServiceName, options.RootNamespace),
		LeaseName:             features.GatewayLeaseName,
		Agentgateway: gatewaydeployer.AgentgatewaySources{
			Config:      p.sources.AgentioConfig,
			Services:    p.sources.Services,
			Endpoints:   p.sources.Endpoints,
			Secrets:     p.registry.Secrets,
			TrustBundle: gatewayTrustBundle,
		},
	})
	if err != nil {
		return err
	}
	go deployer.Run(ctx)
	return nil
}

func (p *controlPlane) newResourceCompiler(
	resolver *resolverdns.Resolver,
	gatewayTrustBundle string,
) (*compiler.Compiler, error) {
	options, registry, sources := p.options, p.registry, p.sources
	return compiler.New(compiler.Inputs{
		SandboxMode:                features.SandboxMode,
		ClusterID:                  options.ClusterID,
		RootNamespace:              options.RootNamespace,
		Sandboxes:                  sources.Sandboxes.Collection,
		Workloads:                  sources.Workloads,
		Pods:                       registry.Pods,
		KubernetesServices:         registry.KubernetesServices,
		EndpointSlices:             registry.EndpointSlices,
		ConfigMaps:                 registry.ConfigMaps,
		Secrets:                    registry.Secrets,
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
		GatewayTrustBundle:         gatewayTrustBundle,
	}, p.krtBuilder)
}

func (p *controlPlane) serve(
	ctx context.Context,
	shutdownCtx context.Context,
	finishStartup func() bool,
	cancel func(),
) error {
	empty, err := model.NewResourceSet(nil)
	if err != nil {
		return err
	}
	store := xdsstore.New(empty)
	domainSigner, err := p.newDomainSigner(ctx)
	if err != nil {
		return err
	}
	onDemandIssuer, err := mitm.NewOnDemandIssuer(ctx, domainSigner,
		kubernetesregistry.NewGatewayCertificateAuthorizer(p.compiler.Gateways()), mitm.OnDemandOptions{
			LeafLifetime:    features.MITMLeafLifetime,
			ResourceTTL:     features.MITMResourceTTL,
			RenewBefore:     features.MITMRenewBefore,
			CacheMaxAge:     features.MITMCacheMaxAge,
			CacheMaxEntries: features.MITMCacheMaxEntries,
			SignConcurrency: features.MITMSignConcurrency,
			KrtOptions:      p.krtBuilder,
		})
	if err != nil {
		return err
	}
	secretChanges := onDemandIssuer.Changes().AsCollection().RegisterBatch(
		func([]krt.Event[mitm.CertificateGeneration]) { store.NotifyType(model.SecretType) }, false)
	defer secretChanges.UnregisterHandler()
	sandboxSources := p.sources.Sandboxes.Registry
	unregisterSourceDeletes := sandboxSources.RegisterDeletes(store.NotifyKeys)
	defer unregisterSourceDeletes()
	controller, err := xds.NewController(p.compiler, store, features.PushDebounceAfter, features.PushDebounceMax)
	if err != nil {
		return err
	}
	discoveryServer, err := p.newDiscoveryServer(store, onDemandIssuer)
	if err != nil {
		return err
	}
	defer discoveryServer.Close()
	grpcServer := grpc.NewServer(
		grpc.MaxRecvMsgSize(math.MaxInt32),
		grpc.Creds(credentials.NewTLS(p.authority.TLSConfig())),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             30 * time.Second,
			PermitWithoutStream: true,
		}),
		// MaxConnectionAge forces periodic reconnect and re-authentication;
		// MaxConnectionIdle alone never fires while a stream is open.
		grpc.KeepaliveParams(grpcServerKeepaliveParameters()),
	)
	discoveryv3.RegisterAggregatedDiscoveryServiceServer(grpcServer, discoveryServer)
	securityapi.RegisterIstioCertificateServiceServer(grpcServer, p.authority)

	discoveryListener, err := net.Listen("tcp", p.options.DiscoveryAddress)
	if err != nil {
		return fmt.Errorf("listen for xDS: %w", err)
	}
	defer discoveryListener.Close()

	healthServer := p.newMonitoringServer()
	defer shutdownHTTP(healthServer, 5*time.Second)
	injectorServe, err := p.setupWebhooks(ctx, domainSigner)
	if err != nil {
		return err
	}

	errorsChannel := make(chan error, 4)
	// Start the process-wide Kubernetes client only after every source and
	// controller has had a chance to register its shared informers. Registry is
	// one consumer of this client; it does not own the client lifecycle.
	p.kubeClient.Run(ctx.Done())
	serveHTTP(healthServer, injectorServe, errorsChannel)

	synced, err := p.waitForInitialSync(ctx, errorsChannel)
	if err != nil || !synced {
		return err
	}
	initial, err := p.compiler.Snapshot()
	if err != nil {
		return fmt.Errorf("compile initial configuration: %w", err)
	}
	store.Replace(initial)
	if !finishStartup() {
		return nil
	}
	p.startDiscovery(ctx, controller, grpcServer, discoveryListener, initial, errorsChannel)

	var runErr error
	select {
	case <-shutdownCtx.Done():
	case runErr = <-errorsChannel:
	}
	p.ready.Store(false)
	shutdown(grpcServer)
	cancel()
	return runErr
}

func serveHTTP(healthServer *http.Server, injectorServe func() error, errorsChannel chan<- error) {
	go func() {
		if err := healthServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errorsChannel <- fmt.Errorf("serve health endpoint: %w", err)
		}
	}()

	if injectorServe != nil {
		go func() {
			if err := injectorServe(); err != nil {
				errorsChannel <- fmt.Errorf("serve admission webhooks: %w", err)
			}
		}()
	}
}

func (p *controlPlane) startDiscovery(
	ctx context.Context,
	controller *xds.Controller,
	grpcServer *grpc.Server,
	discoveryListener net.Listener,
	initial model.ResourceSet,
	errorsChannel chan<- error,
) {
	p.ready.Store(true)
	go func() { errorsChannel <- controller.Run(ctx) }()
	go func() {
		if err := grpcServer.Serve(discoveryListener); err != nil {
			errorsChannel <- fmt.Errorf("serve xDS: %w", err)
		}
	}()
	log.Info(
		"agentiod ready",
		"xds_address",
		p.options.DiscoveryAddress,
		"monitoring_address",
		p.options.MonitoringAddress,
		"snapshot",
		initial.Version(),
		"startup_duration",
		time.Since(p.started),
		"resources",
		initial.Len(),
		"resources_by_type",
		initial.CountsByType(),
	)
}

func (p *controlPlane) newDomainSigner(ctx context.Context) (mitm.DomainSignerSource, error) {
	if p.composition.domainSigner != nil {
		return *p.composition.domainSigner, nil
	}
	mitmSecretNamespace := strings.TrimSpace(features.MITMCASecretNamespace)
	if mitmSecretNamespace == "" {
		mitmSecretNamespace = p.options.RootNamespace
	}
	builtInSigner, err := mitm.NewMITMSigner(ctx, p.kubeClient, mitm.MITMSignerOptions{
		Mode:                  mitm.MITMSignMode(features.MITMSignMode),
		Namespace:             mitmSecretNamespace,
		SecretName:            features.MITMCASecretName,
		RootLifetime:          features.MITMRootLifetime,
		RootRenewBefore:       features.MITMRootRenewBefore,
		RotationCheckInterval: features.MITMRotationCheckInterval,
		LeafExpiryMargin:      features.MITMRenewBefore,
		KrtOptions:            p.krtBuilder,
	})
	if err != nil {
		return mitm.DomainSignerSource{}, err
	}
	return mitm.DomainSignerSource{
		Signer:      builtInSigner,
		State:       builtInSigner.State(),
		TrustBundle: builtInSigner.TrustBundles(),
	}, nil
}

func (p *controlPlane) newDiscoveryServer(
	store *xdsstore.Store,
	onDemandIssuer *mitm.OnDemandIssuer,
) (*xds.Server, error) {
	scopeFuncs, err := mergeScopeFuncs(xds.ScopeFuncs{
		model.AttestationKubernetes: xds.KubernetesScopeFunc(p.registry.PodScopeResolver(p.sources.Workloads)),
	}, p.composition.scopeFuncs)
	if err != nil {
		return nil, err
	}

	workloadGenerator := xds.WorkloadGenerator{}
	sdsGenerator, err := xds.NewSDSGenerator(onDemandIssuer)
	if err != nil {
		return nil, err
	}
	return xds.NewServer(
		p.authenticator,
		scopeFuncs,
		store,
		p.ready.Load,
		features.ClientQueueSize,
		map[string]xds.ResourceGenerator{
			model.AddressType:               workloadGenerator,
			model.WorkloadType:              workloadGenerator,
			model.WorkloadAuthorizationType: xds.AuthorizationGenerator{},
			model.TrafficPolicyType:         xds.TrafficPolicyGenerator{},
			model.SecurityProfileType:       xds.SecurityProfileGenerator{},
			model.SandboxType:               xds.SandboxGenerator{Source: p.sources.Sandboxes.Registry},
			model.SecretType:                sdsGenerator,
		},
		features.PushConcurrency,
		features.RequestRateLimit,
		xds.FlowControlOptions{
			InitialAdmission: features.XDSInitialAdmissionTimeout,
			RateLimit:        features.XDSRateLimitTimeout,
			Send:             features.XDSSendTimeout,
			ACK:              features.XDSACKTimeout,
			MaxPodStreams:    features.XDSMaxPodStreams,
		},
	)
}

func (p *controlPlane) newMonitoringServer() *http.Server {
	var debugHandler http.Handler
	if features.EnableDebugOnHTTP {
		debugHandler = debug.NewHandler(debug.Sources{
			AgentioConfig:    p.sources.AgentioConfig,
			TrafficPolicies:  p.sources.TrafficPolicies,
			SecurityProfiles: p.sources.SecurityProfiles,
			Gateways:         p.sources.Gateways,
			GatewayPatches:   p.sources.GatewayPatches,
			Telemetry:        p.sources.Telemetry,
		}, p.compiler, p.authenticator, p.options.RootNamespace)
	}
	return &http.Server{
		Addr:              p.options.MonitoringAddress,
		Handler:           newMonitoringHandler(p.ready.Load, debugHandler),
		ReadHeaderTimeout: 5 * time.Second,
	}
}

func (p *controlPlane) setupWebhooks(ctx context.Context, domainSigner mitm.DomainSignerSource) (func() error, error) {
	if !features.EnableSidecarInjector && features.ValidationWebhookConfigName == "" {
		return nil, nil
	}
	options := p.options
	injectorOptions := SidecarInjectorOptions{
		EnableInjection:             features.EnableSidecarInjector,
		ValidationWebhookConfigName: features.ValidationWebhookConfigName,
		EnableClientTrust:           features.EnableClientTrustDistributor,
		Secrets:                     p.registry.Secrets,
		MITMTrustBundle:             domainSigner.TrustBundle,
		ClientTrustPackagePath:      features.ClientTrustPackagePath,
		Namespace:                   options.RootNamespace,
		ConfigMapName:               features.InjectorConfigMapName,
		WebhookConfigName:           features.InjectionWebhookConfigName,
		NativeSidecarMode:           features.NativeSidecarMode,
		DiscoveryAddress: fmt.Sprintf(
			"%s.%s.svc.%s:15012",
			features.ServiceName,
			options.RootNamespace,
			options.ClusterDomain,
		),
	}
	return setupAdmissionWebhooks(ctx, p.kubeClient, p.authority, injectorOptions)
}

func (p *controlPlane) waitForInitialSync(ctx context.Context, errorsChannel <-chan error) (bool, error) {
	// The derived collections are filled asynchronously, so the compiler has its
	// own sync barrier beyond the informer caches. Publishing before it is
	// reached would ship a partial configuration.
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	nextSyncLog := time.Now().Add(10 * time.Second)
	for !p.registry.HasSynced() || !p.compiler.HasSynced() || !p.authenticationSynced() {
		select {
		case <-ctx.Done():
			return false, nil
		case err := <-errorsChannel:
			return false, err
		case <-ticker.C:
		}
		if time.Now().After(nextSyncLog) {
			log.Info(
				"waiting for initial configuration sync",
				"elapsed",
				time.Since(p.started),
				"registry_synced",
				p.registry.HasSynced(),
				"compiler_synced",
				p.compiler.HasSynced(),
				"authentication_synced",
				p.authenticationSynced(),
			)
			nextSyncLog = time.Now().Add(10 * time.Second)
		}
	}
	return true, nil
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

func shutdown(grpcServer *grpc.Server) {
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
}

func shutdownHTTP(server *http.Server, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Warn("graceful HTTP shutdown failed; closing connections", "address", server.Addr, "error", err)
		if err := server.Close(); err != nil {
			log.Error("close HTTP server", "address", server.Addr, "error", err)
		}
	}
}
