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

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/go-logr/zapr"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	uberzap "go.uber.org/zap"
	"go.uber.org/zap/exp/zapslog"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc"
	grpchealth "google.golang.org/grpc/health"
	healthPb "google.golang.org/grpc/health/grpc_health_v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/admin"
	"github.com/openkruise/agentio/extensions/epe/pkg/audit"
	"github.com/openkruise/agentio/extensions/epe/pkg/audit/accesslog"
	"github.com/openkruise/agentio/extensions/epe/pkg/audit/sinks/webhook"
	"github.com/openkruise/agentio/extensions/epe/pkg/certs/certsource"
	"github.com/openkruise/agentio/extensions/epe/pkg/extensionprovider"
	_ "github.com/openkruise/agentio/extensions/epe/pkg/filters/httpcallout" // Register environment settings.
	"github.com/openkruise/agentio/extensions/epe/pkg/metrics"
	"github.com/openkruise/agentio/extensions/epe/pkg/policy/profilestore"
	"github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"
	"github.com/openkruise/agentio/extensions/epe/pkg/runnable"
	runserver "github.com/openkruise/agentio/extensions/epe/pkg/server"
	"github.com/openkruise/agentio/extensions/epe/pkg/wiring"
	"github.com/openkruise/agentio/pkg/config"
	"github.com/openkruise/agentio/pkg/envdoc"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/kube/kclient"
)

var (
	epeConfigName = flag.String(
		"epe-config",
		"agentio-epe-config",
		"Base EPEConfig ConfigMap for extension providers; absence leaves defaults unchanged",
	)
	epeConfigPrimaryName = flag.String(
		"epe-config-primary",
		"agentio-epe-config-primary",
		"Primary EPEConfig ConfigMap applied after the base; empty disables the overlay",
	)
	epeConfigNamespace = flag.String(
		"epe-config-namespace",
		"agentio-system",
		"Namespace of EPEConfig and its referenced Secrets",
	)
	logVerbosity = flag.Int("v", 2, "number for the log level verbosity")

	grpcPort = flag.Int(
		"grpc-port",
		9002,
		"The gRPC port used for communicating with Envoy proxy")
	grpcHealthPort = flag.Int(
		"grpc-health-port",
		9003,
		"The port used for gRPC liveness and readiness probes")
	metricsPort = flag.Int(
		"metrics-port", 9090, "The metrics port")
	pluginBudget = flag.Duration(
		"plugin-budget",
		4500*time.Millisecond,
		"Maximum duration of one evaluation phase (one ext_proc message), shared by every filter invocation in that phase; 0 disables. Must stay below Envoy's ext_proc message_timeout (shipped default 5s) so the plugin is cancelled before Envoy gives up. Lower it only with the failure-mode change in mind: a fetch that exceeds the budget becomes a fetch error, which the rule's failStrategy (CRD default Block) turns into a 403.",
	)
	kubeconfig  = flag.String("kubeconfig", "", "Path to a kubeconfig; empty means in-cluster config")
	enablePprof = flag.Bool("enable-pprof", false, "Enable pprof profiling endpoint")
	pprofAddr   = flag.String("pprof-addr", ":6060", "The address the pprof server binds to")
	adminAddr   = flag.String("admin-addr", "127.0.0.1:15000",
		"The address the admin HTTP server binds to (set to :15000 to listen on all interfaces)")
	enableDebug = flag.Bool("enable-debug", true,
		"Enable the /debug endpoints on the admin server (profile inspection and runtime log level)")
	auditLogBufferSize = flag.Int("audit-log-buffer-size", accesslog.DefaultBufferSize,
		"Audit log buffered channel capacity; entries are dropped when full")
	auditWebhookBufferSize = flag.Int("audit-webhook-buffer-size", webhook.DefaultBufferSize,
		"Audit webhook dispatcher channel capacity; events dropped when full")
	auditWebhookWorkers = flag.Int("audit-webhook-workers", webhook.DefaultWorkers,
		"Audit webhook dispatcher worker pool size")
	auditWebhookInsecureSkipVerify = flag.Bool("audit-webhook-insecure-skip-verify",
		false, "Skip TLS certificate verification for all HTTPS audit webhook targets; "+
			"enabling this disables server identity verification and is unsafe")
	failClosedOnMissingIdentity = flag.Bool("fail-closed-on-missing-identity", false,
		"Deny requests when the source pod identity is missing from filter_state "+
			"(e.g. a misconfigured metadata exchange); by default such requests pass through")
	tlsSource = flag.String("tls-source", "none", "Serving certificate source: none, ca or file")
	caAddress = flag.String(
		"ca-address",
		"agentiod.agentio-system.svc:15012",
		"Certificate authority host:port implementing the Istio CreateCertificate API; requires --tls-source=ca",
	)
	caTokenPath = flag.String(
		"ca-token-path",
		"/var/run/secrets/tokens/agentio-token",
		"ServiceAccount token file for certificate requests; requires --tls-source=ca",
	)
	caRootPath = flag.String(
		"ca-root-path",
		"/var/run/secrets/agentio/root-cert.pem",
		"CA bundle for verifying the CA server, issued certificates and incoming clients; requires --tls-source=ca",
	)
	tlsSPIFFEID = flag.String(
		"tls-spiffe-id",
		"",
		"Expected EPE ServiceAccount SPIFFE identity in CA mode; Agentiod derives the issued identity from the token",
	)
	tlsCertLifetime = flag.Duration(
		"tls-cert-lifetime",
		24*time.Hour,
		"Requested certificate lifetime in CA mode; capped by Agentiod",
	)
	tlsCertPath = flag.String("tls-cert-path", "",
		"Path to the ext-proc server certificate chain PEM (e.g. Istio OUTPUT_CERTS cert-chain.pem); "+
			"requires --tls-key-path and --tls-source=file")
	tlsKeyPath = flag.String("tls-key-path", "",
		"Path to the ext-proc server private key PEM (e.g. Istio OUTPUT_CERTS key.pem); "+
			"requires --tls-cert-path")
	tlsCAPath = flag.String("tls-ca-path", "",
		"Path to the client CA bundle PEM (e.g. Istio OUTPUT_CERTS root-cert.pem); "+
			"enables mTLS with required and verified client certificates")

	setupLog = ctrllog.Log.WithName("setup")
)

func main() {
	// Report flag and export errors on stderr before runtime logging is configured.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	if err := run(); err != nil {
		slog.Error("EPE run failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	printEnv := envdoc.Flags{}
	printEnv.Bind(flag.CommandLine)

	// Production defaults: JSON encoding and Info level. Development mode also
	// lowers the stacktrace threshold to Warn, which attached a full stack to
	// every request-path failure — see initLogging. -zap-devel still turns it on
	// for local debugging.
	opts := zap.Options{Development: false}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	if err := printEnv.Validate(); err != nil {
		return err
	}
	if printEnv.Enabled {
		return printEnv.Write(os.Stdout, envdoc.Options{
			Prefixes: []string{
				"IDENTITY_PROVIDER_",
				"TOKEN_CACHE_",
				"STS_CACHE_",
				"CREDENTIAL_PROVIDER_",
				"AUDIT_WEBHOOK_",
				"HTTP_CALLOUT_",
			},
		})
	}
	logLevel := initLogging(&opts)

	flags := make(map[string]any)
	flag.VisitAll(func(f *flag.Flag) {
		flags[f.Name] = f.Value.String()
	})
	setupLog.Info("parsed flags", "flags", flags)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Initialize the process-wide Kubernetes client and CRD watcher. The same
	// client owns core, metadata, and agents-api reads for every EPE component.
	kubeConfig, err := kube.LoadConfig(*kubeconfig)
	if err != nil {
		setupLog.Error(err, "failed to load Kubernetes configuration")
		return err
	}
	client, err := kube.NewClient(kubeConfig)
	if err != nil {
		setupLog.Error(err, "failed to create kube client")
		return err
	}
	client = kube.EnableCrdWatcher(client, kube.CrdWatcherOptions{})
	agentsCS := client.AgentsAPI()

	group := &runnable.Group{}

	// Build the shared filter chain first: the profile collection projects
	// every candidate version's rule payloads against these registrations, so
	// a static authoring error is rejected at the collection boundary (with
	// last-known-good retention) instead of on the first matching request.
	// See wiring.BuildFilters for ordering semantics.
	defaults, err := wiring.DefaultEPEConfig()
	if err != nil {
		return fmt.Errorf("initialize extension providers: %w", err)
	}
	providers := &extensionprovider.Registry{}
	defer providers.Close()
	chainDeps := wiring.Deps{Kube: client, Providers: providers}
	if *epeConfigName == "" || *epeConfigNamespace == "" {
		return fmt.Errorf("--epe-config and --epe-config-namespace must not be empty")
	}
	servingTLS, err := buildExtProcTLS(extProcTLSOptions{
		Source:   *tlsSource,
		CertPath: *tlsCertPath,
		KeyPath:  *tlsKeyPath,
		CAPath:   *tlsCAPath,
		Workload: certsource.WorkloadOptions{
			Address:   *caAddress,
			TokenPath: *caTokenPath,
			RootPath:  *caRootPath,
			SPIFFEID:  *tlsSPIFFEID,
			Lifetime:  *tlsCertLifetime,
		},
	}, ctx.Done())
	if err != nil {
		return fmt.Errorf("invalid ext-proc TLS flags: %w", err)
	}
	if servingTLS.Workload != nil {
		group.Add(servingTLS.Workload)
	}
	cms := kclient.NewFiltered[*corev1.ConfigMap](client, kclient.Filter{})
	cms.Start(ctx.Done())
	configMaps := krt.WrapClient(cms, krt.WithName("EPEConfigMaps"), krt.WithStop(ctx.Done()))
	configs := config.NewCollection(configMaps, config.Options[*configv1.EPEConfig]{
		Namespace: *epeConfigNamespace,
		Names:     []string{*epeConfigName, *epeConfigPrimaryName},
		Defaults:  defaults,
		Apply:     extensionprovider.ApplyConfig,
		Validate:  extensionprovider.Validate,
	}, krt.WithName("EPEConfig"), krt.WithStop(ctx.Done())).AsCollection()
	providerConfigs := extensionprovider.NewCollection(client, *epeConfigNamespace,
		configs, configMaps, nil, ctx.Done())
	providerReg := providers.RegisterCollection(providerConfigs)
	registrations, err := wiring.BuildFilters(chainDeps)
	if err != nil {
		setupLog.Error(err, "failed to build filter chain")
		return err
	}

	// Create the in-memory config store, materialized from one joined krt
	// collection of compiled SecurityProfile / GlobalSecurityProfile objects
	// and per-Sandbox rule profiles (agents.kruise.io/security-rules
	// annotation, looked up by verified pod identity and evaluated after the
	// selector-matched profiles). Registration replays current collection
	// state and then applies every event batch.
	store := profilestore.NewStore()
	profiles := profilestore.NewCollection(client, registrations, nil, ctx.Done())
	profileReg := store.RegisterCollection(profiles)

	// Liveness remains healthy during CA outages. Readiness follows certificate
	// validity independently, allowing an expired identity to recover in place.
	healthSrv := grpc.NewServer()
	health := grpchealth.NewServer()
	health.SetServingStatus("liveness", healthPb.HealthCheckResponse_SERVING)
	updateReadiness := func() {
		state := healthPb.HealthCheckResponse_SERVING
		if servingTLS.Ready() != nil {
			state = healthPb.HealthCheckResponse_NOT_SERVING
		}
		for _, service := range []string{"", "readiness", extProcPb.ExternalProcessor_ServiceDesc.ServiceName} {
			health.SetServingStatus(service, state)
		}
	}
	updateReadiness()
	healthPb.RegisterHealthServer(healthSrv, health)
	group.Add(runnable.GRPCServer("health", healthSrv, *grpcHealthPort))
	group.Add(runnable.Func(func(ctx context.Context) error {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				health.Shutdown()
				return nil
			case <-ticker.C:
				updateReadiness()
			}
		}
	}))

	// Admin HTTP server. It is always on; the /debug endpoints are only
	// wired when --enable-debug is set. The agents-api clientset serves full
	// profile content in full mode.
	adminHandler := admin.NewHandler(admin.Options{
		EnableDebug: *enableDebug,
		Store:       store,
		Client:      agentsCS,
		LogLevel:    &logLevel,
	})
	group.Add(runnable.HTTPServer("admin", adminHandler, *adminAddr))

	// Metrics HTTP server backed by the process-wide registry.
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.HandlerFor(metrics.Registry, promhttp.HandlerOpts{}))
	group.Add(runnable.HTTPServer("metrics", metricsMux, fmt.Sprintf(":%d", *metricsPort)))

	// Wire the per-request audit logger.
	auditLogger := accesslog.NewBufferedLogger(ctrllog.Log.WithName("audit"), *auditLogBufferSize)
	group.Add(auditLogger)

	// Wire the audit webhook dispatcher and sink through the Router.
	webhookDispatcher := webhook.NewBuffered(
		ctrllog.Log.WithName("audit-webhook"),
		*auditWebhookBufferSize, *auditWebhookWorkers,
		*auditWebhookInsecureSkipVerify)
	group.Add(webhookDispatcher)
	webhookSink := webhook.NewSink(webhookDispatcher, ctrllog.Log.WithName("audit-webhook"))
	auditRouter := audit.NewRouter()
	auditRouter.Register(audit.SinkKindWebhook, webhookSink)

	// Assemble the ext-proc gRPC server around the shared filter chain built
	// above.
	group.Add(runserver.New(runserver.Config{
		GrpcPort:                    *grpcPort,
		PluginBudget:                *pluginBudget,
		FailClosedOnMissingIdentity: *failClosedOnMissingIdentity,
		SecureServing:               servingTLS.Secure,
		CertProvider:                servingTLS.Provider,
		RequireClientCert:           servingTLS.RequireClientCert,
		Resolve:                     securityprofile.NewResolver(store, registrations, auditRouter),
		AuditLogger:                 auditLogger,
		Registrations:               registrations,
	}, ctrllog.Log.WithName("ext-proc")))

	// Start pprof server if enabled.
	if *enablePprof {
		go func() {
			setupLog.Info("starting pprof server", "addr", *pprofAddr)
			if err := http.ListenAndServe(*pprofAddr, nil); err != nil {
				setupLog.Error(err, "pprof server failed")
			}
		}()
	}

	// Start the shared informer machinery and CRD watcher once. Each collection
	// owns its sync condition, so readiness waits on both registrations.
	client.Run(ctx.Done())
	if !providerReg.WaitUntilSynced(ctx.Done()) {
		return fmt.Errorf("EPEConfig collection sync interrupted")
	}

	// Block until the initial profile state has been applied to the store so
	// ext-proc never serves from an empty snapshot during startup.
	if !profileReg.WaitUntilSynced(ctx.Done()) {
		setupLog.Info("profile collection sync interrupted")
		return fmt.Errorf("profile collection sync interrupted")
	}

	setupLog.Info("EPE starting")
	if err := group.Start(ctx); err != nil {
		setupLog.Error(err, "error running components")
		return err
	}
	setupLog.Info("EPE terminated")
	return nil
}

// initLogging maps the klog-style -v flag onto the zap level unless the user
// explicitly set --zap-log-level, then installs the controller-runtime logger
// process-wide and bridges slog and klog onto the same zap core. The returned
// atomic level lets the admin handler update existing loggers without rebuilding
// their cores or changing encoder and stacktrace options.
func initLogging(opts *zap.Options) uberzap.AtomicLevel {
	level := newLogLevel(opts)
	opts.Level = level

	// Keep stacktraces off every level the request path uses. The ext-proc
	// handlers report broken streams, unreadable bodies and failed credential
	// fetches through Error, and those are conditions a client or a policy
	// produced, not defects in this binary: the stack names a fixed, known line,
	// while the fields that identify the request — requestID, pod, rule — are
	// already on the line. Such a condition repeats once per request, so a stack
	// turns one log line into dozens at request rate.
	//
	// DPanic and above still carry one, which is where a stack earns its cost.
	// -zap-stacktrace-level overrides this, and -zap-devel does not: Development
	// only supplies a default when none is set.
	if opts.StacktraceLevel == nil {
		opts.StacktraceLevel = uberzap.NewAtomicLevelAt(zapcore.DPanicLevel)
	}

	raw := zap.NewRaw(zap.UseFlagOptions(opts), zap.RawZapOpts(uberzap.AddCaller()))
	ctrllog.SetLogger(zapr.NewLogger(raw))

	// Shared agentio packages linked into this binary — pkg/krt, pkg/kube,
	// pkg/queue — log through pkg/log, which resolves slog.Default() per record.
	// Its independent info-level scope gate remains in place; accepted records,
	// direct slog calls, and klog all follow the same dynamic zap threshold.
	slogLogger := slog.New(zapslog.NewHandler(raw.Core(), zapslog.WithCaller(true)))
	slog.SetDefault(slogLogger)
	klog.SetSlogLogger(slogLogger)
	return level
}

func newLogLevel(opts *zap.Options) uberzap.AtomicLevel {
	useV := true
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "zap-log-level" {
			useV = false
		}
	})
	if useV {
		// See https://pkg.go.dev/sigs.k8s.io/controller-runtime/pkg/log/zap#Options.Level
		lvl := -1 * (*logVerbosity)
		return uberzap.NewAtomicLevelAt(zapcore.Level(int8(lvl)))
	}
	return uberzap.NewAtomicLevelAt(zapcore.LevelOf(opts.Level))
}
