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

package agentio

import (
	"fmt"
	"strings"
	"time"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	agentsclient "github.com/openkruise/agents-api/client/clientset/versioned"
	"google.golang.org/protobuf/proto"
	securityclient "istio.io/client-go/pkg/apis/security/v1"
	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio/extensions"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio/spstatus"
	"istio.io/istio/pilot/pkg/status"
	"istio.io/istio/pkg/config/mesh/meshwatcher"
	"istio.io/istio/pkg/env"
	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/kube/controllers"
	"istio.io/istio/pkg/kube/kclient"
	"istio.io/istio/pkg/kube/krt"
	istiolog "istio.io/istio/pkg/log"
	"istio.io/istio/pkg/revisions"
	"istio.io/istio/pkg/util/sets"
	"istio.io/istio/pkg/workloadapi/security"
	corev1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
)

var (
	log        = istiolog.RegisterScope("agentio-controller", "agentio controller")
	dnsServers = func() []string {
		servers := env.Register("EXTERNAL_NAMES_CONTROLLER_DNS_SERVER", "", "Dns servers for external names controller.").Get()
		if servers == "" {
			return nil
		}
		return strings.Split(servers, ",")
	}()

	mitmSecretNamespace = env.Register("ON_DEMAND_SECRET_NAMESPACE", "",
		"The namespace of the Kubernetes Secret containing the CA certificate and key used for MITM certificate signing.").Get()
	mitmSecretName = env.Register("ON_DEMAND_SECRET_NAME", "",
		"The name of the Kubernetes Secret containing the CA certificate (ca.crt) and key (ca.key) used for MITM certificate signing.").Get()
	mitmCertValidity = env.Register("ON_DEMAND_CERT_VALIDITY", 24*time.Hour,
		"The TTL of on-demand generated MITM certificates. Expired certificates are automatically regenerated on next request.").Get()
	mitmCertRenewBefore = env.Register("ON_DEMAND_CERT_RENEW_BEFORE", 30*time.Minute,
		"The duration before expiry at which a cached MITM certificate is considered stale and will be regenerated.").Get()
	mitmCertMaxAge = env.Register("ON_DEMAND_CERT_MAX_AGE", 1*time.Hour,
		"The maximum age (from sign time) a cached MITM certificate is retained before the background reaper evicts it, regardless of recent use. Set to 0 to disable eviction.").Get()
	mitmSignMode = env.Register("ON_DEMAND_SIGN_MODE", "SECRET",
		"Controls how the MITM CA is obtained. "+
			"SECRET: read CA cert/key from the specified Kubernetes Secret. "+
			"SELF_SIGN: generate an ephemeral self-signed CA at startup (for testing only, not suitable for multi-instance deployments).").Get()
)

type Options struct {
	KubeClient kube.Client
	MeshConfig meshwatcher.WatcherCollection
	Debugger   *krt.DebugHandler
	Stop       <-chan struct{}
	Revision   string
}

type Controller struct {
	ConfigStoreController model.ConfigStoreController
	meshConfig            meshwatcher.WatcherCollection
	agentioConfig         krt.Singleton[model.AgentioConfig]

	externalNamesController *externalNamesController
	authorizationController *authorizationController
	onDemandController      *onDemandCertController

	workloadConfigs krt.Singleton[model.WorkloadConfig]

	trafficPolicies       krt.Collection[*agentsv1alpha1.TrafficPolicy]
	globalTrafficPolicies krt.Collection[*agentsv1alpha1.GlobalTrafficPolicy]

	spStatusCollections *status.StatusCollections
	spStatusQueue       *spstatus.Queue

	revision string
	stop     <-chan struct{}
}

func NewController(options Options) (*Controller, error) {
	stop := options.Stop
	if stop == nil {
		return nil, fmt.Errorf("stop channel is required")
	}

	// Create agents-api clientset and register types before creating collections
	agentsCS, err := agentsclient.NewForConfig(options.KubeClient.RESTConfig())
	if err != nil {
		return nil, err
	}
	registerTypes(agentsCS)

	opts := krt.NewOptionsBuilder(stop, "agentio-controller", options.Debugger)
	TrafficPolicies := newTrafficPoliciesCollection(options.KubeClient, stop, opts)
	GlobalTrafficPolicies := newGlobalTrafficPoliciesCollection(options.KubeClient, stop, opts)

	store := newConfigStore(options.KubeClient, options.MeshConfig.Get().RootNamespace, stop)
	agentioConfig := newAgentioConfig(options.KubeClient, options.MeshConfig.Get().RootNamespace, opts)

	c := &Controller{
		ConfigStoreController: store,
		stop:                  stop,
		trafficPolicies:       TrafficPolicies,
		meshConfig:            options.MeshConfig,
		globalTrafficPolicies: GlobalTrafficPolicies,
		agentioConfig:         agentioConfig,
		revision:              options.Revision,
	}

	if features.EnableOnDemandCerts {
		if err := c.initOnDemandController(options.KubeClient, opts); err != nil {
			log.Errorf("Failed to create on demand cert controller, err: %+v", err)
			return nil, err
		}
	}

	c.initExternalNamesController()
	if features.EnableSecurityProfileStatus {
		c.initSecurityProfileStatus(options.KubeClient, opts)
	}
	c.initWorkloadConfigs(opts)
	return c, nil
}

func (c *Controller) initOnDemandController(kc kube.Client, opts krt.OptionsBuilder) error {
	onDemandController, err := newOnDemandCertController(kc, OnDemandCertControllerOption{
		SecretNamespace: mitmSecretNamespace,
		SecretName:      mitmSecretName,
		CertValidity:    mitmCertValidity,
		RenewBefore:     mitmCertRenewBefore,
		MaxAge:          mitmCertMaxAge,
		SignMode:        mitmSignMode,
		KrtOptions:      opts,
		AgentioConfig:   c.agentioConfig,
	})
	if err != nil {
		return err
	}
	go onDemandController.Run(c.stop)
	c.onDemandController = onDemandController
	return nil
}

func (c *Controller) initExternalNamesController() {
	externalNamesController := newExternalServiceController(externalNamesControllerOptions{
		dnsServers: dnsServers,
	})

	c.trafficPolicies.Register(func(o krt.Event[*agentsv1alpha1.TrafficPolicy]) {
		switch o.Event {
		case controllers.EventAdd:
			for hostname := range extractHostname(&(*o.New).Spec) {
				externalNamesController.HandleAdd(hostname)
			}
		case controllers.EventDelete:
			for hostname := range extractHostname(&(*o.Old).Spec) {
				externalNamesController.HandleDelete(hostname)
			}
		case controllers.EventUpdate:
			oldSet := extractHostname(&(*o.Old).Spec)
			newSet := extractHostname(&(*o.New).Spec)
			removed, added := oldSet.Diff(newSet)
			for _, hostname := range removed {
				externalNamesController.HandleDelete(hostname)
			}
			for _, hostname := range added {
				externalNamesController.HandleAdd(hostname)
			}
		}
	})

	c.globalTrafficPolicies.Register(func(o krt.Event[*agentsv1alpha1.GlobalTrafficPolicy]) {
		switch o.Event {
		case controllers.EventAdd:
			for hostname := range extractHostname(&(*o.New).Spec) {
				externalNamesController.HandleAdd(hostname)
			}
		case controllers.EventDelete:
			for hostname := range extractHostname(&(*o.Old).Spec) {
				externalNamesController.HandleDelete(hostname)
			}
		case controllers.EventUpdate:
			oldSet := extractHostname(&(*o.Old).Spec)
			newSet := extractHostname(&(*o.New).Spec)
			removed, added := oldSet.Diff(newSet)
			for _, hostname := range removed {
				externalNamesController.HandleDelete(hostname)
			}
			for _, hostname := range added {
				externalNamesController.HandleAdd(hostname)
			}
		}
	})

	c.agentioConfig.AsCollection().Register(func(o krt.Event[model.AgentioConfig]) {
		oldHosts := o.Old.ExtractMatchHosts()
		newHosts := o.New.ExtractMatchHosts()
		removed, added := oldHosts.Diff(newHosts)
		for _, hostname := range removed {
			externalNamesController.HandleDelete(hostname)
		}
		for _, hostname := range added {
			externalNamesController.HandleAdd(hostname)
		}
	})

	c.externalNamesController = externalNamesController
	c.externalNamesController.Start(c.stop)
}

// initSecurityProfileStatus builds the status pipeline but does not start
// writing. SetSecurityProfileStatusWrite turns writing on once this instance
// wins leader election.
func (c *Controller) initSecurityProfileStatus(kc kube.Client, opts krt.OptionsBuilder) {
	profiles := newSecurityProfilesCollection(kc, c.stop, opts)
	secrets := newSecretsCollection(kc, opts)
	col := spstatus.NewCollection(profiles, secrets, opts)

	patcher := kclient.ToPatcher(kclient.NewWriteClient[*agentsv1alpha1.SecurityProfile](kc))
	c.spStatusQueue = spstatus.NewQueue(patcher, col)
	c.spStatusCollections = &status.StatusCollections{}

	tagWatcher := revisions.NewTagWatcher(kc, c.revision, c.meshConfig.Get().RootNamespace)
	go tagWatcher.Run(c.stop)
	spstatus.Register(c.spStatusCollections, col, tagWatcher)

	go c.spStatusQueue.Run(c.stop)
}

// SetSecurityProfileStatusWrite turns status writing on or off. Only the
// elected leader for a revision should write.
//
// Enabling registers the krt handler, which replays the current state
// (pkg/kube/krt/collection.go:743-746); disabling unregisters it, so a
// non-leader neither computes nor writes. This mirrors
// gateway.Controller.SetStatusWrite (pilot/pkg/config/kube/gateway/controller.go:515).
func (c *Controller) SetSecurityProfileStatusWrite(enabled bool) {
	if c.spStatusCollections == nil {
		// Feature disabled; nothing was built.
		return
	}
	if enabled {
		c.spStatusCollections.SetQueue(c.spStatusQueue)
		return
	}
	c.spStatusCollections.UnsetQueue()
}

func (c *Controller) initWorkloadConfigs(opts krt.OptionsBuilder) {
	rootNamespace := c.meshConfig.Get().RootNamespace
	c.workloadConfigs = krt.NewSingleton(func(ctx krt.HandlerContext) *model.WorkloadConfig {
		sc := krt.FetchOne(ctx, c.agentioConfig.AsCollection())
		var resolved []*extensions.EgressPolicy
		if sc != nil {
			for _, p := range sc.GetEgressPolicies() {
				resolved = append(resolved, resolveEgressPolicy(ctx, p, c.externalNamesController))
			}
		}
		return &model.WorkloadConfig{
			Namespace: rootNamespace,
			Name:      "default",
			Config: &extensions.WorkloadConfig{
				EgressPolicies: resolved,
				Scope:          extensions.WorkloadConfigScope_WORKLOAD_CONFIG_SCOPE_GLOBAL,
			},
		}
	}, opts.WithName("WorkloadConfigs")...)
}

func (c *Controller) AgentioConfig() krt.Singleton[model.AgentioConfig] {
	return c.agentioConfig
}

func (c *Controller) WorkloadConfigs() krt.Collection[model.WorkloadConfig] {
	return c.workloadConfigs.AsCollection()
}

// unreachableCIDR is the IANA IPv4 Dummy Address (RFC 7600). Used as a
// sentinel when all match_hosts fail to resolve — ensures the policy
// cannot accidentally wildcard-match all traffic.
const unreachableCIDR = "192.0.0.8/32"

func resolveEgressPolicy(ctx krt.HandlerContext, p *extensions.EgressPolicy, enc *externalNamesController) *extensions.EgressPolicy {
	if len(p.GetMatchHosts()) == 0 {
		return p
	}
	clone := proto.Clone(p).(*extensions.EgressPolicy)
	hasOriginalCidrs := len(clone.GetMatchCidrs()) > 0
	resolved := false
	for _, h := range clone.GetMatchHosts() {
		if addrs := enc.FetchOrResolve(ctx, h); len(addrs) > 0 {
			for _, addr := range addrs {
				clone.MatchCidrs = append(clone.MatchCidrs, addr+"/32")
			}
			resolved = true
		} else {
			log.Warnf("failed to resolve match_hosts entry %q, policy may not match intended traffic", h)
		}
	}
	if !resolved && !hasOriginalCidrs {
		clone.MatchCidrs = append(clone.MatchCidrs, unreachableCIDR)
	}
	return clone
}

func (c *Controller) OnDemandCertController() OnDemandCertController {
	if c.onDemandController == nil {
		return nil
	}
	return c.onDemandController
}

func (c *Controller) BuildPolicyCollection(
	services krt.Collection[*corev1.Service],
	endpointSlices krt.Collection[*discovery.EndpointSlice],
	pods krt.Collection[*corev1.Pod],
	transform func(*securityclient.AuthorizationPolicy) (*security.Authorization, *model.StatusMessage),
) krt.Collection[model.WorkloadAuthorization] {
	c.authorizationController = newAuthorizationController(
		c.trafficPolicies,
		c.globalTrafficPolicies,
		services,
		endpointSlices,
		c.externalNamesController.FetchOrResolve,
		pods,
		transform,
		c.meshConfig.Get().RootNamespace,
	)
	return c.authorizationController.AsCollection()
}

// extractHostname returns all FQDN hostnames referenced in the policy's
// ingress and egress rules (both From and To peers).
func extractHostname(spec *agentsv1alpha1.TrafficPolicySpec) sets.Set[string] {
	hosts := sets.New[string]()
	if spec == nil {
		return hosts
	}
	if spec.Egress != nil {
		for _, rule := range spec.Egress.Rules {
			for _, to := range rule.To {
				hosts.Insert(to.FQDN)
			}
			for _, from := range rule.From {
				hosts.Insert(from.FQDN)
			}
		}
	}

	if spec.Ingress != nil {
		for _, rule := range spec.Ingress.Rules {
			for _, to := range rule.To {
				hosts.Insert(to.FQDN)
			}
			for _, from := range rule.From {
				hosts.Insert(from.FQDN)
			}
		}
	}

	return hosts
}
