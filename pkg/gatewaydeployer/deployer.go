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

package gatewaydeployer

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	appsclientv1 "k8s.io/client-go/kubernetes/typed/apps/v1"
	coreclientv1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayclientv1 "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned/typed/apis/v1"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/kube/controllers"
	"github.com/openkruise/agentio/pkg/kube/kclient"
)

// Fallback Kubernetes version used when the API server version cannot be parsed.
const defaultKubeVersion = 128

// gatewayCRDPollInterval is how often the waitForGatewayCRD discovery fallback
// polls for the Gateway CRD when the shared client has no CrdWatcher.
const gatewayCRDPollInterval = 10 * time.Second

// gatewayCRDGVR is the Gateway API resource that waitForGatewayCRD waits for.
var gatewayCRDGVR = schema.GroupVersionResource{
	Group:    gatewayv1.GroupName,
	Version:  "v1",
	Resource: "gateways",
}

var gatewayClassCRDGVR = schema.GroupVersionResource{
	Group:    gatewayv1.GroupName,
	Version:  "v1",
	Resource: "gatewayclasses",
}

type Deployer struct {
	client          kube.Client
	kubeVersion     int
	provider        *templateProvider
	options         Options
	injectorConfigs kclient.StartableInformer[*corev1.ConfigMap]

	clients   controllerClients
	informers []startableInformer
}

type startableInformer interface {
	Start(stop <-chan struct{})
}

// New constructs a Deployer from the process-wide Kubernetes client. Reads,
// watches, writes, CRD discovery, and dynamic SSA all reuse the same client
// lifecycle as the registry.
func New(client kube.Client, o Options) (*Deployer, error) {
	if client == nil {
		return nil, fmt.Errorf("kubernetes client is required")
	}
	kubeVersion := defaultKubeVersion
	if serverVersion, err := client.Kube().Discovery().ServerVersion(); err != nil {
		log.Warn("get Kubernetes server version; using default",
			"default_version", defaultKubeVersion, "error", err)
	} else if parsed, err := parseKubeVersion(serverVersion.Major, serverVersion.Minor); err != nil {
		log.Warn("parse Kubernetes server version; using default", "major", serverVersion.Major, "minor", serverVersion.Minor,
			"default_version", defaultKubeVersion, "error", err)
	} else {
		kubeVersion = parsed
	}
	proxyConfig := defaultProxyConfig()
	proxyConfig.DiscoveryAddress = o.CAAddress
	provider, err := newTemplateProvider(o, proxyConfig)
	if err != nil {
		return nil, err
	}
	if o.InjectorConfigMapName == "" {
		o.InjectorConfigMapName = "agentio-sidecar-injector"
	}
	injectorConfigs := kclient.NewFiltered[*corev1.ConfigMap](client, kclient.Filter{Namespace: o.SystemNamespace})
	filter := kclient.Filter{}
	deployments := kclient.NewWritableFromInformer(
		kclient.NewFiltered[*appsv1.Deployment](client, filter),
		func(namespace string) appsclientv1.DeploymentInterface {
			return client.Kube().AppsV1().Deployments(namespace)
		},
	)
	services := kclient.NewWritableFromInformer(
		kclient.NewFiltered[*corev1.Service](client, filter),
		func(namespace string) coreclientv1.ServiceInterface {
			return client.Kube().CoreV1().Services(namespace)
		},
	)
	serviceAccounts := kclient.NewWritableStatuslessFromInformer(
		kclient.NewFiltered[*corev1.ServiceAccount](client, filter),
		func(namespace string) coreclientv1.ServiceAccountInterface {
			return client.Kube().CoreV1().ServiceAccounts(namespace)
		},
	)
	// HPA and PDB children are read through informers and written through
	// the dynamic SSA patcher, so a read-only client is enough.
	hpas := kclient.NewFiltered[*autoscalingv2.HorizontalPodAutoscaler](client, filter)
	pdbs := kclient.NewFiltered[*policyv1.PodDisruptionBudget](client, filter)
	configMaps := kclient.NewFiltered[*corev1.ConfigMap](client, filter)

	var gatewayInformer kclient.StartableInformer[*gatewayv1.Gateway]
	var gatewayClassInformer kclient.StartableInformer[*gatewayv1.GatewayClass]
	if client.CrdWatcher() == nil {
		gatewayInformer = kclient.NewFiltered[*gatewayv1.Gateway](client, filter)
		gatewayClassInformer = kclient.NewFiltered[*gatewayv1.GatewayClass](client, filter)
	} else {
		gatewayInformer = kclient.NewDelayedInformer[*gatewayv1.Gateway](client, gatewayCRDGVR, filter)
		gatewayClassInformer = kclient.NewDelayedInformer[*gatewayv1.GatewayClass](client, gatewayClassCRDGVR, filter)
	}
	gateways := kclient.NewWritableFromInformer(
		gatewayInformer,
		func(namespace string) gatewayclientv1.GatewayInterface {
			return client.GatewayAPI().GatewayV1().Gateways(namespace)
		},
	)
	gatewayClasses := kclient.NewWritableFromInformer(
		gatewayClassInformer,
		func(string) gatewayclientv1.GatewayClassInterface {
			return client.GatewayAPI().GatewayV1().GatewayClasses()
		},
	)

	clients := controllerClients{
		Gateways:        gateways,
		GatewayClasses:  gatewayClasses,
		Deployments:     deployments,
		Services:        services,
		ServiceAccounts: serviceAccounts,
		HPAs:            hpas,
		PDBs:            pdbs,
		ConfigMaps:      configMaps,
	}
	deployer := &Deployer{
		client:          client,
		kubeVersion:     kubeVersion,
		provider:        provider,
		options:         o,
		injectorConfigs: injectorConfigs,
		clients:         clients,
		informers: []startableInformer{
			injectorConfigs,
			deployments,
			services,
			serviceAccounts,
			hpas,
			pdbs,
			configMaps,
			gateways,
			gatewayClasses,
		},
	}
	injectorConfigs.AddEventHandler(controllers.FilteredObjectSpecHandler(func(controllers.Object) {
		if err := deployer.loadInjectorConfig(); err != nil {
			log.Error("reload injector configuration", "error", err)
		}
	}, func(obj controllers.Object) bool {
		return obj.GetName() == o.InjectorConfigMapName
	}))
	deployer.clients.Patcher = deployer.patch
	return deployer, nil
}

func (d *Deployer) loadInjectorConfig() error {
	configMap := d.injectorConfigs.Get(d.options.InjectorConfigMapName, d.options.SystemNamespace)
	if configMap == nil {
		return fmt.Errorf("injector ConfigMap %s/%s is absent; keeping last known gateway configuration",
			d.options.SystemNamespace, d.options.InjectorConfigMapName)
	}
	if err := d.provider.updateFromInjectorConfig(configMap.Data["config"], configMap.Data["values"]); err != nil {
		return fmt.Errorf("load injector ConfigMap %s/%s: %w", configMap.Namespace, configMap.Name, err)
	}
	return nil
}

// parseKubeVersion renders major/minor version strings as major*100+minor,
// tolerating the "+" suffix some distributions append to minor (e.g. "24+").
func parseKubeVersion(major, minor string) (int, error) {
	majorNum, err := strconv.Atoi(strings.TrimSuffix(strings.TrimSpace(major), "+"))
	if err != nil {
		return 0, fmt.Errorf("parse major version %q: %w", major, err)
	}
	minorNum, err := strconv.Atoi(strings.TrimSuffix(strings.TrimSpace(minor), "+"))
	if err != nil {
		return 0, fmt.Errorf("parse minor version %q: %w", minor, err)
	}
	return majorNum*100 + minorNum, nil
}

// Run blocks until ctx is done, re-entering leader election after losses so a
// replica that regains the lease resumes reconciling.
func (d *Deployer) Run(ctx context.Context) {
	for _, informer := range d.informers {
		informer.Start(ctx.Done())
	}
	// Load the initial template/value snapshot before a leader can reconcile a
	// Gateway. A later valid ConfigMap update requeues all managed Gateways.
	if !kube.WaitForCacheSync("egress gateway injector config", ctx.Done(), d.injectorConfigs.HasSynced) {
		return
	}
	if err := d.loadInjectorConfig(); err != nil {
		log.Error("load injector configuration", "error", err)
	}
	// Gateway API availability is a process-level prerequisite. Waiting once
	// avoids accumulating CRD callbacks across leader-election cycles while the
	// CRD is absent.
	if !d.waitForGatewayCRD(ctx.Done()) {
		return
	}
	for _, source := range []krt.Syncer{d.options.Agentgateway.Config, d.options.Agentgateway.Services,
		d.options.Agentgateway.Endpoints, d.options.Agentgateway.Secrets} {
		if source != nil && !source.WaitUntilSynced(ctx.Done()) {
			return
		}
	}
	hostname, _ := os.Hostname()
	suffix := make([]byte, 4)
	_, _ = rand.Read(suffix)
	identity := fmt.Sprintf("%s-%s", hostname, hex.EncodeToString(suffix))
	for ctx.Err() == nil {
		lock := &resourcelock.LeaseLock{
			LeaseMeta: metav1.ObjectMeta{
				Name:      d.options.LeaseName,
				Namespace: d.options.SystemNamespace,
			},
			Client:     d.client.Kube().CoordinationV1(),
			LockConfig: resourcelock.ResourceLockConfig{Identity: identity},
		}
		elector, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
			Lock:            lock,
			LeaseDuration:   30 * time.Second,
			RenewDeadline:   20 * time.Second,
			RetryPeriod:     5 * time.Second,
			ReleaseOnCancel: true,
			Callbacks: leaderelection.LeaderCallbacks{
				OnStartedLeading: func(leaderCtx context.Context) { d.runControllers(leaderCtx) },
				OnStoppedLeading: func() {},
			},
		})
		if err != nil {
			// Construction failure must not silently end the loop: without a
			// leader no gateways are reconciled, so log and retry instead.
			log.Error("create leader elector", "error", err)
		} else {
			elector.Run(ctx)
		}
		if ctx.Err() == nil {
			sleepContext(ctx, 5*time.Second)
		}
	}
}

// sleepContext blocks for d or until ctx is done, whichever comes first.
func sleepContext(ctx context.Context, d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

// waitForGatewayCRD blocks until the Gateway API's v1 gateways resource is
// served or stop closes. With the shared client's CrdWatcher it is event-driven;
// otherwise it polls discovery every gatewayCRDPollInterval.
func (d *Deployer) waitForGatewayCRD(stop <-chan struct{}) bool {
	if d.client.CrdWatcher() != nil {
		return d.client.CrdWatcher().WaitForCRD(gatewayCRDGVR, stop)
	}
	check := func() bool {
		resources, err := d.client.Kube().Discovery().ServerResourcesForGroupVersion(gatewayv1.GroupVersion.String())
		if err != nil {
			return false
		}
		for _, r := range resources.APIResources {
			if r.Name == "gateways" {
				return true
			}
		}
		return false
	}
	if check() {
		return true
	}
	ticker := time.NewTicker(gatewayCRDPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return false
		case <-ticker.C:
			if check() {
				return true
			}
		}
	}
}

// runControllers installs one leader cycle's handlers and queues on the
// process-wide informer clients, then removes them when the leader context is
// done.
func (d *Deployer) runControllers(leaderCtx context.Context) {
	leaderStop := leaderCtx.Done()
	classController := NewClassController(d.clients.GatewayClasses)
	controller, deregisterRequeueAll := NewDeploymentController(
		d.clients,
		d.provider.Renderer(),
		d.options.ClusterID,
		d.options.SystemNamespace,
		d.kubeVersion,
		d.provider.AddHandler,
	)
	// Unregister this cycle's requeueAll handler so a dead queue stops receiving values reloads.
	defer deregisterRequeueAll()
	controller.agentgatewaySources = d.options.Agentgateway
	unregisterSources := controller.watchAgentgatewaySources()
	defer unregisterSources()

	var wg sync.WaitGroup
	wg.Go(func() {
		classController.Run(leaderStop)
	})
	controller.Run(leaderStop)
	// Wait for ClassController's handler cleanup before a future lease cycle
	// installs fresh handlers on the process-wide informers.
	wg.Wait()
}

// patch performs Server-Side Apply through the dynamic client with Force=true
// under an Agentio-owned field manager, so this controller wins
// conflicts against fields it owns.
func (d *Deployer) patch(gvr schema.GroupVersionResource, name, namespace string, data []byte, subresources ...string) error {
	force := true
	_, err := d.client.Dynamic().Resource(gvr).Namespace(namespace).Patch(
		context.Background(), name, types.ApplyPatchType, data,
		metav1.PatchOptions{
			Force:        &force,
			FieldManager: "agentio.kruise.io/gateway-controller",
		},
		subresources...,
	)
	return err
}
