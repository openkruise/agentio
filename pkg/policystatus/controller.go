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

package policystatus

import (
	"context"
	"fmt"
	"math"
	"os"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/wiring"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/kube/controllers"
	agentlog "github.com/openkruise/agentio/pkg/log"
	"github.com/openkruise/agentio/pkg/policy"
	kubernetesregistry "github.com/openkruise/agentio/pkg/registry/kubernetes"
)

var log = agentlog.New("policy-status")

// Controller validates policy configuration; it does not gate data-plane loading.
type Controller struct {
	client           kube.Client
	registry         *kubernetesregistry.Registry
	namespace        string
	scopedSecrets    bool
	filters          []filter.Registration
	traffic          policy.TrafficPolicyInputs
	secretsSynced    krt.Singleton[bool]
	configMapsSynced krt.Singleton[bool]
	results          krt.Collection[result]
}

// New reuses the registry's informers and the production policy compilers.
func New(client kube.Client, registry *kubernetesregistry.Registry, namespace string,
	scopedSecrets bool, resolve policy.HostnameResolver, stop <-chan struct{},
) (*Controller, error) {
	filters, err := wiring.BuildValidationFilters()
	if err != nil {
		return nil, fmt.Errorf("build policy validation parsers: %w", err)
	}
	opts := krt.NewOptionsBuilder(stop, "policy-status", nil)
	c := &Controller{
		client:        client,
		registry:      registry,
		namespace:     namespace,
		scopedSecrets: scopedSecrets,
		filters:       filters,
	}
	c.secretsSynced = cacheSynced(registry.Secrets, stop, opts.WithName("secrets-synced"))
	c.configMapsSynced = cacheSynced(registry.ConfigMaps, stop, opts.WithName("configmaps-synced"))
	c.traffic = policy.TrafficPolicyInputs{
		RootNamespace:  namespace,
		Services:       registry.KubernetesServices,
		EndpointSlices: registry.EndpointSlices,
		Pods:           registry.Pods,
		Resolve:        resolve,
		PodsByNamespace: krt.NewIndex(registry.Pods, "status-pods-by-namespace",
			func(p *corev1.Pod) []string { return []string{p.Namespace} }),
		ServicesByNamespace: krt.NewIndex(registry.KubernetesServices, "status-services-by-namespace",
			func(s *corev1.Service) []string { return []string{s.Namespace} }),
		EndpointSlicesByService: krt.NewIndex(registry.EndpointSlices, "status-endpoints-by-service",
			func(s *discoveryv1.EndpointSlice) []string {
				name := s.Labels[discoveryv1.LabelServiceName]
				if name == "" {
					return nil
				}
				return []string{s.Namespace + "/" + name}
			}),
	}
	sources := newSources(registry, opts)
	profiles := krt.NewCollection(sources, func(_ krt.HandlerContext, s source) *compiledProfile {
		if s.Profile == nil {
			return nil
		}
		return c.compileProfile(s)
	}, opts.WithName("compiled-profiles")...)
	profileResults := krt.NewCollection(profiles, c.profileStatus, opts.WithName("profile-results")...)
	trafficResults := krt.NewCollection(sources, func(ctx krt.HandlerContext, s source) *result {
		if s.Traffic == nil {
			return nil
		}
		return c.trafficStatus(ctx, s)
	}, opts.WithName("traffic-results")...)
	c.results = krt.JoinCollection([]krt.Collection[result]{profileResults, trafficResults},
		opts.WithName("results")...)
	return c, nil
}

func cacheSynced(cache krt.Syncer, stop <-chan struct{}, options []krt.CollectionOption) krt.Singleton[bool] {
	ready := cache.HasSynced()
	state := krt.NewStatic(&ready, true, options...)
	go func() {
		if cache.WaitUntilSynced(stop) {
			synced := true
			state.Set(&synced)
		}
	}()
	return state
}

// Run elects one writer per installation; validation itself remains read-only.
func (c *Controller) Run(ctx context.Context) {
	if !c.results.WaitUntilSynced(ctx.Done()) {
		return
	}
	hostname, err := os.Hostname()
	if err != nil {
		log.Error("read status writer hostname", "error", err)
		return
	}
	identity := hostname + "-" + string(uuid.NewUUID())
	for ctx.Err() == nil {
		lock := &resourcelock.LeaseLock{
			LeaseMeta: metav1.ObjectMeta{Name: "agentiod-policy-status",
				Namespace: c.namespace},
			Client:     c.client.Kube().CoordinationV1(),
			LockConfig: resourcelock.ResourceLockConfig{Identity: identity},
		}
		elector, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
			Lock:            lock,
			LeaseDuration:   30 * time.Second,
			RenewDeadline:   20 * time.Second,
			RetryPeriod:     5 * time.Second,
			ReleaseOnCancel: true,
			Callbacks: leaderelection.LeaderCallbacks{
				OnStartedLeading: c.runWriter,
				OnStoppedLeading: func() {},
			},
		})
		if err != nil {
			log.Error("create policy status leader elector", "error", err)
			return
		}
		elector.Run(ctx)
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
		}
	}
}

func (c *Controller) runWriter(ctx context.Context) {
	log.Info("policy status writer started")
	queue := controllers.NewQueue("policy-status", controllers.WithMaxAttempts(math.MaxInt),
		controllers.WithGenericReconciler(func(key any) error {
			if ctx.Err() != nil {
				return nil
			}
			current := c.results.GetKey(key.(string))
			if current == nil {
				return nil
			}
			return c.write(ctx, *current)
		}))
	registration := c.results.Register(func(event krt.Event[result]) {
		if event.New != nil {
			queue.Add(event.New.ResourceName())
		}
	})
	defer registration.UnregisterHandler()
	queue.Run(ctx.Done())
	if err := queue.WaitForClose(0); err != nil {
		log.Error("wait for policy status writer", "error", err)
	}
	log.Info("policy status writer stopped")
}
