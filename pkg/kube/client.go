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

package kube

import (
	"fmt"

	agentsclient "github.com/openkruise/agents-api/client/clientset/versioned"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/rest"
	gatewayclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"
)

// Client owns the typed clients, shared informers, and CRD discovery used by Kubernetes-backed sources and controllers.
type Client interface {
	Kube() kubernetes.Interface
	AgentsAPI() agentsclient.Interface
	GatewayAPI() gatewayclient.Interface
	Metadata() metadata.Interface
	Dynamic() dynamic.Interface
	CrdWatcher() CrdWatcher
	InformerFor(InformerRegistration, InformerOptions) StartableInformer
	Run(stop <-chan struct{})
}

// CrdWatcher is the CRD availability contract used by delayed informers and
// controllers that can start after an optional API is installed.
type CrdWatcher interface {
	HasSynced() bool
	// Synced is closed when the watcher has processed its initial CRD events.
	Synced() <-chan struct{}
	KnownOrCallback(schema.GroupVersionResource, func(stop <-chan struct{})) bool
	WaitForCRD(schema.GroupVersionResource, <-chan struct{}) bool
	Run(stop <-chan struct{})
}

// CrdWatcherOptions controls which CRDs the shared watcher exposes.
type CrdWatcherOptions struct {
	IgnoreResources  string
	IncludeResources string
}

type client struct {
	kube       kubernetes.Interface
	agentsAPI  agentsclient.Interface
	metadata   metadata.Interface
	gatewayAPI gatewayclient.Interface
	dynamic    dynamic.Interface
	watcher    CrdWatcher
	informers  *informerFactory
}

// NewClient constructs the typed clients that share one REST configuration.
func NewClient(config *rest.Config) (Client, error) {
	if config == nil {
		return nil, fmt.Errorf("kubernetes REST config is required")
	}
	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes client: %w", err)
	}
	agentsAPIClient, err := agentsclient.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create Agents API client: %w", err)
	}
	metadataClient, err := metadata.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes metadata client: %w", err)
	}
	gatewayAPIClient, err := gatewayclient.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create Gateway API client: %w", err)
	}
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create dynamic client: %w", err)
	}
	return &client{
		kube:       kubeClient,
		agentsAPI:  agentsAPIClient,
		metadata:   metadataClient,
		gatewayAPI: gatewayAPIClient,
		dynamic:    dynamicClient,
		informers:  newInformerFactory(),
	}, nil
}

// EnableCrdWatcher attaches the process-wide CRD watcher; the constructor hook avoids a kube/kclient import cycle.
func EnableCrdWatcher(value Client, options CrdWatcherOptions) Client {
	concrete, ok := value.(*client)
	if !ok {
		panic("EnableCrdWatcher requires a client created by kube.NewClient")
	}
	if concrete.watcher != nil {
		panic("EnableCrdWatcher called twice for the same client")
	}
	if NewCrdWatcher == nil {
		panic("kube.NewCrdWatcher is unset")
	}
	concrete.watcher = NewCrdWatcher(concrete.metadata, options)
	return concrete
}

// NewCrdWatcher is installed by pkg/kube/kclient to avoid an import cycle.
var NewCrdWatcher func(metadata.Interface, CrdWatcherOptions) CrdWatcher

func (c *client) Kube() kubernetes.Interface { return c.kube }

func (c *client) AgentsAPI() agentsclient.Interface { return c.agentsAPI }

func (c *client) GatewayAPI() gatewayclient.Interface { return c.gatewayAPI }

func (c *client) Metadata() metadata.Interface { return c.metadata }

func (c *client) Dynamic() dynamic.Interface { return c.dynamic }

func (c *client) CrdWatcher() CrdWatcher { return c.watcher }

func (c *client) InformerFor(
	registration InformerRegistration,
	options InformerOptions,
) StartableInformer {
	return c.informers.informerFor(registration, options)
}

func (c *client) Run(stop <-chan struct{}) {
	c.informers.start(stop)
	if c.watcher != nil {
		go c.watcher.Run(stop)
	}
}
