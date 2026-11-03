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

package kubernetes

import (
	"fmt"
	"slices"

	corev1 "k8s.io/api/core/v1"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	podsource "github.com/openkruise/agentio/pkg/registry/kubernetes/pod"
)

// PodScopeResolver resolves TokenReview evidence through the live registry.
type PodScopeResolver struct {
	pods                  krt.Collection[*corev1.Pod]
	workloads             krt.Collection[model.Workload]
	configurations        krt.Collection[model.AgentioConfiguration]
	clusterID             string
	rootNamespace         string
	ztunnelServiceAccount string
	synced                func() bool
}

func (r *Registry) PodScopeResolver(workloads krt.Collection[model.Workload]) *PodScopeResolver {
	return &PodScopeResolver{
		pods:                  r.Pods,
		workloads:             workloads,
		configurations:        r.AgentioConfig,
		clusterID:             r.options.ClusterID,
		rootNamespace:         r.options.RootNamespace,
		ztunnelServiceAccount: r.options.ZTunnelServiceAccount,
		synced: func() bool {
			return r.HasSynced() && workloads.HasSynced()
		},
	}
}

func (s *PodScopeResolver) ResolveScope(peer model.PeerIdentity, nodeName string) (model.ClientScope, error) {
	if !s.synced() {
		return model.ClientScope{}, fmt.Errorf("registry is not synced: %w", model.ErrScopeNotReady)
	}
	pod, err := activeCallerPod(s.pods, peer)
	if err != nil {
		return model.ClientScope{}, err
	}
	if nodeName != "" && pod.Spec.NodeName != nodeName {
		return model.ClientScope{}, fmt.Errorf("client node does not match the bound Pod")
	}
	source := podsource.SourceRef(s.clusterID, string(pod.UID))
	workload := s.workloads.GetKey(podsource.WorkloadUID(s.clusterID, pod))
	if workload != nil {
		if workload.Source != source ||
			workload.Namespace != pod.Namespace || workload.Name != pod.Name {
			return model.ClientScope{}, fmt.Errorf("client Pod does not match its active Workload")
		}
		if workload.GatewayKey != "" {
			return model.ClientScope{
				Class:       model.ClientEgressGateway,
				Principal:   workload.Principal,
				WorkloadUID: workload.UID,
				Source:      source,
				GatewayKey:  workload.GatewayKey,
			}, nil
		}
		configuration := s.configurations.GetKey("effective")
		if slices.Contains(configuration.Value.GetTrustedEpeIdentities(), workload.Principal.String()) {
			return model.ClientScope{
				Class: model.ClientEPE, Principal: workload.Principal,
				WorkloadUID: workload.UID, Source: source,
			}, nil
		}
	}
	if pod.Namespace == s.rootNamespace && pod.Spec.ServiceAccountName == s.ztunnelServiceAccount && nodeName != "" {
		// A shared proxy is authorized by its verified node binding. It need not have
		// a certificate-bearing Workload of its own.
		return model.ClientScope{Class: model.ClientSharedZTunnel, Source: source, NodeName: pod.Spec.NodeName}, nil
	}
	if workload == nil {
		return model.ClientScope{}, fmt.Errorf("client Pod has no active Workload: %w", model.ErrScopeNotReady)
	}
	return model.ClientScope{
		Class:       model.ClientDedicatedZTunnel,
		Principal:   workload.Principal,
		WorkloadUID: workload.UID,
		Source:      source,
	}, nil
}
