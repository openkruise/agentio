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

package xds

import (
	"context"
	"fmt"
	"testing"

	"google.golang.org/protobuf/types/known/anypb"

	workloadv1 "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/pkg/model"
	xdsstore "github.com/openkruise/agentio/pkg/xds/store"
)

func BenchmarkAuthorizationGeneratorIncremental(b *testing.B) {
	const authorizationCount = 10_000
	const workloadCount = 100
	const targetName = "demo/policy-005000"
	workload := func(uid, node string, policies []string) model.Resource {
		resource, err := model.NewResource(
			model.ResourceKey{TypeURL: model.AddressType, Name: uid}, "",
			mustAny(&workloadv1.Address{Type: &workloadv1.Address_Workload{Workload: &workloadv1.Workload{
				Uid:                   uid,
				Namespace:             "demo",
				Node:                  node,
				AuthorizationPolicies: policies,
			}}}), nil,
			model.ResourceFacts{Workload: &model.WorkloadResourceFacts{Namespace: "demo",
				WorkloadUID:       uid,
				Source:            model.SourceRef{Registry: "kubernetes/test", Key: uid},
				NodeName:          node,
				Principal:         model.MustServiceAccountPrincipal("demo", "default"),
				AuthorizationRefs: policies,
			}},
		)
		if err != nil {
			b.Fatal(err)
		}
		return resource
	}
	resources := make([]model.Resource, 0, authorizationCount+workloadCount+1)
	resources = append(resources, workload("uid-000", "node-a", []string{targetName}))
	for index := 1; index < workloadCount; index++ {
		resources = append(resources, workload(fmt.Sprintf("uid-%03d", index), "node-a", nil))
	}
	oldRemote := workload("uid-remote", "node-z", nil)
	resources = append(resources, oldRemote)
	value := &anypb.Any{TypeUrl: model.WorkloadAuthorizationType, Value: []byte("authorization")}
	for index := range authorizationCount {
		name := fmt.Sprintf("demo/policy-%06d", index)
		resources = append(resources, model.Resource{
			Key:     model.ResourceKey{TypeURL: model.WorkloadAuthorizationType, Name: name},
			XDSName: name,
			Value:   value,
			Hash:    name + "-old",
			Facts: model.ResourceFacts{Authorization: &model.AuthorizationResourceFacts{
				Scope: model.AuthorizationScopeWorkload,
			}},
		})
	}
	before, err := model.NewResourceSet(resources)
	if err != nil {
		b.Fatal(err)
	}
	targetKey := model.ResourceKey{TypeURL: model.WorkloadAuthorizationType, Name: targetName}
	oldTarget, found := before.Get(targetKey)
	if !found {
		b.Fatalf("target Authorization %q not found", targetName)
	}
	newTarget := oldTarget
	newTarget.Hash = targetName + "-new"
	afterPolicy, changed, err := before.Apply([]model.ResourceChange{{Key: targetKey, New: &newTarget}})
	if err != nil || !changed {
		b.Fatalf("build Authorization transition: changed=%v err=%v", changed, err)
	}
	policyUpdate := updateBetween(before, afterPolicy, []model.ResourceChange{{
		Key: targetKey,
		Old: &oldTarget,
		New: &newTarget,
	}})

	newRemote := oldRemote
	newRemote.Hash += "-new"
	afterChurn, changed, err := before.Apply([]model.ResourceChange{{Key: oldRemote.Key, New: &newRemote}})
	if err != nil || !changed {
		b.Fatalf("build Address churn transition: changed=%v err=%v", changed, err)
	}
	churnUpdate := updateBetween(before, afterChurn, []model.ResourceChange{{
		Key: oldRemote.Key,
		Old: &oldRemote,
		New: &newRemote,
	}})

	dedicated := model.ClientScope{
		Class:       model.ClientDedicatedZTunnel,
		Principal:   model.MustServiceAccountPrincipal("demo", "default"),
		WorkloadUID: "uid-000",
		Source:      model.SourceRef{Registry: "kubernetes/test", Key: "uid-000"},
	}
	node := model.ClientScope{Class: model.ClientSharedZTunnel, NodeName: "node-a"}
	for _, benchmark := range []struct {
		name          string
		scope         model.ClientScope
		snapshot      model.ResourceSet
		update        xdsstore.Update
		wantResources int
	}{
		{
			name:          "change=policy/client=dedicated",
			scope:         dedicated,
			snapshot:      afterPolicy,
			update:        policyUpdate,
			wantResources: 1,
		},
		{
			name:          "change=policy/client=shared/local-workloads=100",
			scope:         node,
			snapshot:      afterPolicy,
			update:        policyUpdate,
			wantResources: 1,
		},
		{
			name:          "change=unrelated-address/client=shared/local-workloads=100",
			scope:         node,
			snapshot:      afterChurn,
			update:        churnUpdate,
			wantResources: 0,
		},
	} {
		b.Run("policies=10000/"+benchmark.name, func(b *testing.B) {
			request := GenerationRequest{
				Scope:        benchmark.scope,
				TypeURL:      model.WorkloadAuthorizationType,
				Subscription: SubscriptionView{wildcard: true},
				Snapshot:     benchmark.snapshot,
				Update:       benchmark.update,
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				delta, err := (AuthorizationGenerator{}).Generate(context.Background(), request)
				if err != nil || len(delta.Resources) != benchmark.wantResources {
					b.Fatalf("Generate() resources=%d err=%v, want %d resources",
						len(delta.Resources), err, benchmark.wantResources)
				}
			}
		})
	}
}
