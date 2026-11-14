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

package compiler

import (
	"testing"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	dfpclusterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/clusters/dynamic_forward_proxy/v3"
	"google.golang.org/protobuf/proto"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/internal/testutil"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/networking"
)

func TestGatewayExtProcDependenciesFollowOverrides(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := krt.NewOptionsBuilder(stop, "", nil)
	inputs := validCompilerInputs(stop)
	declarations := []model.Gateway{
		{Namespace: "demo", Name: "inherit", Config: &configv1.EgressGateway{}},
		{
			Namespace: "demo",
			Name:      "override",
			Config:    &configv1.EgressGateway{ExtProc: &configv1.ExtProcProvider{Service: "own.demo.svc"}},
		},
		{Namespace: "demo", Name: "disabled", Config: &configv1.EgressGateway{ExtProc: &configv1.ExtProcProvider{}}},
	}
	gateways := krt.NewMutableCollection[model.Gateway](nil, declarations, options.WithName("gateways")...)
	config := gatewayGlobalExtProc{Provider: &configv1.ExtProcProvider{Service: "global.demo.svc"}}
	initial := config
	global := krt.NewStatic(&initial, true, options.WithName("global")...)
	authorizationConfig := krt.NewStatic(&configuration{}, true, options.WithName("configuration")...)
	publish := func() {
		next := config
		global.Set(&next)
	}
	resources := newGatewayResources(
		inputs,
		newBaseIndexes(inputs),
		global,
		authorizationConfig,
		gateways.AsCollection(),
		newFailureRecorder(),
		options.WithName,
	)
	testutil.Eventually(t, resources.HasSynced, "gateway resources synced")
	settle()
	count := func() uint64 { return resources.Metadata()["recomputeTotal"].(uint64) }
	host := func(gateway, cluster string) string {
		t.Helper()
		resource := resources.GetKey(gatewayResourceName(model.ClusterType, "demo/"+gateway, cluster))
		if resource == nil {
			return ""
		}
		value := &clusterv3.Cluster{}
		if err := resource.Value.UnmarshalTo(value); err != nil {
			t.Fatal(err)
		}
		return value.GetLoadAssignment().GetEndpoints()[0].GetLbEndpoints()[0].GetEndpoint().
			GetAddress().
			GetSocketAddress().
			GetAddress()
	}
	before := count()
	config.Provider = &configv1.ExtProcProvider{Service: "global-new.demo.svc"}
	publish()
	testutil.Eventually(
		t,
		func() bool { return host("inherit", networking.ExtProcCluster) == "global-new.demo.svc" },
		"inherited primary updated",
	)
	settle()
	if got := count() - before; got != 1 {
		t.Fatalf("primary change rebuilt %d gateways, want only inherited gateway", got)
	}
	if host("override", networking.ExtProcCluster) != "own.demo.svc" ||
		host("disabled", networking.ExtProcCluster) != "" {
		t.Fatal("global primary change altered override or disabled gateway")
	}
	for _, service := range []string{"audit.demo.svc", "audit-new.demo.svc", ""} {
		before = count()
		config.Additional = nil
		if service != "" {
			config.Additional = []*configv1.ExtProcProvider{{Name: "audit", Service: service}}
		}
		publish()
		testutil.Eventually(t, func() bool {
			return host("inherit", "agentio.additional-ext-proc.audit") == service &&
				host("override", "agentio.additional-ext-proc.audit") == service
		}, "additional processor add/update/removal reached both enabled gateways")
		settle()
		if got := count() - before; got != 2 {
			t.Fatalf("additional change rebuilt %d gateways, want inherited and override", got)
		}
		if host("disabled", "agentio.additional-ext-proc.audit") != "" {
			t.Fatal("disabled gateway received additional processor")
		}
	}
	// Switching the override back to inheritance must restore its primary dependency.
	inherited := declarations[1]
	inherited.Config = proto.Clone(inherited.Config).(*configv1.EgressGateway)
	inherited.Config.ExtProc = nil
	gateways.ConditionalUpdateObject(inherited)
	testutil.Eventually(
		t,
		func() bool { return host("override", networking.ExtProcCluster) == "global-new.demo.svc" },
		"override now inherits",
	)
	settle()
	before = count()
	config.Provider = &configv1.ExtProcProvider{Service: "global-last.demo.svc"}
	publish()
	testutil.Eventually(t, func() bool {
		return host("inherit", networking.ExtProcCluster) == "global-last.demo.svc" &&
			host("override", networking.ExtProcCluster) == "global-last.demo.svc"
	}, "primary dependency restored")
	settle()
	if got := count() - before; got != 2 {
		t.Fatalf("primary change rebuilt %d gateways after override removal, want 2", got)
	}
	for _, cidr := range []string{"192.0.2.0/24", "198.51.100.0/24", ""} {
		settings := &configv1.EgressAuthorization{}
		if cidr != "" {
			settings.DeniedCidrs = []string{cidr}
		}
		authorizationConfig.Set(&configuration{Config: &configv1.AgentioConfig{EgressAuthorization: settings}})
		testutil.Eventually(t, func() bool {
			for _, gateway := range declarations {
				resource := resources.GetKey(
					gatewayResourceName(
						model.ClusterType,
						gateway.ResourceName()+"|agentio-egress",
						networking.HTTPDynamicForwardProxy,
					),
				)
				if resource == nil {
					return false
				}
				cluster := new(clusterv3.Cluster)
				if err := resource.Value.UnmarshalTo(cluster); err != nil {
					t.Fatal(err)
				}
				dfp := new(dfpclusterv3.ClusterConfig)
				if err := cluster.GetClusterType().GetTypedConfig().UnmarshalTo(dfp); err != nil {
					t.Fatal(err)
				}
				ranges := dfp.GetDnsCacheConfig().GetResolvedAddressFilter().GetRanges()
				if cidr == "" {
					if len(ranges) != 9 {
						return false
					}
				} else if len(ranges) != 11 || ranges[9].GetAddressPrefix()+"/24" != cidr {
					return false
				}
				legacy := resources.GetKey(
					gatewayResourceName(model.ClusterType, gateway.ResourceName(), networking.HTTPDynamicForwardProxy),
				)
				if (legacy != nil) != (cidr == "") {
					return false
				}
			}
			return true
		}, "egress authorization add/update/clear reached every gateway, including ext_proc disabled")
	}
}
