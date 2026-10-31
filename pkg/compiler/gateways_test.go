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
	"errors"
	"maps"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	fileaccesslogv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/file/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"istio.io/istio/pkg/test"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	workloadv1 "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/pkg/features"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/networking"
)

func TestFailureRecorderSerializesGatewayDeleteAndRecreate(t *testing.T) {
	const name = "demo/egress"
	failures := newFailureRecorder()
	failures.record("Gateway", name, errors.New("old invalid gateway"))

	var exists atomic.Bool
	deleteChecked := make(chan struct{})
	releaseDelete := make(chan struct{})
	deleteDone := make(chan struct{})
	go func() {
		failures.clearIf("Gateway", name, func() bool {
			absent := !exists.Load()
			close(deleteChecked)
			<-releaseDelete
			return absent
		})
		close(deleteDone)
	}()

	<-deleteChecked
	exists.Store(true)
	recordDone := make(chan struct{})
	go func() {
		failures.recordIf("Gateway", name, errors.New("new invalid gateway"), exists.Load)
		close(recordDone)
	}()

	close(releaseDelete)
	<-deleteDone
	<-recordDone
	if got := failures.snapshot()["Gateway/"+name]; got != "new invalid gateway" {
		t.Fatalf("current gateway failure = %q, want new invalid gateway", got)
	}
}

func TestRecordGatewayFailureRequiresCurrentGateway(t *testing.T) {
	stop := make(chan struct{})
	defer close(stop)
	gateways := krt.NewMutableCollection[model.Gateway](nil, nil,
		krt.NewOptionsBuilder(stop, "", nil).WithName("test-gateways")...)
	failures := newFailureRecorder()
	configured := model.Gateway{
		Namespace: "demo",
		Name:      "egress",
		Config:    &configv1.EgressGateway{},
		Source:    model.GatewaySourceAgentioConfig,
	}
	gateways.ConditionalUpdateObject(configured)

	recordGatewayFailureIfCurrent(gateways.AsCollection(), failures, configured, errors.New("invalid current gateway"))
	if _, found := failures.snapshot()["Gateway/demo/egress"]; !found {
		t.Fatal("current invalid gateway did not record a failure")
	}
	failures.clear("Gateway", configured.ResourceName())

	replacement := configured
	replacement.Config = &configv1.EgressGateway{
		TlsTermination: &configv1.TlsTerminationConfig{
			IncludeHosts: []string{"new.example.com"},
		},
	}
	gateways.ConditionalUpdateObject(replacement)
	recordGatewayFailureIfCurrent(gateways.AsCollection(), failures, configured, errors.New("stale replaced gateway"))
	if _, found := failures.snapshot()["Gateway/demo/egress"]; found {
		t.Fatal("replaced gateway recorded a stale failure")
	}

	gateways.DeleteObject(replacement.ResourceName())
	recordGatewayFailureIfCurrent(gateways.AsCollection(), failures, replacement, errors.New("stale deleted gateway"))
	if _, found := failures.snapshot()["Gateway/demo/egress"]; found {
		t.Fatal("deleted gateway recorded a stale failure")
	}
}

func TestGatewayAPIDeclarationOverridesOnlyLegacyPolicyFallback(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	builder := krt.NewOptionsBuilder(stop, "", nil)
	options := func(name string) []krt.CollectionOption { return builder.WithName(name) }
	configurations := krt.NewStatic[configuration](&configuration{
		ResourceVersion: "legacy-policy",
		Config: &configv1.AgentioConfig{
			EgressPolicies: []*extensionsv1.EgressPolicy{{
				Policy: extensionsv1.EgressPolicyAction_GATEWAY,
				Gateway: &extensionsv1.GatewayAddress{
					Service: "egress.agentio-system.svc.cluster.local",
					Port:    15008,
				},
			}},
		},
	}, true, options("configuration")...)
	externalConfig := &configv1.EgressGateway{
		ExtProc: &configv1.ExtProcProvider{Service: "epe.agentio-system.svc.cluster.local", Port: 9002},
	}
	external := krt.NewStaticCollection[model.Gateway](nil, []model.Gateway{{
		Namespace: "agentio-system",
		Name:      "egress",
		Config:    externalConfig,
		Source:    model.GatewaySourceGatewayAPI,
	}}, options("gateway-api")...)

	merged := newGatewayDeclarations(configurations, external, options)
	if !merged.WaitUntilSynced(stop) {
		t.Fatal("merged gateway declarations did not sync")
	}
	eventually(t, func() bool {
		gateway := merged.GetKey("agentio-system/egress")
		return gateway != nil && gateway.Source == model.GatewaySourceGatewayAPI &&
			gateway.Config.GetExtProc().GetService() == externalConfig.GetExtProc().GetService()
	}, "Gateway API declaration to replace the inferred legacy fallback")
}

func TestGatewayAPIParameterUpdatePublishesIncrementalRoutesWithLegacyPolicyReference(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	agentioConfig := krt.NewMutableCollection[model.AgentioConfiguration](nil, nil, options...)
	gatewayAPI := krt.NewMutableCollection[model.Gateway](nil, nil, options...)
	inputs := validCompilerInputs(stop)
	inputs.AgentioConfig = agentioConfig.AsCollection()
	inputs.Gateways = gatewayAPI.AsCollection()

	agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{
		ResourceVersion: "legacy-policy",
		Value: &configv1.AgentioConfig{
			EgressPolicies: []*extensionsv1.EgressPolicy{{
				Policy: extensionsv1.EgressPolicyAction_GATEWAY,
				Gateway: &extensionsv1.GatewayAddress{
					Service: "egress.agentio-system.svc.cluster.local",
					Port:    15008,
				},
			}},
		},
	})
	gatewayWithTimeout := func(timeout time.Duration) model.Gateway {
		return model.Gateway{
			Namespace: "agentio-system",
			Name:      "egress",
			Source:    model.GatewaySourceGatewayAPI,
			Config: &configv1.EgressGateway{ConnectionPool: &configv1.ConnectionPoolSettings{
				Http: &configv1.ConnectionPoolHttpSettings{
					DefaultRoute: &configv1.HttpRouteSettings{Timeout: durationpb.New(timeout)},
				},
			}},
		}
	}
	gatewayAPI.ConditionalUpdateObject(gatewayWithTimeout(7 * time.Second))
	compiled, err := New(inputs, krt.NewOptionsBuilder(stop, "", nil))
	if err != nil {
		t.Fatal(err)
	}
	if !compiled.WaitUntilSynced(stop) {
		t.Fatal("compiler did not sync")
	}
	routeTimeout := func() time.Duration {
		for _, resource := range currentSnapshot(t, compiled).ListResourcesOwnedByGateway(model.RouteType, "agentio-system/egress") {
			if resource.XDSName != networking.HTTPDynamicForwardProxy {
				continue
			}
			route := &routev3.RouteConfiguration{}
			if err := resource.Value.UnmarshalTo(route); err != nil {
				t.Fatal(err)
			}
			for _, candidate := range route.GetVirtualHosts()[0].GetRoutes() {
				if candidate.GetName() == "default" {
					return candidate.GetRoute().GetTimeout().AsDuration()
				}
			}
		}
		return 0
	}
	eventually(t, func() bool { return routeTimeout() == 7*time.Second }, "initial Gateway API route timeout")
	recorder := newRecorder(compiled.Resources())

	gatewayAPI.ConditionalUpdateObject(gatewayWithTimeout(11 * time.Second))
	eventually(t, func() bool {
		return routeTimeout() == 11*time.Second && recorder.has(gatewayResourceName(
			model.RouteType, "agentio-system/egress", networking.HTTPDynamicForwardProxy))
	}, "parametersRef-equivalent update to publish an incremental RDS resource")
}

func TestGatewayResourcesCarryClusterOptions(t *testing.T) {
	const rootCAPath = "/etc/ssl/custom.pem"
	test.SetForTest(t, &features.GatewayConnectTimeout, 7*time.Second)
	test.SetForTest(t, &features.GatewayRootCAPath, rootCAPath)
	resources, err := gatewayResourcesFor(
		model.Gateway{
			Namespace: "agentio-system",
			Name:      "egress",
			Config:    &configv1.EgressGateway{},
		},
		nil,
		nil,
		"agentiod.agentio-system.svc:15012",
		"cluster.local",
		nil,
		"",
		"",
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("gatewayResourcesFor: %v", err)
	}
	clusters := make(map[string]*clusterv3.Cluster)
	for _, resource := range resources {
		if resource.Key.TypeURL != model.ClusterType {
			continue
		}
		cluster := &clusterv3.Cluster{}
		if err := resource.Value.UnmarshalTo(cluster); err != nil {
			t.Fatalf("unmarshal cluster %s: %v", resource.XDSName, err)
		}
		clusters[resource.XDSName] = cluster
	}
	if got := clusters[networking.PassthroughCluster].GetConnectTimeout().AsDuration(); got != 7*time.Second {
		t.Fatalf("passthrough connect timeout = %s, want 7s", got)
	}
	tlsContext := &tlsv3.UpstreamTlsContext{}
	if err := clusters[networking.TLSConnectOriginate].GetTransportSocket().
		GetTypedConfig().
		UnmarshalTo(tlsContext); err != nil {
		t.Fatalf("unmarshal TLS origination context: %v", err)
	}
	if got := tlsContext.GetCommonTlsContext().GetValidationContext().GetTrustedCa().GetFilename(); got != rootCAPath {
		t.Fatalf("TLS origination root CA = %q, want %q", got, rootCAPath)
	}
}

func TestGatewayAccessLogFormatUpdateAndReset(t *testing.T) {
	fixture := newIncrementalFixture(t)
	config := &configv1.AgentioConfig{
		EgressGateways: []*configv1.EgressGateway{
			{Namespace: "demo", Name: "egress-a"},
			{Namespace: "demo", Name: "egress-b"},
		},
	}
	fixture.agentioConfig.ConditionalUpdateObject(
		model.AgentioConfiguration{ResourceVersion: "defaults", Value: config},
	)
	wantA := gatewayResourceName(model.ListenerType, "demo/egress-a", networking.MainForward)
	wantB := gatewayResourceName(model.ListenerType, "demo/egress-b", networking.MainForward)
	waitSynced(t, fixture.compiler)
	awaitSteadyState(t, fixture.compiler, wantA, wantB)
	beforeA := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress-a")
	beforeB := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress-b")
	recorder := newRecorder(fixture.compiler.Resources())

	updated := proto.Clone(config).(*configv1.AgentioConfig)
	updated.EgressGateways[0].AccessLogFormat = &configv1.AccessLogFormat{
		Text: new("%REQ(:SCHEME)% %PROTOCOL%"),
	}
	fixture.agentioConfig.ConditionalUpdateObject(
		model.AgentioConfiguration{ResourceVersion: "custom-format", Value: updated},
	)
	eventually(t, func() bool {
		resource := fixture.compiler.graph.resources.GetKey(wantA)
		if resource == nil || !recorder.has(wantA) {
			return false
		}
		listener := &listenerv3.Listener{}
		if err := resource.Value.UnmarshalTo(listener); err != nil {
			t.Fatal(err)
		}
		for _, chain := range listener.GetFilterChains() {
			for _, filter := range chain.GetFilters() {
				if filter.GetName() != "envoy.filters.network.http_connection_manager" {
					continue
				}
				hcm := &hcmv3.HttpConnectionManager{}
				if err := filter.GetTypedConfig().UnmarshalTo(hcm); err != nil {
					t.Fatal(err)
				}
				if len(hcm.GetAccessLog()) != 1 {
					return false
				}
				fileLog := &fileaccesslogv3.FileAccessLog{}
				if err := hcm.GetAccessLog()[0].GetTypedConfig().UnmarshalTo(fileLog); err != nil {
					t.Fatal(err)
				}
				return fileLog.GetLogFormat().GetTextFormatSource().GetInlineString() == "%REQ(:SCHEME)% %PROTOCOL%\n"
			}
		}
		return false
	}, "gateway format change to publish a new listener with the custom template")

	fixture.agentioConfig.ConditionalUpdateObject(
		model.AgentioConfiguration{ResourceVersion: "reset-format", Value: config},
	)
	eventually(t, func() bool {
		return maps.Equal(beforeA, gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress-a"))
	}, "removing the override to restore the default gateway graph")
	settle()
	for _, changed := range recorder.names() {
		if strings.Contains(changed, "|demo/egress-b|") {
			t.Fatalf("format change invalidated the other gateway: %v", recorder.names())
		}
	}
	if afterB := gatewayGraphHashes(
		currentSnapshot(t, fixture.compiler),
		"demo/egress-b",
	); !maps.Equal(
		beforeB,
		afterB,
	) {
		t.Fatalf("other gateway changed: before=%v after=%v", beforeB, afterB)
	}
}

func TestGatewayExtProcDisableAndRestoreInheritance(t *testing.T) {
	fixture := newIncrementalFixture(t)
	config := &configv1.AgentioConfig{
		SandboxExtProc: &configv1.ExtProcProvider{Service: "epe.demo.svc.cluster.local", Port: 9002},
		EgressGateways: []*configv1.EgressGateway{
			{Namespace: "demo", Name: "egress-a"},
			{Namespace: "demo", Name: "egress-b"},
		},
	}
	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{ResourceVersion: "inherit", Value: config})
	clusterA := gatewayResourceName(model.ClusterType, "demo/egress-a", networking.ExtProcCluster)
	clusterB := gatewayResourceName(model.ClusterType, "demo/egress-b", networking.ExtProcCluster)
	internalA := gatewayResourceName(model.ListenerType, "demo/egress-a", networking.MainInternal)
	forwardA := gatewayResourceName(model.ListenerType, "demo/egress-a", networking.MainForward)
	waitSynced(t, fixture.compiler)
	awaitSteadyState(t, fixture.compiler, clusterA, clusterB, internalA, forwardA)
	beforeA := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress-a")
	beforeB := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress-b")

	disabled := proto.Clone(config).(*configv1.AgentioConfig)
	disabled.EgressGateways[0].ExtProc = &configv1.ExtProcProvider{}
	fixture.agentioConfig.ConditionalUpdateObject(
		model.AgentioConfiguration{ResourceVersion: "disable", Value: disabled},
	)
	eventually(t, func() bool {
		after := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress-a")
		return after[clusterA] == "" &&
			after[internalA] != "" && after[internalA] != beforeA[internalA] &&
			after[forwardA] != "" && after[forwardA] != beforeA[forwardA]
	}, "empty override removes the ext_proc cluster and updates both listeners")
	if failures := fixture.compiler.Failures(); len(failures) != 0 {
		t.Fatalf("empty ext_proc override rejected: %v", failures)
	}
	if afterB := gatewayGraphHashes(
		currentSnapshot(t, fixture.compiler),
		"demo/egress-b",
	); !maps.Equal(
		beforeB,
		afterB,
	) {
		t.Fatalf("disabling egress-a changed egress-b: before=%v after=%v", beforeB, afterB)
	}

	fixture.agentioConfig.ConditionalUpdateObject(
		model.AgentioConfiguration{ResourceVersion: "inherit-again", Value: config},
	)
	eventually(t, func() bool {
		return maps.Equal(beforeA, gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress-a"))
	}, "removing the override restores the inherited ext_proc graph")
}

func TestGatewayTelemetryChangeAffectsOnlyTargetGateway(t *testing.T) {
	fixture := newIncrementalFixture(t)
	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{
		ResourceVersion: "gateways",
		Value: &configv1.AgentioConfig{
			EgressGateways: []*configv1.EgressGateway{
				{Namespace: "demo", Name: "egress-a"},
				{Namespace: "demo", Name: "egress-b"},
			},
		},
	})
	wantA := gatewayResourceName(model.ListenerType, "demo/egress-a|agentio-egress", networking.MainForward)
	wantB := gatewayResourceName(model.ListenerType, "demo/egress-b|agentio-egress", networking.MainForward)
	waitSynced(t, fixture.compiler)
	awaitSteadyState(t, fixture.compiler, wantA, wantB)
	beforeB := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress-b")
	recorder := newRecorder(fixture.compiler.Resources())

	policy, err := model.NewTelemetry(model.TelemetryMetadata{
		Namespace: "demo",
		Name:      "metrics-a",
		Source:    "agentio-system/custom-source",
	}, []string{"demo/egress-a"}, []model.TelemetryMetrics{{
		Overrides: []model.TelemetryMetricOverride{
			{
				Match: model.TelemetryMetricSelector{
					Kind: model.TelemetryMetricStandard,
					Name: "REQUEST_COUNT",
					Mode: model.TelemetryModeServer,
				},
				Disabled: new(true),
			},
		},
	}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	fixture.telemetry.ConditionalUpdateObject(policy)
	eventually(t, func() bool { return recorder.has(wantA) }, "target Gateway Telemetry listener update")
	settle()
	for _, changed := range recorder.names() {
		if strings.Contains(changed, "|demo/egress-b|") {
			t.Fatalf("Telemetry for egress-a invalidated egress-b: %v", recorder.names())
		}
	}
	if afterB := gatewayGraphHashes(
		currentSnapshot(t, fixture.compiler),
		"demo/egress-b",
	); !maps.Equal(
		beforeB,
		afterB,
	) {
		t.Fatalf("non-target Gateway changed:\nbefore=%v\nafter=%v", beforeB, afterB)
	}
}

func TestConflictingTelemetryRetainsTargetGatewayLastKnownGood(t *testing.T) {
	fixture := newIncrementalFixture(t)
	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{
		ResourceVersion: "gateway",
		Value: &configv1.AgentioConfig{
			EgressGateways: []*configv1.EgressGateway{{Namespace: "demo", Name: "egress"}},
		},
	})
	wantListener := gatewayResourceName(model.ListenerType, "demo/egress", networking.MainForward)
	waitSynced(t, fixture.compiler)
	awaitSteadyState(t, fixture.compiler, wantListener)

	first, err := model.NewTelemetry(model.TelemetryMetadata{
		Namespace: "demo",
		Name:      "first",
		Source:    "agentio-system/source-a",
	}, []string{"demo/egress"}, []model.TelemetryMetrics{{Overrides: []model.TelemetryMetricOverride{
		{
			Match: model.TelemetryMetricSelector{
				Kind: model.TelemetryMetricStandard,
				Name: "REQUEST_COUNT",
				Mode: model.TelemetryModeServer,
			},
			TagOverrides: map[string]model.TelemetryMetricTagOverride{"first": {Operation: model.TelemetryTagRemove}},
		},
	}}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	fixture.telemetry.ConditionalUpdateObject(first)
	eventually(t, func() bool {
		_, failed := fixture.compiler.Failures()["Gateway/demo/egress"]
		return !failed
	}, "first Telemetry accepted")
	settle()
	lastGood := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress")

	second, err := model.NewTelemetry(model.TelemetryMetadata{
		Namespace: "demo",
		Name:      "second",
		Source:    "agentio-system/source-b",
	}, []string{"demo/egress"}, nil, nil, []model.TelemetryAccessLogging{{Mode: model.TelemetryModeServer}})
	if err != nil {
		t.Fatal(err)
	}
	fixture.telemetry.ConditionalUpdateObject(second)
	eventually(t, func() bool {
		_, failed := fixture.compiler.Failures()["Gateway/demo/egress"]
		return failed
	}, "same-layer Telemetry conflict recorded")
	settle()
	if got := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress"); !maps.Equal(got, lastGood) {
		t.Fatalf("Telemetry conflict replaced last-known-good graph:\nlast-good=%v\ngot=%v", lastGood, got)
	}

	fixture.telemetry.DeleteObject(second.ResourceName())
	eventually(t, func() bool {
		_, failed := fixture.compiler.Failures()["Gateway/demo/egress"]
		return !failed
	}, "Telemetry conflict recovery")
}

func TestEnvoyFilterChangeAffectsOnlyTargetGateway(t *testing.T) {
	fixture := newIncrementalFixture(t)
	a := &configv1.EgressGateway{Namespace: "demo", Name: "egress-a"}
	b := &configv1.EgressGateway{Namespace: "demo", Name: "egress-b"}
	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{
		ResourceVersion: "gateways",
		Value: &configv1.AgentioConfig{
			EgressGateways: []*configv1.EgressGateway{a, b},
		},
	})
	waitSynced(t, fixture.compiler)
	aCluster := gatewayResourceName(model.ClusterType, "demo/egress-a", networking.MainForward)
	bCluster := gatewayResourceName(model.ClusterType, "demo/egress-b", networking.MainForward)
	awaitSteadyState(t, fixture.compiler, aCluster, bCluster)
	before := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress-b")
	recorder := newRecorder(fixture.compiler.Resources())

	fixture.gatewayPatches.ConditionalUpdateObject(testClusterGatewayPatch(t,
		"patch-a", "agentio-system/config-sources", "1", "demo/egress-a", "patched-a"))

	eventually(t, func() bool { return recorder.has(aCluster) }, "target Gateway cluster patched")
	settle()
	for _, changed := range recorder.names() {
		if strings.Contains(changed, "|demo/egress-b|") {
			t.Fatalf("EnvoyFilter for egress-a invalidated egress-b: %v", recorder.names())
		}
	}
	after := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress-b")
	if !maps.Equal(before, after) {
		t.Fatalf("non-target Gateway graph changed:\nbefore=%v\nafter=%v", before, after)
	}
}

func TestDuplicateEnvoyFilterIdentityRetainsTargetGatewayLastKnownGood(t *testing.T) {
	fixture := newIncrementalFixture(t)
	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{
		ResourceVersion: "gateway",
		Value: &configv1.AgentioConfig{
			EgressGateways: []*configv1.EgressGateway{{Namespace: "demo", Name: "egress"}},
		},
	})
	wantCluster := gatewayResourceName(model.ClusterType, "demo/egress", networking.MainForward)
	waitSynced(t, fixture.compiler)
	awaitSteadyState(t, fixture.compiler, wantCluster)
	baseline := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress")

	filter := testClusterGatewayPatch(t, "shared", "agentio-system/source-a", "1", "demo/egress", "last-good")
	fixture.gatewayPatches.ConditionalUpdateObject(filter)
	eventually(t, func() bool {
		return !maps.Equal(gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress"), baseline)
	}, "first EnvoyFilter applied")
	settle()
	lastGood := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress")

	duplicate := filter
	duplicate.Source = "agentio-system/source-b"
	duplicate.ResourceVersion = "2"
	fixture.gatewayPatches.ConditionalUpdateObject(duplicate)
	eventually(t, func() bool {
		_, found := fixture.compiler.Failures()["Gateway/demo/egress"]
		return found
	}, "duplicate EnvoyFilter records target Gateway failure")
	settle()
	if got := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress"); !maps.Equal(got, lastGood) {
		t.Fatalf("duplicate EnvoyFilter replaced last-known-good gateway graph:\nlast-good=%v\ngot=%v", lastGood, got)
	}
}

func TestDuplicateEnvoyFilterIdentityAcrossTargetsFailsTargetUnionClosed(t *testing.T) {
	fixture := newIncrementalFixture(t)
	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{
		ResourceVersion: "gateways",
		Value: &configv1.AgentioConfig{
			EgressGateways: []*configv1.EgressGateway{
				{Namespace: "demo", Name: "egress-a"},
				{Namespace: "demo", Name: "egress-b"},
			},
		},
	})
	wantA := gatewayResourceName(model.ClusterType, "demo/egress-a", networking.MainForward)
	wantB := gatewayResourceName(model.ClusterType, "demo/egress-b", networking.MainForward)
	waitSynced(t, fixture.compiler)
	awaitSteadyState(t, fixture.compiler, wantA, wantB)
	baselineA := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress-a")
	baselineB := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress-b")

	first := testClusterGatewayPatch(t, "shared", "agentio-system/source-a", "1", "demo/egress-a", "patched-a")
	fixture.gatewayPatches.ConditionalUpdateObject(first)
	eventually(t, func() bool {
		return !maps.Equal(gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress-a"), baselineA)
	}, "first source establishes gateway A last-known-good graph")
	lastGoodA := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress-a")

	duplicate := testClusterGatewayPatch(t, "shared", "agentio-system/source-b", "2", "demo/egress-b", "patched-b")
	fixture.gatewayPatches.ConditionalUpdateObject(duplicate)
	eventually(t, func() bool {
		failures := fixture.compiler.Failures()
		_, failedA := failures["Gateway/demo/egress-a"]
		_, failedB := failures["Gateway/demo/egress-b"]
		return failedA && failedB
	}, "duplicate logical identity fails the union of disjoint target Gateways")
	settle()
	if got := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress-a"); !maps.Equal(got, lastGoodA) {
		t.Fatalf("gateway A did not retain last-known-good graph:\nwant=%v\ngot=%v", lastGoodA, got)
	}
	if got := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress-b"); !maps.Equal(got, baselineB) {
		t.Fatalf("gateway B did not retain baseline graph:\nwant=%v\ngot=%v", baselineB, got)
	}

	fixture.gatewayPatches.DeleteObject(duplicate.ResourceName())
	eventually(t, func() bool {
		return len(fixture.compiler.Failures()) == 0
	}, "removing one source resolves both target Gateway conflicts")
	if got := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress-a")[wantA]; got != lastGoodA[wantA] {
		t.Fatalf("gateway A patched cluster hash after recovery = %s, want %s", got, lastGoodA[wantA])
	}
	if got := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress-b")[wantB]; got != baselineB[wantB] {
		t.Fatalf("gateway B baseline cluster hash after recovery = %s, want %s", got, baselineB[wantB])
	}
}

// The semantic configuration is projected into keyed gateways before resource
// generation, so a valid add, update, or delete publishes only that identity.
func TestGatewayConfigChangesAffectOnlyConfiguredGateway(t *testing.T) {
	fixture := newIncrementalFixture(t)
	a := &configv1.EgressGateway{Namespace: "demo", Name: "egress-a"}
	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{
		ResourceVersion: "initial",
		Value: &configv1.AgentioConfig{
			EgressGateways: []*configv1.EgressGateway{a},
		},
	})
	waitSynced(t, fixture.compiler)
	awaitSteadyState(t, fixture.compiler,
		gatewayResourceName(model.ProxyConfigType, "demo/egress-a", "agentio-proxy"))
	recorder := newRecorder(fixture.compiler.Resources())

	b := &configv1.EgressGateway{Namespace: "demo", Name: "egress-b"}
	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{
		ResourceVersion: "add",
		Value: &configv1.AgentioConfig{
			EgressGateways: []*configv1.EgressGateway{a, b},
		},
	})
	bProxy := gatewayResourceName(model.ProxyConfigType, "demo/egress-b", "agentio-proxy")
	eventually(t, func() bool { return recorder.has(bProxy) }, "configured gateway add")
	settle()
	for _, changed := range recorder.names() {
		if strings.Contains(changed, "|demo/egress-a|") {
			t.Fatalf("adding egress-b invalidated egress-a; changed=%v", recorder.names())
		}
	}

	recorder.reset()
	b = &configv1.EgressGateway{
		Namespace:      "demo",
		Name:           "egress-b",
		ExtProc:        &configv1.ExtProcProvider{Service: "epe.demo.svc.cluster.local", Port: 9002},
		TlsTermination: &configv1.TlsTerminationConfig{IncludeHosts: []string{"new.example.com"}},
	}
	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{
		ResourceVersion: "update",
		Value: &configv1.AgentioConfig{
			EgressGateways: []*configv1.EgressGateway{a, b},
		},
	})
	bExtProc := gatewayResourceName(model.ClusterType, "demo/egress-b", networking.ExtProcCluster)
	eventually(t, func() bool { return recorder.has(bExtProc) }, "configured gateway update")
	settle()
	for _, changed := range recorder.names() {
		if strings.Contains(changed, "|demo/egress-a|") {
			t.Fatalf("updating egress-b invalidated egress-a; changed=%v", recorder.names())
		}
	}

	recorder.reset()
	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{
		ResourceVersion: "delete",
		Value: &configv1.AgentioConfig{
			EgressGateways: []*configv1.EgressGateway{a},
		},
	})
	eventually(t, func() bool { return recorder.has(bProxy) }, "configured gateway delete")
	settle()
	for _, changed := range recorder.names() {
		if strings.Contains(changed, "|demo/egress-a|") {
			t.Fatalf("deleting egress-b invalidated egress-a; changed=%v", recorder.names())
		}
	}
	if got := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress-b"); len(got) != 0 {
		t.Fatalf("deleted gateway retained resources: %v", got)
	}
}

// The registry preserves duplicate selected entries in one Gateway.Config; the
// compiler must therefore report the existing fail-closed error and publish no
// resources for that identity.
func TestDuplicateGatewayConfigPublishesNoGraphAndRecordsFailure(t *testing.T) {
	fixture := newIncrementalFixture(t)
	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{
		ResourceVersion: "duplicate",
		Value: &configv1.AgentioConfig{
			EgressGateways: []*configv1.EgressGateway{
				{Namespace: "demo", Name: "egress"},
				{Namespace: "demo", Name: "egress"},
			},
		},
	})
	waitSynced(t, fixture.compiler)

	eventually(t, func() bool {
		_, found := fixture.compiler.Failures()["Gateway/demo/egress"]
		return found
	}, "duplicate gateway configuration failure")
	snapshot := currentSnapshot(t, fixture.compiler)
	for _, typeURL := range []string{model.ClusterType, model.ListenerType, model.RouteType, model.ProxyConfigType} {
		if resources := snapshot.ListResourcesOwnedByGateway(typeURL, "demo/egress"); len(resources) != 0 {
			t.Fatalf("duplicate gateway published %s resources: %v", typeURL, resources)
		}
	}

	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{
		ResourceVersion: "removed",
		Value:           &configv1.AgentioConfig{},
	})
	eventually(t, func() bool {
		_, failed := fixture.compiler.Failures()["Gateway/demo/egress"]
		return !failed
	}, "removed initially invalid gateway clears failure")
}

func TestInvalidSemanticConfigurationRetainsGatewayGraphUntilRecovery(t *testing.T) {
	fixture := newIncrementalFixture(t)
	valid := &configv1.AgentioConfig{
		SandboxExtProc: &configv1.ExtProcProvider{Service: "epe-old.demo.svc.cluster.local", Port: 9002},
		EgressPolicies: []*extensionsv1.EgressPolicy{{
			MatchCidrs: []string{"10.0.0.0/24"},
			Policy:     extensionsv1.EgressPolicyAction_DENY,
		}},
		EgressGateways: []*configv1.EgressGateway{{
			Namespace:      "demo",
			Name:           "egress",
			TlsTermination: &configv1.TlsTerminationConfig{IncludeHosts: []string{"old.example.com"}},
		}},
	}
	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{ResourceVersion: "valid", Value: valid})
	waitSynced(t, fixture.compiler)
	awaitSteadyState(t, fixture.compiler,
		gatewayResourceName(model.ClusterType, "demo/egress", networking.ExtProcCluster),
		gatewayResourceName(model.ListenerType, "demo/egress", networking.MainInternal))
	baseline := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress")
	if len(baseline) == 0 {
		t.Fatal("valid configuration published no gateway graph")
	}

	invalid := &configv1.AgentioConfig{
		SandboxExtProc: &configv1.ExtProcProvider{
			Service:          "epe-new.demo.svc.cluster.local",
			Port:             9002,
			FailureModeAllow: true,
		},
		EgressPolicies: []*extensionsv1.EgressPolicy{{
			MatchCidrs: []string{"not-a-cidr"},
			Policy:     extensionsv1.EgressPolicyAction_DENY,
		}},
		EgressGateways: []*configv1.EgressGateway{{
			Namespace:      "demo",
			Name:           "egress",
			TlsTermination: &configv1.TlsTerminationConfig{IncludeHosts: []string{"new.example.com"}},
		}},
	}
	fixture.agentioConfig.ConditionalUpdateObject(
		model.AgentioConfiguration{ResourceVersion: "invalid", Value: invalid},
	)
	eventually(t, func() bool {
		_, found := fixture.compiler.Failures()["AgentioConfig/configuration"]
		return found
	}, "invalid semantic configuration failure")
	settle()

	effective := fixture.compiler.graph.configuration.Get()
	if effective == nil || effective.ResourceVersion != "valid" ||
		len(effective.Egress.GetEgressPolicies()) != 1 ||
		effective.Egress.GetEgressPolicies()[0].GetMatchCidrs()[0] != "10.0.0.0/24" {
		t.Fatalf("effective policy advanced past last known good: %+v", effective)
	}
	if got := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress"); !maps.Equal(got, baseline) {
		t.Fatalf("gateway graph advanced with rejected configuration:\nold=%v\nnew=%v", baseline, got)
	}
	semanticGateway := fixture.compiler.Gateways().GetKey("demo/egress")
	if semanticGateway == nil ||
		!slices.Equal(semanticGateway.Config.GetTlsTermination().GetIncludeHosts(), []string{"old.example.com"}) {
		t.Fatalf("semantic gateway advanced with rejected configuration: %+v", semanticGateway)
	}

	recovered := &configv1.AgentioConfig{
		SandboxExtProc: invalid.SandboxExtProc,
		EgressPolicies: []*extensionsv1.EgressPolicy{{
			MatchCidrs: []string{"203.0.113.0/24"},
			Policy:     extensionsv1.EgressPolicyAction_DENY,
		}},
		EgressGateways: invalid.EgressGateways,
	}
	fixture.agentioConfig.ConditionalUpdateObject(
		model.AgentioConfiguration{ResourceVersion: "recovered", Value: recovered},
	)
	eventually(t, func() bool {
		current := fixture.compiler.graph.configuration.Get()
		if current == nil || current.ResourceVersion != "recovered" {
			return false
		}
		_, failed := fixture.compiler.Failures()["AgentioConfig/configuration"]
		return !failed && !maps.Equal(gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress"), baseline)
	}, "valid recovery applies policy and gateway changes")
}

func TestInitialInvalidEgressAndTLSGatewayDoNotCreateSandboxReference(t *testing.T) {
	for _, test := range []struct {
		name   string
		config *configv1.AgentioConfig
	}{
		{
			name: "invalid egress",
			config: &configv1.AgentioConfig{EgressPolicies: []*extensionsv1.EgressPolicy{
				{
					Policy:  extensionsv1.EgressPolicyAction_GATEWAY,
					Gateway: &extensionsv1.GatewayAddress{Service: "egress..svc.cluster.local", Port: 15008},
				},
			}},
		},
		{
			name: "TLS include hosts only",
			config: &configv1.AgentioConfig{EgressGateways: []*configv1.EgressGateway{
				{
					Namespace:      "agentio-system",
					Name:           "egress",
					TlsTermination: &configv1.TlsTerminationConfig{IncludeHosts: []string{"api.example.com"}},
				},
			}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newIncrementalFixture(t)
			client := testWorkload("demo", "client", "10.0.0.2")
			fixture.sandboxes.ConditionalUpdateObject(testSandboxForWorkload(client))
			fixture.workloads.ConditionalUpdateObject(client)
			fixture.agentioConfig.ConditionalUpdateObject(
				model.AgentioConfiguration{ResourceVersion: "initial", Value: test.config},
			)
			waitSynced(t, fixture.compiler)
			awaitSteadyState(t, fixture.compiler, addressResourceName("demo", "client"))
			resource, _ := currentSnapshot(
				t,
				fixture.compiler,
			).Get(model.ResourceKey{TypeURL: model.AddressType, Name: client.UID})
			if resource.Facts.Workload != nil && len(resource.Facts.Workload.GatewayReferences) != 0 {
				t.Fatalf("facts = %+v, unexpected gateway reference", resource.Facts)
			}
			address := &workloadv1.Address{}
			if err := resource.Value.UnmarshalTo(address); err != nil {
				t.Fatal(err)
			}
			names := extensionNames(address.GetWorkload().GetExtensions())
			for _, name := range names {
				if name == "egress-policies" {
					t.Fatalf("extensions = %v, unexpected egress policy", names)
				}
			}
		})
	}
}

func TestGatewayWDSOwnershipLifecycle(t *testing.T) {
	fixture := newIncrementalFixture(t)
	gatewaySandbox := testWorkload("demo", "egress-pod", "10.0.0.10")
	gatewaySandbox.Principal = mustTestPrincipal("cluster.local", "ns/demo/sa/gateway-bootstrap")
	unrelatedSandbox := testWorkload("other", "client", "10.0.1.10")
	gatewayService := model.Service{
		Namespace: "demo",
		Name:      "egress",
		Hostname:  "egress.demo.svc.cluster.local",
		Addresses: []string{"10.96.0.10"},
	}
	unrelatedService := model.Service{
		Namespace: "other",
		Name:      "backend",
		Hostname:  "backend.other.svc.cluster.local",
		Addresses: []string{"10.96.1.10"},
	}
	fixture.sandboxes.ConditionalUpdateObject(testSandboxForWorkload(gatewaySandbox))
	fixture.workloads.ConditionalUpdateObject(gatewaySandbox)
	fixture.sandboxes.ConditionalUpdateObject(testSandboxForWorkload(unrelatedSandbox))
	fixture.workloads.ConditionalUpdateObject(unrelatedSandbox)
	fixture.services.ConditionalUpdateObject(gatewayService)
	fixture.services.ConditionalUpdateObject(unrelatedService)
	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{
		ResourceVersion: "empty",
		Value:           &configv1.AgentioConfig{},
	})
	waitSynced(t, fixture.compiler)
	awaitSteadyState(t, fixture.compiler,
		addressResourceName("demo", "egress-pod"), addressResourceName("other", "client"),
		model.AddressType+"|"+gatewayService.ResourceName(), model.AddressType+"|"+unrelatedService.ResourceName())
	baseline := currentSnapshot(t, fixture.compiler)
	unrelatedWorkload, _ := baseline.Get(model.ResourceKey{TypeURL: model.AddressType, Name: unrelatedSandbox.UID})
	unrelatedServiceResource, _ := baseline.Get(
		model.ResourceKey{TypeURL: model.AddressType, Name: unrelatedService.ResourceName()},
	)
	owned := "demo/egress"
	for _, key := range []model.ResourceKey{
		{TypeURL: model.AddressType, Name: gatewaySandbox.UID},
		{TypeURL: model.AddressType, Name: gatewayService.ResourceName()},
	} {
		resource, _ := baseline.Get(key)
		if resource.Facts.GatewayOwner == owned {
			t.Fatalf("resource %v owned before Gateway configuration", key)
		}
	}

	// Registry updates the Workload membership when gateway declarations change.
	gatewaySandbox.GatewayKey = owned
	fixture.workloads.ConditionalUpdateObject(gatewaySandbox)
	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{
		ResourceVersion: "add",
		Value: &configv1.AgentioConfig{EgressGateways: []*configv1.EgressGateway{{
			Namespace: "demo",
			Name:      "egress",
		}}},
	})
	eventually(t, func() bool {
		snapshot := currentSnapshot(t, fixture.compiler)
		workload, workloadFound := snapshot.Get(model.ResourceKey{TypeURL: model.AddressType, Name: gatewaySandbox.UID})
		service, serviceFound := snapshot.Get(
			model.ResourceKey{TypeURL: model.AddressType, Name: gatewayService.ResourceName()},
		)
		return workloadFound && serviceFound && workload.Facts.GatewayOwner == owned &&
			service.Facts.GatewayOwner == owned
	}, "Gateway workload and service gain ownership")
	settle()
	afterAdd := currentSnapshot(t, fixture.compiler)
	if current, _ := afterAdd.Get(
		model.ResourceKey{TypeURL: model.AddressType, Name: unrelatedSandbox.UID},
	); current.Hash != unrelatedWorkload.Hash {
		t.Fatal("Gateway configuration changed unrelated workload")
	}
	if current, _ := afterAdd.Get(
		model.ResourceKey{TypeURL: model.AddressType, Name: unrelatedService.ResourceName()},
	); current.Hash != unrelatedServiceResource.Hash {
		t.Fatal("Gateway configuration changed unrelated service")
	}

	gatewaySandbox.GatewayKey = ""
	fixture.workloads.ConditionalUpdateObject(gatewaySandbox)
	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{
		ResourceVersion: "remove",
		Value:           &configv1.AgentioConfig{},
	})
	eventually(t, func() bool {
		snapshot := currentSnapshot(t, fixture.compiler)
		workload, workloadFound := snapshot.Get(model.ResourceKey{TypeURL: model.AddressType, Name: gatewaySandbox.UID})
		service, serviceFound := snapshot.Get(
			model.ResourceKey{TypeURL: model.AddressType, Name: gatewayService.ResourceName()},
		)
		return workloadFound && serviceFound && workload.Facts.GatewayOwner == "" && service.Facts.GatewayOwner == ""
	}, "Gateway workload and service lose ownership")
}

func TestInvalidGatewayUpdateRetainsLastKnownGoodGraph(t *testing.T) {
	fixture := newIncrementalFixture(t)
	valid := &configv1.AgentioConfig{EgressGateways: []*configv1.EgressGateway{{
		Namespace: "demo",
		Name:      "egress",
	}}}
	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{ResourceVersion: "valid", Value: valid})
	waitSynced(t, fixture.compiler)
	awaitSteadyState(t, fixture.compiler,
		gatewayResourceName(model.ProxyConfigType, "demo/egress", "agentio-proxy"))
	baseline := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress")

	duplicate := &configv1.AgentioConfig{EgressGateways: []*configv1.EgressGateway{
		{Namespace: "demo", Name: "egress"},
		{
			Namespace:      "demo",
			Name:           "egress",
			TlsTermination: &configv1.TlsTerminationConfig{IncludeHosts: []string{"new.example.com"}},
		},
	}}
	fixture.agentioConfig.ConditionalUpdateObject(
		model.AgentioConfiguration{ResourceVersion: "duplicate", Value: duplicate},
	)
	eventually(t, func() bool {
		_, found := fixture.compiler.Failures()["Gateway/demo/egress"]
		return found
	}, "duplicate gateway update failure")
	settle()
	if got := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress"); !maps.Equal(got, baseline) {
		t.Fatalf("invalid gateway update replaced last known good graph:\nold=%v\nnew=%v", baseline, got)
	}

	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{
		ResourceVersion: "removed",
		Value:           &configv1.AgentioConfig{},
	})
	eventually(t, func() bool {
		_, failed := fixture.compiler.Failures()["Gateway/demo/egress"]
		return !failed && len(gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress")) == 0
	}, "removed invalid gateway clears failure and last-known-good graph")

	recovered := &configv1.AgentioConfig{EgressGateways: []*configv1.EgressGateway{{
		Namespace:      "demo",
		Name:           "egress",
		TlsTermination: &configv1.TlsTerminationConfig{IncludeHosts: []string{"new.example.com"}},
	}}}
	fixture.agentioConfig.ConditionalUpdateObject(
		model.AgentioConfiguration{ResourceVersion: "recovered", Value: recovered},
	)
	eventually(t, func() bool {
		_, failed := fixture.compiler.Failures()["Gateway/demo/egress"]
		return !failed && !maps.Equal(gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress"), baseline)
	}, "valid gateway recovery replaces last known good graph")
}

func TestGatewayWDSResourcesCarryOwnership(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	configuredWorkload := testWDSWorkload("egress-a-pod", "egress-a-uid", "10.0.0.10")
	configuredWorkload.Namespace = "agentio-system"
	configuredWorkload.Principal = mustTestPrincipal("cluster.local", "ns/agentio-system/sa/gateway-bootstrap")
	configuredWorkload.GatewayKey = "agentio-system/egress-a"
	lookalikeWorkload := testWDSWorkload("lookalike", "lookalike-uid", "10.0.0.11")
	lookalikeWorkload.Namespace = "agentio-system"
	lookalikeWorkload.Principal = mustTestPrincipal("cluster.local", "ns/agentio-system/sa/gateway-bootstrap")
	configuredService := model.Service{
		Namespace: "agentio-system",
		Name:      "egress-a",
		Hostname:  "egress-a.agentio-system.svc.cluster.local",
		Addresses: []string{"10.96.0.10"},
	}
	lookalikeService := model.Service{
		Namespace: "agentio-system",
		Name:      "lookalike",
		Hostname:  "lookalike.agentio-system.svc.cluster.local",
		Addresses: []string{"10.96.0.11"},
	}
	inputs := validCompilerInputs(stop)
	inputs.Workloads = krt.NewStaticCollection(nil, []model.Workload{configuredWorkload, lookalikeWorkload}, options...)
	inputs.Services = krt.NewStaticCollection(nil, []model.Service{configuredService, lookalikeService}, options...)
	inputs.Gateways = krt.NewStaticCollection(nil, []model.Gateway{{
		Namespace: "agentio-system",
		Name:      "egress-a",
		Config:    &configv1.EgressGateway{},
		Source:    model.GatewaySourceAgentioConfig,
	}}, options...)
	inputs.AgentioConfig = krt.NewStaticCollection(nil, []model.AgentioConfiguration{{
		Value: &configv1.AgentioConfig{EgressGateways: []*configv1.EgressGateway{{
			Namespace: "agentio-system",
			Name:      "egress-a",
		}}},
	}}, options...)
	compiler, err := New(inputs, krt.NewOptionsBuilder(stop, "", nil))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := compileSynced(t, compiler)
	owned := "agentio-system/egress-a"
	for _, key := range []model.ResourceKey{
		{
			TypeURL: model.AddressType,
			Name:    configuredWorkload.UID,
		},
		{
			TypeURL: model.AddressType,
			Name:    configuredService.ResourceName(),
		},
	} {
		resource, found := snapshot.Get(key)
		if !found || resource.Facts.GatewayOwner != owned {
			t.Fatalf("resource %v = %+v, missing Gateway ownership", key, resource)
		}
	}
	for _, key := range []model.ResourceKey{
		{
			TypeURL: model.AddressType,
			Name:    lookalikeWorkload.UID,
		},
		{
			TypeURL: model.AddressType,
			Name:    lookalikeService.ResourceName(),
		},
	} {
		resource, found := snapshot.Get(key)
		if !found {
			t.Fatalf("lookalike resource %v is missing", key)
		}
		if resource.Facts.GatewayOwner != "" {
			t.Fatalf("lookalike resource %v has Gateway ownership: %v", key, resource.Facts)
		}
	}
}

func TestAdditionalExtProcHotUpdate(t *testing.T) {
	fixture := newIncrementalFixture(t)
	first := &configv1.ExtProcProvider{Name: "first", Service: "first.demo.svc", Port: 9002}
	second := &configv1.ExtProcProvider{Name: "second", Service: "second.demo.svc", Port: 9002}
	config := &configv1.AgentioConfig{
		SandboxExtProc: &configv1.ExtProcProvider{Service: "epe.demo.svc"},
		EgressGateways: []*configv1.EgressGateway{{Namespace: "demo", Name: "egress"}},
	}
	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{Value: config})
	key := gatewayResourceName(model.ListenerType, "demo/egress", networking.MainForward)
	waitSynced(t, fixture.compiler)
	awaitSteadyState(t, fixture.compiler, key)
	readNames := func() []string {
		resource := fixture.compiler.graph.resources.GetKey(key)
		if resource == nil {
			return nil
		}
		listener := &listenerv3.Listener{}
		if err := resource.Value.UnmarshalTo(listener); err != nil {
			t.Fatal(err)
		}
		for _, chain := range listener.FilterChains {
			for _, f := range chain.Filters {
				if f.Name != "envoy.filters.network.http_connection_manager" {
					continue
				}
				hcm := &hcmv3.HttpConnectionManager{}
				if err := f.GetTypedConfig().UnmarshalTo(hcm); err != nil {
					t.Fatal(err)
				}
				names := []string{}
				for _, hf := range hcm.HttpFilters {
					if name, ok := strings.CutPrefix(hf.Name, "agentio.additional-ext-proc."); ok {
						names = append(names, name)
					}
				}
				return names
			}
		}
		return nil
	}
	for _, tc := range []struct {
		name      string
		providers []*configv1.ExtProcProvider
		want      []string
	}{
		{"add", []*configv1.ExtProcProvider{first, second}, []string{"first", "second"}},
		{"reorder", []*configv1.ExtProcProvider{second, first}, []string{"second", "first"}},
		{"remove", []*configv1.ExtProcProvider{second}, []string{"second"}},
		{"clear", nil, []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := proto.Clone(config).(*configv1.AgentioConfig)
			next.AdditionalExtProcs = tc.providers
			// Keep ResourceVersion unchanged: content alone must invalidate the projection.
			fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{Value: next})
			eventually(t, func() bool {
				if !slices.Equal(readNames(), tc.want) {
					return false
				}
				for _, name := range []string{"first", "second"} {
					clusterKey := gatewayResourceName(
						model.ClusterType,
						"demo/egress",
						"agentio.additional-ext-proc."+name,
					)
					if (fixture.compiler.graph.resources.GetKey(clusterKey) != nil) != slices.Contains(tc.want, name) {
						return false
					}
				}
				return true
			}, "list content changes LDS and CDS")
		})
	}
	config.AdditionalExtProcs = []*configv1.ExtProcProvider{first}
	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{Value: config})
	eventually(t, func() bool { return slices.Equal(readNames(), []string{"first"}) }, "restore processor")
	next := proto.Clone(config).(*configv1.AgentioConfig)
	next.AdditionalExtProcs[0].Service = "replacement.demo.svc"
	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{Value: next})
	eventually(t, func() bool {
		resource := fixture.compiler.graph.resources.GetKey(
			gatewayResourceName(model.ClusterType, "demo/egress", "agentio.additional-ext-proc.first"),
		)
		if resource == nil {
			return false
		}
		cluster := &clusterv3.Cluster{}
		if err := resource.Value.UnmarshalTo(cluster); err != nil {
			t.Fatal(err)
		}
		return cluster.GetLoadAssignment().GetEndpoints()[0].GetLbEndpoints()[0].GetEndpoint().
			GetAddress().
			GetSocketAddress().
			GetAddress() ==
			"replacement.demo.svc"
	}, "endpoint change updates named CDS resource")
}

func TestNetworkLimitsCompileCommunityVariant(t *testing.T) {
	for _, field := range []string{"bandwidthLimit", "connectConcurrencyLimit"} {
		t.Run(field, func(t *testing.T) {
			settings := new(configv1.EgressGateway)
			limit := `"bandwidthLimit":{"downloadBytesPerSecond":1024}`
			filterName := "agentio.bandwidth"
			if field == "connectConcurrencyLimit" {
				limit = `"maxConcurrentStreams":2`
				filterName = "agentio.connect_concurrency"
			}
			raw := `{"` + field + `":{"rateLimits":[{"actions":[{"filterState":{"key":"sandbox.id","descriptorKey":"sandbox"}}]}],"descriptors":[{"entries":[{"key":"sandbox"}],` + limit + `}]}}`
			if err := protojson.Unmarshal([]byte(raw), settings); err != nil {
				t.Fatal(err)
			}
			resources, err := gatewayResourcesFor(
				model.Gateway{Name: "egress", Namespace: "demo", Config: settings},
				nil,
				nil,
				"agentiod:15012",
				"cluster.local",
				nil,
				"Kubernetes",
				"agentio-system",
				nil,
				nil,
			)
			if err != nil {
				t.Fatal(err)
			}
			if len(resources) == 0 {
				t.Fatal("community gateway resources missing")
			}
			found := false
			for _, resource := range resources {
				if !resource.Facts.AgentioEgress {
					t.Fatalf("unsupported legacy variant published: %v", resource.Key)
				}
				if resource.Key.TypeURL == model.ExtensionConfigurationType && resource.XDSName == filterName {
					message := new(corev3.TypedExtensionConfig)
					if err := resource.Value.UnmarshalTo(message); err != nil {
						t.Fatal(err)
					}
					data, err := protojson.Marshal(message)
					if err != nil {
						t.Fatal(err)
					}
					found = found || strings.Contains(string(data), "libenvoy_agentio_network_limits.so")
				}
			}
			if !found {
				t.Fatal("network limits module not present in compiled ECDS configuration")
			}
		})
	}
}
