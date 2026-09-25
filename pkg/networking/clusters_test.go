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

package networking

import (
	"slices"
	"testing"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	httpupstreamv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	"google.golang.org/protobuf/proto"
	"istio.io/istio/pkg/test"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/features"
	"github.com/openkruise/agentio/pkg/model"
)

func TestGatewayClustersUseConfiguredConnectTimeoutAndRootCA(t *testing.T) {
	const rootCAPath = "/etc/ssl/custom.pem"
	test.SetForTest(t, &features.GatewayConnectTimeout, 7*time.Second)
	test.SetForTest(t, &features.GatewayRootCAPath, rootCAPath)
	resources, err := Build(Inputs{
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local",
		Gateway:          testGateway(nil),
		GlobalExtProc: &configv1.ExtProcProvider{
			Service: "epe.agentio-system.svc",
			Port:    9002,
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	clusters := messagesOf(t, resources, model.ClusterType, func() *clusterv3.Cluster { return &clusterv3.Cluster{} })
	for _, name := range []string{PassthroughCluster, HTTPDynamicForwardProxy, TLSConnectOriginate} {
		if got := clusters[name].GetConnectTimeout().AsDuration(); got != 7*time.Second {
			t.Errorf("cluster %s connect timeout = %s, want 7s", name, got)
		}
	}
	for _, name := range []string{MainInternal, MainForward, ExtProcCluster} {
		if got := clusters[name].GetConnectTimeout().AsDuration(); got != 10*time.Second {
			t.Errorf("cluster %s connect timeout = %s, want owned 10s", name, got)
		}
	}

	tlsContext := &tlsv3.UpstreamTlsContext{}
	if err := clusters[TLSConnectOriginate].GetTransportSocket().GetTypedConfig().UnmarshalTo(tlsContext); err != nil {
		t.Fatalf("unmarshal TLS origination context: %v", err)
	}
	if got := tlsContext.GetCommonTlsContext().GetValidationContext().GetTrustedCa().GetFilename(); got != rootCAPath {
		t.Fatalf("TLS origination root CA = %q, want %q", got, rootCAPath)
	}
}

func TestGatewayTLSOriginationDisablesSharedSessionCache(t *testing.T) {
	resources, err := Build(Inputs{
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local",
		Gateway:          testGateway(nil),
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	clusters := messagesOf(t, resources, model.ClusterType, func() *clusterv3.Cluster { return &clusterv3.Cluster{} })
	for _, name := range []string{TLSConnectOriginate, TLSProxyOriginate} {
		t.Run(name, func(t *testing.T) {
			cluster := clusters[name]
			context := &tlsv3.UpstreamTlsContext{}
			if err := cluster.GetTransportSocket().GetTypedConfig().UnmarshalTo(context); err != nil {
				t.Fatalf("decode TLS context: %v", err)
			}
			// An absent wrapper enables Envoy's default session cache.
			if keys := context.GetMaxSessionKeys(); keys == nil || keys.GetValue() != 0 {
				t.Fatalf("max session keys = %v, want explicit zero to prevent cross-SNI session reuse", keys)
			}
			if got := context.GetCommonTlsContext().GetValidationContext().GetTrustedCa().GetFilename(); got != features.ResolveGatewayRootCAPath() {
				t.Fatalf("trusted CA = %q, want configured roots", got)
			}
			if name == TLSConnectOriginate {
				options := &httpupstreamv3.HttpProtocolOptions{}
				if err := cluster.GetTypedExtensionProtocolOptions()[httpProtocolOptionsType].UnmarshalTo(options); err != nil {
					t.Fatalf("decode HTTP options: %v", err)
				}
				if !options.GetUpstreamHttpProtocolOptions().GetAutoSni() || !options.GetUpstreamHttpProtocolOptions().GetAutoSanValidation() {
					t.Fatal("TLS origination must retain automatic SNI and SAN validation")
				}
			}
		})
	}
}

func TestGatewayClustersUseAgentioStatsAndCircuitBreakers(t *testing.T) {
	resources, err := Build(Inputs{
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local",
		Gateway:          testGateway(nil),
		GlobalExtProc: &configv1.ExtProcProvider{
			Service: "epe.agentio-system.svc",
			Port:    9002,
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	clusters := messagesOf(t, resources, model.ClusterType, func() *clusterv3.Cluster { return &clusterv3.Cluster{} })
	for _, name := range []string{
		MainInternal, MainForward, PassthroughCluster,
		HTTPDynamicForwardProxy, TLSConnectOriginate, TLSProxyOriginate, ExtProcCluster,
	} {
		cluster := clusters[name]
		if got, want := cluster.GetAltStatName(), name+";"; got != want {
			t.Errorf("cluster %s alt stat name = %q, want %q", name, got, want)
		}
		thresholds := cluster.GetCircuitBreakers().GetThresholds()
		if len(thresholds) != 1 {
			t.Errorf("cluster %s circuit breaker thresholds = %d, want 1", name, len(thresholds))
			continue
		}
		if thresholds[0].GetTrackRemaining() {
			t.Errorf("cluster %s enables track_remaining; Agentio does not", name)
		}
	}
}

func TestGatewayClustersUseAgentioDownstreamIdleTimeout(t *testing.T) {
	resources, err := Build(Inputs{
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local",
		Gateway:          testGateway(nil),
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	clusters := messagesOf(t, resources, model.ClusterType, func() *clusterv3.Cluster { return &clusterv3.Cluster{} })
	for _, name := range []string{MainInternal, MainForward, PassthroughCluster, TLSProxyOriginate, HTTPDynamicForwardProxy} {
		protocol := &httpupstreamv3.HttpProtocolOptions{}
		if err := clusters[name].GetTypedExtensionProtocolOptions()[httpProtocolOptionsType].UnmarshalTo(protocol); err != nil {
			t.Fatalf("unmarshal cluster %s HTTP protocol options: %v", name, err)
		}
		if got := protocol.GetCommonHttpProtocolOptions().GetIdleTimeout().AsDuration(); got != 5*time.Minute {
			t.Errorf("cluster %s downstream HTTP idle timeout = %s, want 5m", name, got)
		}
	}
}

func TestGatewayUpstreamTLS(t *testing.T) {
	defaults := []string{
		"ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-RSA-AES128-GCM-SHA256",
		"ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-RSA-AES256-GCM-SHA384",
		"ECDHE-ECDSA-CHACHA20-POLY1305", "ECDHE-RSA-CHACHA20-POLY1305",
		"AES128-GCM-SHA256", "AES256-GCM-SHA384",
	}
	replacement := []string{"AES256-GCM-SHA384", "ECDHE-RSA-AES128-GCM-SHA256"}
	for _, tt := range []struct {
		name     string
		settings *configv1.UpstreamTlsSettings
		min, max tlsv3.TlsParameters_TlsProtocol
		ciphers  []string
	}{
		{"omitted", nil, tlsv3.TlsParameters_TLSv1_2, tlsv3.TlsParameters_TLSv1_3, defaults},
		{"empty settings", &configv1.UpstreamTlsSettings{}, tlsv3.TlsParameters_TLSv1_2, tlsv3.TlsParameters_TLSv1_3, defaults},
		{"empty cipher list", &configv1.UpstreamTlsSettings{CipherSuites: []string{}}, tlsv3.TlsParameters_TLSv1_2, tlsv3.TlsParameters_TLSv1_3, defaults},
		{"TLS 1.2 only", &configv1.UpstreamTlsSettings{MaxProtocolVersion: configv1.UpstreamTlsSettings_TLSV1_2}, tlsv3.TlsParameters_TLSv1_2, tlsv3.TlsParameters_TLSv1_2, defaults},
		{"TLS 1.3 only", &configv1.UpstreamTlsSettings{MinProtocolVersion: configv1.UpstreamTlsSettings_TLSV1_3}, tlsv3.TlsParameters_TLSv1_3, tlsv3.TlsParameters_TLSv1_3, defaults},
		{"replace ciphers in order", &configv1.UpstreamTlsSettings{CipherSuites: replacement}, tlsv3.TlsParameters_TLSv1_2, tlsv3.TlsParameters_TLSv1_3, replacement},
	} {
		t.Run(tt.name, func(t *testing.T) {
			gateway := testGateway(&configv1.EgressGateway{UpstreamTls: tt.settings})
			before := proto.Clone(gateway.Config)
			for _, selected := range []bool{true, false} {
				current := gateway
				if !selected {
					current = testGateway(nil)
					current.Name = "other"
				}
				resources, err := Build(Inputs{
					DiscoveryAddress: "agentiod.agentio-system.svc:15012",
					TrustDomain:      "cluster.local",
					Gateway:          current,
				})
				if err != nil {
					t.Fatal(err)
				}
				minVersion, maxVersion, ciphers := tt.min, tt.max, tt.ciphers
				if !selected {
					minVersion, maxVersion, ciphers = tlsv3.TlsParameters_TLSv1_2, tlsv3.TlsParameters_TLSv1_3, defaults
				}
				clusters := messagesOf(t, resources, model.ClusterType, func() *clusterv3.Cluster { return &clusterv3.Cluster{} })
				for _, name := range []string{TLSConnectOriginate, TLSProxyOriginate} {
					cluster := clusters[name]
					ctx := &tlsv3.UpstreamTlsContext{}
					if err := cluster.GetTransportSocket().GetTypedConfig().UnmarshalTo(ctx); err != nil {
						t.Fatal(err)
					}
					params := ctx.GetCommonTlsContext().GetTlsParams()
					if params.GetTlsMinimumProtocolVersion() != minVersion || params.GetTlsMaximumProtocolVersion() != maxVersion || !slices.Equal(params.GetCipherSuites(), ciphers) {
						t.Fatalf("gateway %s cluster %s TLS parameters = %v, want %v–%v and %v", current.Name, name, params, minVersion, maxVersion, ciphers)
					}
					if ctx.GetMaxSessionKeys() == nil || ctx.GetMaxSessionKeys().GetValue() != 0 || ctx.GetCommonTlsContext().GetValidationContext().GetTrustedCa().GetFilename() != features.ResolveGatewayRootCAPath() {
						t.Fatalf("cluster %s lost CA validation or disabled session cache: %v", name, ctx)
					}
					if name == TLSConnectOriginate {
						options := &httpupstreamv3.HttpProtocolOptions{}
						if err := cluster.GetTypedExtensionProtocolOptions()[httpProtocolOptionsType].UnmarshalTo(options); err != nil {
							t.Fatal(err)
						}
						if !options.GetUpstreamHttpProtocolOptions().GetAutoSni() || !options.GetUpstreamHttpProtocolOptions().GetAutoSanValidation() {
							t.Fatal("upstream TLS override lost SNI or SAN validation")
						}
					}
				}
			}
			if !proto.Equal(before, gateway.Config) {
				t.Fatal("building TLS resources mutated gateway configuration")
			}
		})
	}
}

func TestGatewayBuildRejectsInvalidUpstreamTLS(t *testing.T) {
	for _, settings := range []*configv1.UpstreamTlsSettings{
		{MinProtocolVersion: configv1.UpstreamTlsSettings_TLSV1_3, MaxProtocolVersion: configv1.UpstreamTlsSettings_TLSV1_2},
		{MinProtocolVersion: configv1.UpstreamTlsSettings_ProtocolVersion(99)},
		{CipherSuites: []string{"ALL"}},
	} {
		_, err := Build(Inputs{
			DiscoveryAddress: "agentiod.agentio-system.svc:15012",
			TrustDomain:      "cluster.local",
			Gateway:          testGateway(&configv1.EgressGateway{UpstreamTls: settings}),
		})
		if err == nil {
			t.Fatalf("Build accepted invalid upstream TLS settings: %v", settings)
		}
	}
}

func TestExtProcWorkloadMTLS(t *testing.T) {
	const id = "spiffe://cluster.local/ns/system/sa/epe"
	provider := &configv1.ExtProcProvider{
		Service: "epe.system.svc",
		Tls:     &configv1.ExtProcTLSSettings{Mode: configv1.ExtProcTLSSettings_MUTUAL, PeerSpiffeIds: []string{id}},
	}
	resources, err := Build(
		Inputs{
			DiscoveryAddress: "agentiod.system.svc:15012",
			TrustDomain:      "cluster.local",
			Gateway:          testGateway(nil),
			GlobalExtProc:    provider,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	clusters := messagesOf(t, resources, model.ClusterType, func() *clusterv3.Cluster { return &clusterv3.Cluster{} })
	cfg := &tlsv3.UpstreamTlsContext{}
	if err := clusters[ExtProcCluster].GetTransportSocket().GetTypedConfig().UnmarshalTo(cfg); err != nil {
		t.Fatal(err)
	}
	common := cfg.GetCommonTlsContext()
	identity := common.GetTlsCertificateSdsSecretConfigs()
	trust := common.GetCombinedValidationContext()
	if len(identity) != 1 || identity[0].GetName() != "default" ||
		trust.GetValidationContextSdsSecretConfig().GetName() != "ROOTCA" {
		t.Fatalf("unexpected SDS secrets: %v", common)
	}
	for _, secret := range []*tlsv3.SdsSecretConfig{identity[0], trust.GetValidationContextSdsSecretConfig()} {
		services := secret.GetSdsConfig().GetApiConfigSource().GetGrpcServices()
		if len(services) != 1 || services[0].GetEnvoyGrpc().GetClusterName() != "sds-grpc" {
			t.Fatalf("unexpected SDS source: %v", secret)
		}
	}
	peers := trust.GetDefaultValidationContext().GetMatchTypedSubjectAltNames()
	if len(peers) != 1 || peers[0].GetSanType() != tlsv3.SubjectAltNameMatcher_URI ||
		peers[0].GetMatcher().GetExact() != id {
		t.Fatalf("unexpected peer validation: %v", peers)
	}
	if len(common.AlpnProtocols) != 1 || common.AlpnProtocols[0] != "h2" {
		t.Fatal("ext_proc requires h2 ALPN")
	}
	provider.Tls.PeerSpiffeIds = nil
	if _, err := Build(Inputs{Gateway: testGateway(nil), GlobalExtProc: provider}); err == nil {
		t.Fatal("accepted mTLS without a server identity")
	}
}
