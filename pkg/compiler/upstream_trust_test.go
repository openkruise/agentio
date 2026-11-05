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
	"strings"
	"testing"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/internal/testutil"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/networking"
	"github.com/openkruise/agentio/pkg/security/pki"
)

func TestGatewayUpstreamTrustBundleUpdates(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := krt.NewOptionsBuilder(stop, "", nil)
	inputs := validCompilerInputs(stop)
	certs := make(map[string]string)
	var privateKey string
	var leaf string
	for _, name := range []string{"public", "old", "new"} {
		ca, err := pki.NewSelfSignedCA(name, 365*24*time.Hour, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		certs[name] = string(ca.CertificatePEM())
		if name == "old" {
			privateKey = string(ca.PrivateKeyPEM())
			issued, err := ca.GenerateRSA(t.Context(), pki.LeafOptions{
				CommonName:  "service.example.com",
				DNSNames:    []string{"service.example.com"},
				CurrentTime: time.Now(),
				Lifetime:    time.Hour,
				Server:      true,
			})
			if err != nil {
				t.Fatal(err)
			}
			leaf = string(issued.CertificatePEM)
		}
	}
	inputs.GatewayTrustBundle = certs["public"]
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: inputs.RootNamespace, Name: "company-ca"},
		Data:       map[string]string{"ca.crt": certs["old"] + certs["public"]},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: inputs.RootNamespace, Name: "partner-ca"},
		Data:       map[string][]byte{"ca.crt": []byte(certs["new"])},
	}
	configMaps := krt.NewMutableCollection[*corev1.ConfigMap](
		nil,
		[]*corev1.ConfigMap{cm},
		options.WithName("configmaps")...)
	secrets := krt.NewMutableCollection[*corev1.Secret](nil, []*corev1.Secret{secret}, options.WithName("secrets")...)
	// Objects with the same names in the gateway namespace must not be used.
	wrongCM, wrongSecret := cm.DeepCopy(), secret.DeepCopy()
	wrongCM.Namespace, wrongSecret.Namespace = "demo", "demo"
	wrongCM.Data["ca.crt"], wrongSecret.Data["ca.crt"] = "invalid", []byte("invalid")
	configMaps.ConditionalUpdateObject(wrongCM)
	secrets.ConditionalUpdateObject(wrongSecret)
	inputs.ConfigMaps, inputs.Secrets = configMaps.AsCollection(), secrets.AsCollection()
	sources := []*configv1.UpstreamTrustSource{
		{
			Source: &configv1.UpstreamTrustSource_ConfigMapRef{
				ConfigMapRef: &configv1.TrustSourceReference{Name: cm.Name, Key: "ca.crt"},
			},
		},
		{
			Source: &configv1.UpstreamTrustSource_SecretRef{
				SecretRef: &configv1.TrustSourceReference{Name: secret.Name, Key: "ca.crt"},
			},
		},
	}
	config := &configv1.AgentioConfig{EgressGateways: []*configv1.EgressGateway{
		{
			Namespace:           "demo",
			Name:                "custom",
			UpstreamTrustBundle: &configv1.UpstreamTrustBundle{AdditionalSources: sources},
		},
		{Namespace: "demo", Name: "default"},
	}}
	configurations := krt.NewMutableCollection[model.AgentioConfiguration](
		nil,
		nil,
		options.WithName("configurations")...)
	inputs.AgentioConfig = configurations.AsCollection()
	publish := func(version string) {
		configurations.ConditionalUpdateObject(model.AgentioConfiguration{
			ResourceVersion: version,
			Value:           proto.Clone(config).(*configv1.AgentioConfig),
		})
	}
	publish("initial")
	compiled, err := New(inputs, options)
	if err != nil {
		t.Fatal(err)
	}
	if !compiled.WaitUntilSynced(stop) {
		t.Fatal("compiler did not sync")
	}
	assertBundle := func(want ...string) {
		t.Helper()
		testutil.Eventually(t, func() bool {
			return len(compiled.Failures()) == 0 && gatewayHasTrust(t, compiled, "demo/custom", want...) &&
				gatewayHasTrust(t, compiled, "demo/default", certs["public"])
		}, "gateway to publish the expected CA union")
	}
	assertRetained := func(wantError string, want ...string) {
		t.Helper()
		testutil.Eventually(t, func() bool {
			return strings.Contains(compiled.Failures()["Gateway/demo/custom"], wantError)
		}, "source failure to identify the object and key")
		if !gatewayHasTrust(t, compiled, "demo/custom", want...) ||
			!gatewayHasTrust(t, compiled, "demo/default", certs["public"]) {
			t.Fatal("failed source update changed the effective trust bundle")
		}
	}
	assertBundle(certs["public"], certs["old"], certs["new"])
	for _, tc := range []struct {
		value  string
		reason string
	}{
		{"", "is empty"},
		{"invalid PEM", "non-certificate data"},
		{certs["old"] + leaf, "non-CA certificate"},
		{privateKey, "non-certificate data"},
	} {
		updated := cm.DeepCopy()
		updated.Data["ca.crt"] = tc.value
		configMaps.ConditionalUpdateObject(updated)
		testutil.Eventually(t, func() bool {
			return strings.Contains(compiled.Failures()["Gateway/demo/custom"], tc.reason)
		}, "specific invalid PEM update to be rejected")
		assertRetained(`ConfigMap agentio-system/company-ca key "ca.crt"`, certs["public"], certs["old"], certs["new"])
	}
	configMaps.DeleteObject(cm.Namespace + "/" + cm.Name)
	assertRetained("not found", certs["public"], certs["old"], certs["new"])
	missingKey := cm.DeepCopy()
	missingKey.Data = nil
	configMaps.ConditionalUpdateObject(missingKey)
	assertRetained("data key not found", certs["public"], certs["old"], certs["new"])
	configMaps.ConditionalUpdateObject(cm)
	assertBundle(certs["public"], certs["old"], certs["new"])

	// Removing one source does not revoke a CA that another source still contains.
	rotating := secret.DeepCopy()
	rotating.Data["ca.crt"] = []byte(certs["old"] + certs["new"])
	secrets.ConditionalUpdateObject(rotating)
	config.EgressGateways[0].UpstreamTrustBundle.AdditionalSources = sources[1:]
	publish("secret-only")
	assertBundle(certs["public"], certs["old"], certs["new"])
	secrets.ConditionalUpdateObject(secret)
	assertBundle(certs["public"], certs["new"])
	invalidSecret := secret.DeepCopy()
	invalidSecret.Data["ca.crt"] = []byte("invalid")
	secrets.ConditionalUpdateObject(invalidSecret)
	assertRetained(`Secret agentio-system/partner-ca key "ca.crt"`, certs["public"], certs["new"])
	secrets.DeleteObject(secret.Namespace + "/" + secret.Name)
	assertRetained("not found", certs["public"], certs["new"])
	config.EgressGateways[0].UpstreamTrustBundle.AdditionalSources = nil
	publish("public-only")
	assertBundle(certs["public"])
}

func gatewayHasTrust(t *testing.T, compiled *Compiler, gateway string, want ...string) bool {
	t.Helper()
	count := 0
	for _, resource := range currentSnapshot(t, compiled).ListResourcesOwnedByGateway(model.ClusterType, gateway) {
		if resource.XDSName != networking.TLSConnectOriginate && resource.XDSName != networking.TLSProxyOriginate {
			continue
		}
		cluster := &clusterv3.Cluster{}
		if err := resource.Value.UnmarshalTo(cluster); err != nil {
			t.Fatal(err)
		}
		ctx := &tlsv3.UpstreamTlsContext{}
		if err := cluster.GetTransportSocket().GetTypedConfig().UnmarshalTo(ctx); err != nil {
			t.Fatal(err)
		}
		ca := ctx.GetCommonTlsContext().GetValidationContext().GetTrustedCa()
		bundle := ca.GetInlineString()
		if ca.GetFilename() != "" || strings.Count(bundle, "-----BEGIN CERTIFICATE-----") != len(want) {
			return false
		}
		for _, cert := range want {
			if !strings.Contains(bundle, cert) {
				return false
			}
		}
		count++
	}
	// Both origination clusters in both the legacy and community variants.
	return count == 4
}

func TestGatewayUpstreamTrustMissingSourceHasNoInitialOutput(t *testing.T) {
	ca, err := pki.NewSelfSignedCA("public", 365*24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, base := range []string{"", "package"} {
		t.Run(base, func(t *testing.T) {
			stop := make(chan struct{})
			t.Cleanup(func() { close(stop) })
			inputs := validCompilerInputs(stop)
			if base != "" {
				inputs.GatewayTrustBundle = string(ca.CertificatePEM())
			}
			configMaps := krt.NewMutableCollection[*corev1.ConfigMap](nil, nil, krt.WithStop(stop))
			inputs.ConfigMaps = configMaps.AsCollection()
			inputs.AgentioConfig = krt.NewStaticCollection[model.AgentioConfiguration](
				nil,
				[]model.AgentioConfiguration{{
					Value: &configv1.AgentioConfig{EgressGateways: []*configv1.EgressGateway{
						{
							Namespace: "demo",
							Name:      "missing",
							UpstreamTrustBundle: &configv1.UpstreamTrustBundle{
								AdditionalSources: []*configv1.UpstreamTrustSource{
									{
										Source: &configv1.UpstreamTrustSource_ConfigMapRef{
											ConfigMapRef: &configv1.TrustSourceReference{
												Name: "missing",
												Key:  "ca.crt",
											},
										},
									},
								},
							},
						},
					}},
				}},
				krt.WithStop(stop),
			)
			compiled, err := New(inputs, krt.NewOptionsBuilder(stop, "", nil))
			if err != nil {
				t.Fatal(err)
			}
			wantError := "not found"
			if base == "" {
				wantError = "AGENTIO_CLIENT_TRUST_PACKAGE_PATH"
			}
			testutil.Eventually(t, func() bool {
				return compiled.HasSynced() && strings.Contains(compiled.Failures()["Gateway/demo/missing"], wantError)
			}, "invalid initial source to fail compilation")
			if len(currentSnapshot(t, compiled).ListResourcesOwnedByGateway(model.ClusterType, "demo/missing")) != 0 {
				t.Fatal("invalid initial trust published gateway clusters")
			}
			if base != "" {
				configMaps.ConditionalUpdateObject(&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: inputs.RootNamespace, Name: "missing"},
					Data:       map[string]string{"ca.crt": string(ca.CertificatePEM())},
				})
				testutil.Eventually(t, func() bool {
					return len(compiled.Failures()) == 0 &&
						gatewayHasTrust(t, compiled, "demo/missing", inputs.GatewayTrustBundle)
				}, "creating the missing source to publish the initial gateway output")
			}
		})
	}
}
