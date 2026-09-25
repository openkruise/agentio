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

package charts_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

type renderedObject struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace"`
	} `yaml:"metadata"`
}

func helmTemplate(t *testing.T, args ...string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is not installed")
	}
	commandArgs := []string{"template", "test", "./agentio", "--namespace", "agentio-system", "--include-crds"}
	commandArgs = append(commandArgs, args...)
	command := exec.Command("helm", commandArgs...)
	output, err := command.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("helm %s: %w", strings.Join(commandArgs, " "), err)
	}
	return string(output), nil
}

func renderAgentio(t *testing.T, args ...string) string {
	t.Helper()
	output, err := helmTemplate(t, args...)
	if err != nil {
		t.Fatalf("%v\n%s", err, output)
	}
	return output
}

func requireRenderError(t *testing.T, want string, args ...string) {
	t.Helper()
	output, err := helmTemplate(t, args...)
	if err == nil {
		t.Fatalf("invalid values rendered successfully:\n%s", output)
	}
	if !renderErrorContains(output, want) {
		t.Fatalf("render error does not contain %q:\n%s", want, output)
	}
}

func renderErrorContains(output, want string) bool {
	if strings.Contains(output, want) {
		return true
	}
	if !strings.HasPrefix(want, "/") {
		return false
	}
	dottedPath := strings.ReplaceAll(strings.TrimPrefix(want, "/"), "/", ".")
	return strings.Contains(output, dottedPath)
}

func renderedObjects(t *testing.T, manifest string) []renderedObject {
	t.Helper()
	documents := bytes.Split([]byte(manifest), []byte("\n---"))
	objects := make([]renderedObject, 0, len(documents))
	for _, document := range documents {
		if len(bytes.TrimSpace(document)) == 0 {
			continue
		}
		var object renderedObject
		if err := yaml.Unmarshal(document, &object); err != nil {
			t.Fatalf("decode rendered YAML: %v\n%s", err, document)
		}
		if object.APIVersion == "" || object.Kind == "" {
			continue
		}
		objects = append(objects, object)
	}
	return objects
}

func objectNamesByKind(t *testing.T, manifest, kind string) []string {
	t.Helper()
	var names []string
	for _, object := range renderedObjects(t, manifest) {
		if object.Kind == kind {
			names = append(names, object.Metadata.Name)
		}
	}
	sort.Strings(names)
	return names
}

func requireContains(t *testing.T, manifest string, values ...string) {
	t.Helper()
	for _, value := range values {
		if !strings.Contains(manifest, value) {
			t.Errorf("rendered manifest does not contain %q", value)
		}
	}
}

func requireNotContains(t *testing.T, manifest string, values ...string) {
	t.Helper()
	for _, value := range values {
		if strings.Contains(manifest, value) {
			t.Errorf("rendered manifest unexpectedly contains %q", value)
		}
	}
}

func TestAgentioOwnsOnlyAgentioPolicyCRDs(t *testing.T) {
	manifest := renderAgentio(t)
	got := objectNamesByKind(t, manifest, "CustomResourceDefinition")
	want := []string{
		"globalsecurityprofiles.agents.kruise.io",
		"globaltrafficpolicies.agents.kruise.io",
		"securityprofiles.agents.kruise.io",
		"trafficpolicies.agents.kruise.io",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("CRDs = %v, want %v", got, want)
	}
}

func TestAgentioControlPlaneContract(t *testing.T) {
	manifest := renderAgentio(t)
	requireContains(t, manifest,
		"--discovery-address=:15012",
		"--monitoring-address=:15014",
		"--namespace=agentio-system",
		"containerPort: 15012",
		"containerPort: 15014",
		"path: /healthz",
		"path: /ready",
		"name: AGENTIO_ENABLE_SIDECAR_INJECTOR",
		"name: AGENTIO_ENABLE_GATEWAY_DEPLOYER",
		"name: AGENTIO_SERVICE_NAME",
	)
	requireNotContains(t, manifest,
		"containerPort: 15010",
		"name: PILOT_ENABLE_AMBIENT",
		"name: PILOT_DEBOUNCE_AFTER",
		"name: PILOT_DEBOUNCE_MAX",
		"\n        - discovery\n",
	)
}

func TestAgentiodLoggingConfiguration(t *testing.T) {
	manifest := renderAgentio(t,
		"--set", "agentiod.logging.level=debug",
		"--set", "agentiod.logging.format=json",
	)
	requireContains(t, manifest,
		"name: AGENTIO_LOG_LEVEL\n              value: \"debug\"",
		"name: AGENTIO_LOG_FORMAT\n              value: \"json\"",
	)

	disabled := renderAgentio(t, "--set", "agentiod.logging.level=none")
	requireContains(t, disabled,
		"name: AGENTIO_LOG_LEVEL\n              value: \"none\"",
	)
}

func TestAgentiodMaxServerConnectionAgeConfiguration(t *testing.T) {
	manifest := renderAgentio(t)
	requireContains(t, manifest,
		"name: AGENTIO_KEEPALIVE_MAX_SERVER_CONNECTION_AGE\n              value: \"30m\"",
	)

	configured := renderAgentio(t,
		"--set-string", "agentiod.keepalive.maxServerConnectionAge=47m",
	)
	requireContains(t, configured,
		"name: AGENTIO_KEEPALIVE_MAX_SERVER_CONNECTION_AGE\n              value: \"47m\"",
	)

	disabled := renderAgentio(t,
		"--set-string", "agentiod.keepalive.maxServerConnectionAge=0s",
	)
	requireContains(t, disabled,
		"name: AGENTIO_KEEPALIVE_MAX_SERVER_CONNECTION_AGE\n              value: \"0s\"",
	)

	requireRenderError(t, "maxServerConnectionAge",
		"--set-string", "agentiod.keepalive.maxServerConnectionAge=",
	)
}

func TestAmbientProfile(t *testing.T) {
	manifest := renderAgentio(t, "--set", "profile=ambient")
	if got, want := objectNamesByKind(t, manifest, "DaemonSet"), []string{"agentio-cni", "ztunnel"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ambient DaemonSets = %v, want %v", got, want)
	}
	if got, want := objectNamesByKind(t, manifest, "Deployment"), []string{"agentiod"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ambient Deployments = %v, want %v", got, want)
	}
	if got := objectNamesByKind(t, manifest, "MutatingWebhookConfiguration"); len(got) != 0 {
		t.Fatalf("ambient webhooks = %v, want none", got)
	}
	requireContains(t, manifest,
		"AMBIENT_ENABLED: \"true\"",
		"AMBIENT_ENABLEMENT_SELECTOR",
		"name: ENABLE_SANDBOX_MANAGER",
		"name: INPOD_ENABLED",
		"path: /var/run/ztunnel",
	)
}

func TestSandboxModePropagation(t *testing.T) {
	for _, profile := range []string{"sidecar", "ambient"} {
		for _, mode := range []string{"default", "false", "true"} {
			t.Run(profile+"/"+mode, func(t *testing.T) {
				args := []string{"--set", "profile=" + profile}
				if profile == "ambient" {
					args = append(args, "--show-only", "templates/ztunnel/daemonset.yaml")
				}
				want := "false"
				if mode != "default" {
					args = append(args, "--set-string", "agentiod.env.AGENTIO_SANDBOX_MODE="+mode)
					want = mode
				}
				manifest := renderAgentio(t, args...)
				if profile == "sidecar" {
					requireContains(t, manifest, "sandboxMode: "+fmt.Sprintf("%q", want))
				} else {
					requireContains(t, manifest,
						"name: AGENTIO_SANDBOX_MODE\n              value: "+fmt.Sprintf("%q", want),
					)
				}
			})
		}
	}
}

func TestSidecarProfile(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "default"},
		{name: "explicit", args: []string{"--set", "profile=sidecar"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manifest := renderAgentio(t, tc.args...)
			if got := objectNamesByKind(t, manifest, "DaemonSet"); len(got) != 0 {
				t.Fatalf("sidecar DaemonSets = %v, want none", got)
			}
			if got := objectNamesByKind(t, manifest, "MutatingWebhookConfiguration"); len(got) != 1 {
				t.Fatalf("sidecar webhooks = %v, want one", got)
			}
			requireContains(t, manifest,
				"containerPort: 15017",
				"name: AGENTIO_ENABLE_SIDECAR_INJECTOR\n              value: \"true\"",
				"ztunnel: |",
			)
		})
	}
}

func TestCNIAndZtunnelOverrides(t *testing.T) {
	manifest := renderAgentio(t,
		"--set", "profile=ambient",
		"--set", "cni.cniBinDir=/custom/bin",
		"--set", "cni.cniConfDir=/custom/net.d",
		"--set", "ztunnel.trustBundle.useClusterTrustBundle=true",
		"--set", "global.clusterDomain=cluster.example",
	)
	requireContains(t, manifest,
		"path: /custom/bin",
		"path: /custom/net.d",
		"clusterTrustBundle:",
		"agentiod.agentio-system.svc.cluster.example:15012",
	)
}

func TestStaticEgressGateway(t *testing.T) {
	manifest := renderAgentio(t, "--set", "egressGateway.mode=static")
	if got, want := objectNamesByKind(t, manifest, "Deployment"), []string{"agentio-egress", "agentiod"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("static gateway Deployments = %v, want %v", got, want)
	}
	if got := objectNamesByKind(t, manifest, "Gateway"); len(got) != 0 {
		t.Fatalf("static mode Gateways = %v, want none", got)
	}
	requireContains(t, manifest,
		"networking.agents.kruise.io/sandbox-egress: \"true\"",
		"gateway.networking.k8s.io/gateway-name: agentio-egress",
		"name: PILOT_CERT_PROVIDER",
		"agentiod.agentio-system.svc.cluster.local:15012",
		"egressGateways:",
		"name: agentio-egress",
		"namespace: agentio-system",
	)
}

func TestGatewayAPIEgressGateway(t *testing.T) {
	manifest := renderAgentio(t,
		"--set", "egressGateway.mode=gatewayAPI",
		"--set", "egressGateway.gatewayAPI.create=true",
		"--set-string", "egressGateway.image.repository=registry.example/agentio/proxyv2",
		"--set-string", "egressGateway.image.tag=1.0.0",
	)
	if got, want := objectNamesByKind(t, manifest, "Deployment"), []string{"agentiod"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Gateway API Deployments = %v, want %v", got, want)
	}
	if got, want := objectNamesByKind(t, manifest, "Gateway"), []string{"agentio-egress"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Gateway API Gateways = %v, want %v", got, want)
	}
	requireContains(t, manifest,
		"gatewayClassName: agentio-egress",
		"protocol: HBONE",
		"name: AGENTIO_ENABLE_GATEWAY_DEPLOYER",
		"value: \"true\"",
		"egress-gateway: |",
		`image: "registry.example/agentio/proxyv2:1.0.0"`,
	)
}

func TestAgentgatewayGatewayAPIConfiguration(t *testing.T) {
	manifest := renderAgentio(t,
		"--set", "egressGateway.mode=gatewayAPI",
		"--set", "egressGateway.gatewayAPI.create=true",
		"--set", "egressGateway.gatewayAPI.gatewayClassName=agentio-agentgateway",
		"--set-string", "egressGateway.gatewayAPI.infrastructure.parametersRef.group=",
		"--set", "egressGateway.gatewayAPI.infrastructure.parametersRef.kind=ConfigMap",
		"--set", "egressGateway.gatewayAPI.infrastructure.parametersRef.name=agentgateway-config",
		"--set", "egressGateway.agentgateway.image=registry.example/agentgateway:tested",
	)
	requireContains(t, manifest, "gatewayClassName: agentio-agentgateway", "agentgateway: |",
		"image: registry.example/agentgateway:tested", "parametersRef:", "name: agentgateway-config")
	if got, want := objectNamesByKind(t, manifest, "Deployment"), []string{"agentiod"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("chart must leave gateway deployment to controller: %v", got)
	}
}

func TestManagedEPE(t *testing.T) {
	manifest := renderAgentio(t,
		"--set", "global.tag=0.1.0",
		"--set", "epe.mode=managed",
		"--set", "epe.credentialProvider.url=https://credentials.example",
	)
	if got, want := objectNamesByKind(t, manifest, "Deployment"), []string{"agentio-epe", "agentiod"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("managed EPE Deployments = %v, want %v", got, want)
	}
	requireContains(t, manifest,
		"image: \"docker.io/openkruise/agentio-epe:0.1.0\"",
		"service: agentio-epe.agentio-system.svc.cluster.local",
		"filter_state['agentio.workload.name']",
		"filter_state['agentio.workload.namespace']",
		"filter_state['downstream_peer'].name",
		"filter_state['downstream_peer'].namespace",
		"port: 9002",
		"- -epe-config=agentio-epe-config",
		"- -epe-config-primary=agentio-epe-config-primary",
		"- -epe-config-namespace=agentio-system",
		"- -grpc-port=9002",
		"- -grpc-health-port=9003",
		"- -metrics-port=9090",
		"- -audit-webhook-insecure-skip-verify=false",
		"livenessProbe:",
		"readinessProbe:",
		"name: CREDENTIAL_PROVIDER_MTLS_SOURCE\n              value: \"none\"",
	)
	if strings.Contains(manifest, "credential-provider-mtls") {
		t.Fatal("managed EPE must not mount credential-provider certificates")
	}
}

func TestManagedEPECanExplicitlySkipAuditWebhookTLSVerification(t *testing.T) {
	manifest := renderAgentio(t,
		"--set", "epe.mode=managed",
		"--set", "epe.auditWebhook.insecureSkipVerify=true",
	)
	requireContains(t, manifest, "- -audit-webhook-insecure-skip-verify=true")
	requireNotContains(t, manifest, "- -audit-webhook-insecure-skip-verify=false")
}

func TestImmutableImageDigests(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	manifest := renderAgentio(t,
		"--set", "profile=ambient",
		"--set", "egressGateway.mode=static",
		"--set", "epe.mode=managed",
		"--set-string", "agentiod.image.repository=registry.example/agentiod",
		"--set-string", "agentiod.image.digest="+digest,
		"--set-string", "cni.image.repository=registry.example/install-cni",
		"--set-string", "cni.image.digest="+digest,
		"--set-string", "ztunnel.image.repository=registry.example/ztunnel",
		"--set-string", "ztunnel.image.digest="+digest,
		"--set-string", "egressGateway.image.repository=registry.example/proxyv2",
		"--set-string", "egressGateway.image.digest="+digest,
		"--set-string", "epe.image.repository=registry.example/agentio-epe",
		"--set-string", "epe.image.digest="+digest,
	)
	for _, image := range []string{
		"registry.example/agentiod@" + digest,
		"registry.example/install-cni@" + digest,
		"registry.example/ztunnel@" + digest,
		"registry.example/proxyv2@" + digest,
		"registry.example/agentio-epe@" + digest,
	} {
		requireContains(t, manifest, `image: "`+image+`"`)
	}
}

func TestPrepareReleaseChartPinsAllReleaseImages(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is not installed")
	}
	chartDir := filepath.Join(t.TempDir(), "agentio")
	copyCommand := exec.Command("cp", "-R", "./agentio", chartDir)
	if output, err := copyCommand.CombinedOutput(); err != nil {
		t.Fatalf("copy chart: %v\n%s", err, output)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	agentiodImage := "registry.example/openkruise/agentiod@" + digest
	epeImage := "registry.example/openkruise/agentio-epe@" + digest
	ztunnelImage := "registry.example/openkruise/ztunnel@" + digest
	cniImage := "registry.example/openkruise/install-cni@" + digest
	proxyInitImage := "registry.example/openkruise/proxy-init@" + digest
	gatewayImage := "registry.example/openkruise/proxyv2@" + digest
	prepare := exec.Command(
		"../../tools/prepare-release-chart.sh",
		chartDir,
		"1.2.3",
		agentiodImage,
		epeImage,
		ztunnelImage,
		cniImage,
		proxyInitImage,
		gatewayImage,
	)
	if output, err := prepare.CombinedOutput(); err != nil {
		t.Fatalf("prepare release chart: %v\n%s", err, output)
	}
	render := func(args ...string) []byte {
		t.Helper()
		commandArgs := []string{"template", "test", chartDir, "--namespace", "agentio-system"}
		commandArgs = append(commandArgs, args...)
		manifest, err := exec.Command("helm", commandArgs...).CombinedOutput()
		if err != nil {
			t.Fatalf("render prepared release chart: %v\n%s", err, manifest)
		}
		return manifest
	}
	manifest := append(
		render("--set", "profile=ambient", "--set", "egressGateway.mode=static", "--set", "epe.mode=managed"),
		render("--set", "profile=sidecar")...,
	)
	for _, image := range []string{
		`image: "` + agentiodImage + `"`,
		`image: "` + epeImage + `"`,
		`image: "` + ztunnelImage + `"`,
		`image: "` + cniImage + `"`,
		`image: "` + proxyInitImage + `"`,
		`image: "` + gatewayImage + `"`,
	} {
		if !bytes.Contains(manifest, []byte(image)) {
			t.Errorf("prepared release manifest does not contain %q", image)
		}
	}
	if bytes.Contains(manifest, []byte(":latest")) {
		t.Errorf("prepared release manifest contains a mutable latest image:\n%s", manifest)
	}
	chart, err := os.ReadFile(filepath.Join(chartDir, "Chart.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`version: "1.2.3"`, `appVersion: "1.2.3"`} {
		if !bytes.Contains(chart, []byte(field)) {
			t.Errorf("prepared Chart.yaml does not contain %q", field)
		}
	}
}

func TestPrepareReleaseChartRejectsInvalidSemanticVersion(t *testing.T) {
	chartDir := filepath.Join(t.TempDir(), "agentio")
	copyCommand := exec.Command("cp", "-R", "./agentio", chartDir)
	if output, err := copyCommand.CombinedOutput(); err != nil {
		t.Fatalf("copy chart: %v\n%s", err, output)
	}
	digestImage := "registry.example/image@sha256:" + strings.Repeat("a", 64)
	command := exec.Command(
		"../../tools/prepare-release-chart.sh",
		chartDir,
		"01.2.3",
		digestImage,
		digestImage,
		digestImage,
		digestImage,
		digestImage,
		digestImage,
	)
	output, err := command.CombinedOutput()
	if err == nil || !bytes.Contains(output, []byte("invalid release version")) {
		t.Fatalf("prepare release chart error = %v, output = %q", err, output)
	}
}

func TestExternalEPE(t *testing.T) {
	manifest := renderAgentio(t,
		"--set", "epe.mode=external",
		"--set", "epe.external.address=epe.security-system.svc",
		"--set", "epe.external.port=9443",
	)
	if got, want := objectNamesByKind(t, manifest, "Deployment"), []string{"agentiod"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("external EPE Deployments = %v, want %v", got, want)
	}
	requireContains(t, manifest,
		"service: epe.security-system.svc",
		"port: 9443",
	)
	requireNotContains(t, manifest,
		"app.kubernetes.io/name: agentio-epe",
		"image: \"docker.io/openkruise/agentio-epe:",
	)
}

func TestStaticGatewayUsesConfiguredEPE(t *testing.T) {
	manifest := renderAgentio(t,
		"--set", "egressGateway.mode=static",
		"--set", "epe.mode=external",
		"--set", "epe.external.address=epe.example.internal",
		"--set", "epe.external.port=9443",
	)
	requireContains(t, manifest,
		"name: AGENTIO_EPE_ADDRESS",
		"value: \"epe.example.internal:9443\"",
	)
}

func TestInvalidModesFailRendering(t *testing.T) {
	tests := []struct {
		name string
		want string
		args []string
	}{
		{name: "profile", want: "profile", args: []string{"--set", "profile=invalid"}},
		{name: "log level", want: "/agentiod/logging/level", args: []string{"--set", "agentiod.logging.level=verbose"}},
		{name: "log format", want: "/agentiod/logging/format", args: []string{"--set", "agentiod.logging.format=console"}},
		{name: "agentgateway CA boolean", want: "/egressGateway/agentgateway/ca/enabled", args: []string{"--set-string", "egressGateway.agentgateway.ca.enabled=false"}},
		{name: "egress gateway", want: "/egressGateway/mode", args: []string{"--set", "egressGateway.mode=invalid"}},
		{name: "EPE", want: "/epe/mode", args: []string{"--set", "epe.mode=invalid"}},
		{name: "external EPE address", want: "/epe/external/address", args: []string{"--set", "epe.mode=external"}},
		{
			name: "Gateway API class",
			want: "egressGateway.gatewayAPI.gatewayClassName is required",
			args: []string{"--set", "egressGateway.mode=gatewayAPI", "--set", "egressGateway.gatewayAPI.create=true", "--set", "egressGateway.gatewayAPI.gatewayClassName="},
		},
		{
			name: "managed EPE files source",
			want: "epe.credentialProvider.mtls.source must be secret or none",
			args: []string{"--set", "epe.mode=managed", "--set", "epe.credentialProvider.mtls.source=files"},
		},
		{
			name: "managed EPE secret",
			want: "epe.credentialProvider.mtls.secret.namespace and name are required",
			args: []string{"--set", "epe.mode=managed", "--set", "epe.credentialProvider.mtls.source=secret"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requireRenderError(t, tt.want, tt.args...)
		})
	}
}

func TestEveryProfileAndModeCombinationRendersUniqueObjects(t *testing.T) {
	tests := [][]string{
		nil,
		{"--set", "profile=ambient"},
		{"--set", "profile=sidecar"},
		{"--set", "egressGateway.mode=static", "--set", "epe.mode=managed", "--set", "epe.credentialProvider.url=https://credentials.example"},
		{"--set", "egressGateway.mode=gatewayAPI", "--set", "egressGateway.gatewayAPI.create=true", "--set", "epe.mode=external", "--set", "epe.external.address=epe.example.internal"},
	}
	for i, args := range tests {
		t.Run(fmt.Sprintf("combination-%d", i), func(t *testing.T) {
			seen := map[string]struct{}{}
			for _, object := range renderedObjects(t, renderAgentio(t, args...)) {
				key := fmt.Sprintf("%s/%s/%s/%s", object.APIVersion, object.Kind, object.Metadata.Namespace, object.Metadata.Name)
				if _, found := seen[key]; found {
					t.Fatalf("duplicate rendered object %s", key)
				}
				seen[key] = struct{}{}
			}
			if len(seen) == 0 {
				t.Fatal("chart rendered no Kubernetes objects")
			}
		})
	}
}

func TestAgentgatewayCAInjectorValues(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			manifest := renderAgentio(t,
				"--set", "egressGateway.mode=gatewayAPI",
				"--set", fmt.Sprintf("egressGateway.agentgateway.ca.enabled=%t", enabled),
				"--set", "agentiod.tokenAudience=gateway-ca",
				"--set", "agentiod.ca.trustBundleConfigMapName=gateway-root",
			)
			for _, doc := range strings.Split(manifest, "\n---") {
				var cm struct {
					Kind string
					Data map[string]string
				}
				if err := yaml.Unmarshal([]byte(doc), &cm); err != nil {
					t.Fatal(err)
				}
				if cm.Kind != "ConfigMap" || cm.Data["values"] == "" {
					continue
				}
				var values struct {
					Global struct {
						Agentgateway    struct{ CA struct{ Enabled bool } }
						CAAddress       string
						TrustBundleName string
						SDS             struct{ Token struct{ Aud string } }
					}
				}
				if err := yaml.Unmarshal([]byte(cm.Data["values"]), &values); err != nil {
					t.Fatal(err)
				}
				g := values.Global
				if g.Agentgateway.CA.Enabled != enabled || g.SDS.Token.Aud != "gateway-ca" || g.TrustBundleName != "gateway-root" || g.CAAddress != "agentiod.agentio-system.svc.cluster.local:15012" {
					t.Fatalf("incorrect CA bootstrap values: %+v", g)
				}
				return
			}
			t.Fatal("missing injector values")
		})
	}
}

func TestEPEWorkloadMTLS(t *testing.T) {
	workload := renderAgentio(t, "--set", "epe.mode=managed,epe.tls.enabled=true")
	requireContains(
		t,
		workload,
		"-tls-source=ca",
		"-ca-address=agentiod.agentio-system.svc.cluster.local:15012",
		"-tls-spiffe-id=spiffe://cluster.local/ns/agentio-system/sa/agentio-epe",
		"path: agentio-token",
		"service: readiness",
		"service: liveness",
	)
	if strings.Contains(workload, "/etc/epe/server-tls") {
		t.Fatal("workload mode must not mount a serving Secret")
	}

	valuesFile := filepath.Join(t.TempDir(), "epe.yaml")
	if err := os.WriteFile(valuesFile, []byte(`epe:
  mode: managed
  tls:
    enabled: true
    certificateSource:
      file:
        certificateFile: /custom/tls/cert.pem
        privateKeyFile: /custom/tls/key.pem
        caCertificateFile: /custom/trust/root.pem
  extraVolumes:
  - name: serving-cert
    secret:
      secretName: epe-server
  - name: client-ca
    configMap:
      name: epe-client-ca
  extraVolumeMounts:
  - name: serving-cert
    mountPath: /custom/tls
    readOnly: true
  - name: client-ca
    mountPath: /custom/trust
    readOnly: true
`), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := renderAgentio(t, "-f", valuesFile, "--show-only", "templates/epe/deployment.yaml")
	requireContains(t, manifest,
		"-tls-source=file",
		"-tls-cert-path=/custom/tls/cert.pem",
		"-tls-key-path=/custom/tls/key.pem",
		"-tls-ca-path=/custom/trust/root.pem",
		"secretName: epe-server", "name: epe-client-ca",
		"mountPath: /custom/tls", "mountPath: /custom/trust",
	)
	requireNotContains(t, manifest, "workload-root", "workload-token", "-ca-address")

	// User-provided mounts also serve outbound provider files with inbound TLS off.
	plain := renderAgentio(t, "-f", valuesFile, "--set", "epe.tls.enabled=false",
		"--show-only", "templates/epe/deployment.yaml")
	requireContains(t, plain, "secretName: epe-server", "mountPath: /custom/trust")
	requireNotContains(t, plain, "-tls-source=", "-tls-cert-path=", "workload-root", "workload-token")

	for _, overrides := range []string{
		"epe.tls.certificateSource.file.certificateFile=/cert.pem",
		"epe.tls.certificateSource.ca.address=ca.example:15012,epe.tls.certificateSource.file.certificateFile=/cert.pem,epe.tls.certificateSource.file.privateKeyFile=/key.pem,epe.tls.certificateSource.file.caCertificateFile=/root.pem",
		"epe.tls.certificateSource.ca.tokenFile=relative-path",
		"epe.tls.certificateSource.xds.address=ca.example:15012",
	} {
		requireRenderError(t, "/epe/tls/certificateSource", "--set", "epe.mode=managed,epe.tls.enabled=true,"+overrides)
	}
	requireRenderError(
		t,
		"epe.tls.peerSpiffeIDs is required",
		"--set",
		"epe.mode=external,epe.external.address=epe.other.svc,epe.tls.enabled=true",
	)
}

func TestEPECustomCAPaths(t *testing.T) {
	for _, tc := range []struct {
		name      string
		overrides string
		present   []string
		absent    []string
	}{
		{
			name:      "address override retains default mounts",
			overrides: "epe.tls.certificateSource.ca.address=ca.security.svc:15012",
			present:   []string{"-ca-address=ca.security.svc:15012", "name: workload-root", "name: workload-token"},
		},
		{
			name:      "custom root retains only default token mount",
			overrides: "epe.tls.certificateSource.ca.caCertificateFile=/custom/root.pem",
			present:   []string{"-ca-root-path=/custom/root.pem", "name: workload-token"},
			absent:    []string{"name: workload-root"},
		},
		{
			name:      "explicit paths disable both default mounts",
			overrides: "epe.tls.certificateSource.ca.caCertificateFile=/var/run/secrets/agentio/root-cert.pem,epe.tls.certificateSource.ca.tokenFile=/custom/token",
			present:   []string{"-ca-root-path=/var/run/secrets/agentio/root-cert.pem", "-ca-token-path=/custom/token"},
			absent:    []string{"name: workload-root", "name: workload-token"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manifest := renderAgentio(t, "--set", "epe.mode=managed,epe.tls.enabled=true,"+tc.overrides,
				"--show-only", "templates/epe/deployment.yaml")
			requireContains(t, manifest, tc.present...)
			requireNotContains(t, manifest, tc.absent...)
		})
	}
}
