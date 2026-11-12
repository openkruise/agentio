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

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
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

func TestRelatedDeploymentValuesFollowOverrides(t *testing.T) {
	for _, profile := range []string{"sidecar", "ambient"} {
		t.Run(profile, func(t *testing.T) {
			manifest := renderAgentio(t, "--set", "profile="+profile,
				"--set", "agentiod.ca.configMapName=custom-ca",
				"--set", "ztunnel.serviceAccount.name=custom-ztunnel",
				"--set", "egressGateway.enabled=true")
			for doc := range bytes.SplitSeq([]byte(manifest), []byte("\n---")) {
				var workload struct {
					Kind string
					Spec struct{ Template corev1.PodTemplateSpec }
				}
				if err := yaml.Unmarshal(doc, &workload); err != nil {
					t.Fatal(err)
				}
				if workload.Kind != "Deployment" && workload.Kind != "DaemonSet" {
					continue
				}
				for _, volume := range workload.Spec.Template.Spec.Volumes {
					if volume.Name == "agentiod-ca-cert" && volume.ConfigMap.Name != "custom-ca" {
						t.Fatalf("CA mount did not follow override: %+v", volume)
					}
				}
			}
			requireContains(t, manifest, "name: AGENTIO_TRUSTED_NODE_ACCOUNTS\n              value: \"custom-ztunnel\"")
		})
	}
	manifest := renderAgentio(t, "--set", "ztunnel.serviceAccount.name=custom-ztunnel",
		"--set", "agentiod.trustedNodeServiceAccount=external-ztunnel")
	requireContains(t, manifest, "name: AGENTIO_TRUSTED_NODE_ACCOUNTS\n              value: \"external-ztunnel\"")
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
	if got, want := objectNamesByKind(
		t,
		manifest,
		"DaemonSet",
	), []string{
		"agentio-cni",
		"ztunnel",
	}; !reflect.DeepEqual(
		got,
		want,
	) {
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
		"name: ENABLE_SANDBOX_MANAGER\n              value: \"false\"",
		"name: INPOD_ENABLED",
		"path: /var/run/ztunnel",
	)
}

func TestSandboxModePropagation(t *testing.T) {
	for _, profile := range []string{"sidecar", "ambient"} {
		for _, mode := range []string{"default", "false", "true"} {
			t.Run(profile+"/"+mode, func(t *testing.T) {
				args := []string{"--set", "profile=" + profile, "--set", "epe.mode=managed", "--set", "egressGateway.enabled=true"}
				want := "false"
				if mode != "default" {
					args = append(args, "--set", "sandbox.enabled="+mode)
					want = mode
				}
				if profile == "ambient" && mode == "true" {
					requireRenderError(t, "sandbox.enabled is not supported with profile=ambient", args...)
					return
				}
				manifest := renderAgentio(t, args...)
				if strings.Contains(manifest, "name: AGENTIO_SANDBOX_RUNTIMES") {
					t.Fatal("chart still emits the removed Sandbox runtimes setting")
				}
				// agentiod, managed EPE, Porter, and (for ambient) the node ztunnel agree.
				count := 3
				if profile == "ambient" {
					count++
				}
				setting := "name: AGENTIO_SANDBOX_MODE\n              value: " + fmt.Sprintf("%q", want)
				if got := strings.Count(manifest, setting); got != count {
					t.Fatalf("Sandbox mode settings = %d, want %d", got, count)
				}
				if profile == "sidecar" {
					requireContains(t, manifest, "sandboxMode: "+fmt.Sprintf("%q", want))
				}
				if strings.Contains(manifest, `resources: ["sandboxes"]`) != (want == "true") {
					t.Fatal("Sandbox RBAC does not follow sandbox.enabled")
				}
			})
		}
	}
	for _, name := range []string{"AGENTIO_SANDBOX_MODE", "AGENTIO_SANDBOX_RUNTIMES"} {
		requireRenderError(t, "managed by sandbox.enabled", "--set-string", "agentiod.env."+name+"=true")
	}
	requireRenderError(t, "managed by sandbox.enabled", "--set-string", "epe.env.AGENTIO_SANDBOX_MODE=true")
	for _, name := range []string{"AGENTIO_SANDBOX_MODE", "ENABLE_SANDBOX_MANAGER"} {
		requireRenderError(
			t,
			"managed by sandbox.enabled",
			"--set",
			"profile=ambient",
			"--set-string",
			"ztunnel.env."+name+"=true",
		)
	}
	requireRenderError(t, "boolean", "--set-string", "sandbox.enabled=true")
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

func TestPolicyValidationWebhook(t *testing.T) {
	for _, profile := range []string{"sidecar", "ambient"} {
		t.Run(profile, func(t *testing.T) {
			manifest := renderAgentio(t, "--set", "profile="+profile, "--set", "agentiod.networkPolicy.enabled=true")
			if got := objectNamesByKind(t, manifest, "ValidatingWebhookConfiguration"); len(got) != 1 {
				t.Fatalf("validation webhooks = %v, want one", got)
			}
			requireContains(
				t,
				manifest,
				"name: agentiod-validator-agentio-system",
				"name: AGENTIO_VALIDATION_WEBHOOK_CONFIG_NAME\n              value: \"agentiod-validator-agentio-system\"",
				"containerPort: 15017",
				"- port: 15017",
				"targetPort: https-webhook",
				"resources: [\"validatingwebhookconfigurations\"]",
				"operations: [CREATE, UPDATE]",
				"path: /validate",
				"sideEffects: None",
				"resources: [securityprofiles, globalsecurityprofiles, trafficpolicies, globaltrafficpolicies]",
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
		"name: REPAIR_SIDECAR_ANNOTATION\n              value: sidecar.agentio.kruise.io/status",
		"REPAIR_BROKEN_POD_LABEL_KEY: \"cni.agentio.kruise.io/uninitialized\"",
		"clusterTrustBundle:",
		"agentiod.agentio-system.svc.cluster.example:15012",
	)
}

func TestStaticPorterSNIPolicyFlag(t *testing.T) {
	for _, value := range []string{"default", "false", "true"} {
		t.Run(value, func(t *testing.T) {
			args := []string{
				"--set", "egressGateway.enabled=true",
				"--show-only", "templates/gateway/deployment.yaml",
			}
			want := "false"
			if value != "default" {
				args = append(args, "--set", "agentiod.enableSNITrafficPolicy="+value)
				want = value
			}
			var deployment appsv1.Deployment
			if err := yaml.Unmarshal([]byte(renderAgentio(t, args...)), &deployment); err != nil {
				t.Fatal(err)
			}
			for _, container := range deployment.Spec.Template.Spec.InitContainers {
				if container.Name == "agentio-porter" {
					for _, env := range container.Env {
						if env.Name == "AGENTIO_ENABLE_SNI_TRAFFIC_POLICY" {
							if env.Value != want {
								t.Fatalf("Porter SNI flag = %q, want %q", env.Value, want)
							}
							return
						}
					}
				}
			}
			t.Fatal("Porter SNI flag is missing")
		})
	}
}

func TestStaticEgressGateway(t *testing.T) {
	manifest := renderAgentio(t, "--set", "egressGateway.enabled=true")
	if got, want := objectNamesByKind(
		t,
		manifest,
		"Deployment",
	), []string{
		"agentio-egress",
		"agentiod",
	}; !reflect.DeepEqual(
		got,
		want,
	) {
		t.Fatalf("static gateway Deployments = %v, want %v", got, want)
	}
	if got := objectNamesByKind(t, manifest, "Gateway"); len(got) != 0 {
		t.Fatalf("static mode Gateways = %v, want none", got)
	}
	requireContains(t, manifest,
		"networking.agents.kruise.io/sandbox-egress: \"true\"",
		"gateway.networking.k8s.io/gateway-name: agentio-egress",
		"name: AGENTIO_XDS_ADDRESS",
		"name: agentio-porter",
		"--xds-cache-idle-ttl=10m",
		"--xds-cache-max-entries=0",
		"agentiod.agentio-system.svc.cluster.local:15012",
		"egressGateways:",
		"name: agentio-egress",
		"namespace: agentio-system",
	)
}

func TestStaticGatewayCPULimit(t *testing.T) {
	for _, override := range []string{"", "3"} {
		t.Run("override="+override, func(t *testing.T) {
			args := []string{"--show-only", "templates/gateway/deployment.yaml",
				"--set", "egressGateway.enabled=true", "--set", "egressGateway.resources.limits.cpu=2"}
			want := corev1.EnvVar{
				Name: "AGENTIO_CPU_LIMIT",
				ValueFrom: &corev1.EnvVarSource{ResourceFieldRef: &corev1.ResourceFieldSelector{
					Resource: "limits.cpu",
					Divisor:  resource.MustParse("1"),
				}},
			}
			if override != "" {
				args = append(args, "--set-string", "egressGateway.env.AGENTIO_CPU_LIMIT="+override)
				want = corev1.EnvVar{Name: "AGENTIO_CPU_LIMIT", Value: override}
			}
			var deployment appsv1.Deployment
			if err := yaml.Unmarshal([]byte(renderAgentio(t, args...)), &deployment); err != nil {
				t.Fatal(err)
			}
			var found []corev1.EnvVar
			for _, container := range deployment.Spec.Template.Spec.Containers {
				if container.Name != "agentio-proxy" {
					continue
				}
				for _, env := range container.Env {
					if env.Name == want.Name {
						found = append(found, env)
					}
				}
			}
			if len(found) != 1 {
				t.Fatalf("expected exactly one AGENTIO_CPU_LIMIT, got %v", found)
			}
			if !reflect.DeepEqual(found[0], want) {
				t.Fatalf("AGENTIO_CPU_LIMIT = %+v, want %+v", found[0], want)
			}
		})
	}
}

func TestGatewayAPIEgressGateway(t *testing.T) {
	manifest := renderAgentio(t,
		"--set", "agentiod.gatewayDeployer.enabled=true",
		"--set-string", "egressGateway.image.repository=registry.example/agentio/proxyv2",
		"--set-string", "egressGateway.image.tag=1.0.0",
	)
	if got := objectNamesByKind(t, manifest, "Deployment"); !reflect.DeepEqual(got, []string{"agentiod"}) {
		t.Fatalf("chart must only deploy the control plane: %v", got)
	}
	if got := objectNamesByKind(t, manifest, "Gateway"); len(got) != 0 {
		t.Fatalf("Gateway objects must be user-managed: %v", got)
	}
	requireContains(t, manifest,
		"name: AGENTIO_ENABLE_GATEWAY_DEPLOYER\n              value: \"true\"",
		"egress-gateway: |",
		`image: "registry.example/agentio/proxyv2:1.0.0"`,
	)
}

func TestStaticAndGatewayAPIGatewaysCanCoexist(t *testing.T) {
	manifest := renderAgentio(t, "--set",
		"egressGateway.enabled=true,egressGateway.networkPolicy.enabled=true,agentiod.gatewayDeployer.enabled=true",
	)
	if got := objectNamesByKind(
		t,
		manifest,
		"Deployment",
	); !reflect.DeepEqual(
		got,
		[]string{"agentio-egress", "agentiod"},
	) {
		t.Fatalf("Helm must only own its gateway Deployment and control plane: %v", got)
	}
	if got := objectNamesByKind(t, manifest, "Gateway"); len(got) != 0 {
		t.Fatalf("Gateway objects must be user-managed: %v", got)
	}
	requireContains(t, manifest, "name: AGENTIO_ENABLE_GATEWAY_DEPLOYER\n              value: \"true\"")
}

func TestAgentgatewayGatewayAPIConfiguration(t *testing.T) {
	manifest := renderAgentio(t,
		"--set", "agentiod.gatewayDeployer.enabled=true",
		"--set", "egressGateway.agentgateway.image=registry.example/agentgateway:tested",
	)
	requireContains(t, manifest, "agentgateway: |", `image: "registry.example/agentgateway:tested"`)
	if got := objectNamesByKind(t, manifest, "Gateway"); len(got) != 0 {
		t.Fatalf("native Gateway objects must be user-managed: %v", got)
	}
}

func TestAgentgatewayDefaultVersion(t *testing.T) {
	manifest := renderAgentio(t,
		"--set", "agentiod.gatewayDeployer.enabled=true",
		"--show-only", "templates/agentiod/injector.yaml",
	)
	requireContains(t, manifest, "cr.agentgateway.dev/agentgateway:v1.7.0")
}

func TestManagedEPE(t *testing.T) {
	manifest := renderAgentio(t,
		"--set", "global.tag=0.1.0",
		"--set", "epe.mode=managed",
		"--set", "epe.credentialProvider.url=https://credentials.example",
	)
	if got, want := objectNamesByKind(
		t,
		manifest,
		"Deployment",
	), []string{
		"agentio-epe",
		"agentiod",
	}; !reflect.DeepEqual(
		got,
		want,
	) {
		t.Fatalf("managed EPE Deployments = %v, want %v", got, want)
	}
	requireContains(t, manifest,
		"image: \"docker.io/openkruise/agentio-epe:0.1.0\"",
		"service: agentio-epe.agentio-system.svc.cluster.local",
		"filter_state['agentio.sandbox.metadata']",
		"filter_state['agentio.workload.name']",
		"filter_state['agentio.workload.namespace']",
		"filter_state['downstream_peer'].name",
		"filter_state['downstream_peer'].namespace",
		"port: 9002",
		"- -epe-config=agentio-epe-config",
		"- -epe-config-primary=agentio-epe-config-primary",
		"- -namespace=agentio-system",
		"- -grpc-port=9002",
		"- -grpc-health-port=9003",
		"- -metrics-port=9090",
		"--xds-cache-idle-ttl=10m",
		"--xds-cache-max-entries=10000",
		"- -audit-webhook-insecure-skip-verify=false",
		"livenessProbe:",
		"readinessProbe:",
		"name: CREDENTIAL_PROVIDER_MTLS_SOURCE\n              value: \"none\"",
	)
	if strings.Contains(manifest, "credential-provider-mtls") {
		t.Fatal("managed EPE must not mount credential-provider certificates")
	}
}

func TestManagedEPEGracefulShutdown(t *testing.T) {
	for _, tc := range []struct {
		name  string
		delay int64
		grace int64
		args  []string
	}{
		{name: "defaults", delay: 10, grace: 45},
		{
			name:  "custom budget",
			delay: 5,
			grace: 60,
			args:  []string{"--set", "epe.preStopDelaySeconds=5,epe.terminationGracePeriodSeconds=60"},
		},
		{name: "disabled delay", grace: 45, args: []string{"--set", "epe.preStopDelaySeconds=0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append(
				[]string{"--set", "epe.mode=managed", "--show-only", "templates/epe/deployment.yaml"},
				tc.args...)
			var deployment appsv1.Deployment
			if err := yaml.Unmarshal([]byte(renderAgentio(t, args...)), &deployment); err != nil {
				t.Fatal(err)
			}
			pod := deployment.Spec.Template.Spec
			if pod.TerminationGracePeriodSeconds == nil || *pod.TerminationGracePeriodSeconds != tc.grace {
				t.Fatalf("termination grace = %v, want %d", pod.TerminationGracePeriodSeconds, tc.grace)
			}
			var want *corev1.Lifecycle
			if tc.delay > 0 {
				want = &corev1.Lifecycle{
					PreStop: &corev1.LifecycleHandler{Sleep: &corev1.SleepAction{Seconds: tc.delay}},
				}
			}
			if got := pod.Containers[0].Lifecycle; !reflect.DeepEqual(got, want) {
				t.Fatalf("EPE lifecycle = %+v, want %+v", got, want)
			}
		})
	}
}

func TestManagedEPERejectsInvalidShutdownBudget(t *testing.T) {
	for _, values := range []string{
		"epe.preStopDelaySeconds=-1",
		"epe.preStopDelaySeconds=1.5",
		"epe.preStopDelaySeconds=10s",
		"epe.terminationGracePeriodSeconds=0",
		"epe.terminationGracePeriodSeconds=-1",
		"epe.terminationGracePeriodSeconds=1.5",
	} {
		t.Run(values, func(t *testing.T) {
			field, _, _ := strings.Cut(values, "=")
			requireRenderError(t, "/"+strings.ReplaceAll(field, ".", "/"),
				"--set", "epe.mode=managed", "--set", values)
		})
	}
	for _, grace := range []int{5, 10} {
		requireRenderError(t, "epe.terminationGracePeriodSeconds must exceed epe.preStopDelaySeconds",
			"--set", "epe.mode=managed", "--set", fmt.Sprintf("epe.terminationGracePeriodSeconds=%d", grace))
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

func TestTrustedEPEIdentities(t *testing.T) {
	for _, tc := range []struct {
		name   string
		values string
		want   []string
	}{
		{"managed", "epe.mode=managed", []string{"spiffe://cluster.local/ns/agentio-system/sa/agentio-epe"}},
		{"custom identity", "epe.mode=managed,global.trustDomain=example.org,epe.serviceAccount.name=processor", []string{"spiffe://example.org/ns/agentio-system/sa/processor"}},
		{"disabled", "epe.mode=disabled", nil},
		{"external", "epe.mode=external,epe.external.address=epe.example.org", nil},
		{"override", "epe.mode=managed,agentiod.config.values.trustedEPEIdentities={spiffe://example.org/ns/custom/sa/processor}", []string{"spiffe://example.org/ns/custom/sa/processor"}},
		{"clear", "epe.mode=managed,agentiod.config.values.trustedEPEIdentities=[]", []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{"--set", tc.values, "--show-only", "templates/agentiod/configmaps.yaml"}
			// --set-json preserves an explicit empty list instead of a string.
			if tc.name == "clear" {
				args = []string{
					"--set",
					"epe.mode=managed",
					"--set-json",
					"agentiod.config.values.trustedEPEIdentities=[]",
					"--show-only",
					"templates/agentiod/configmaps.yaml",
				}
			}
			manifest := renderAgentio(t, args...)
			var cm corev1.ConfigMap
			if err := yaml.Unmarshal([]byte(strings.Split(manifest, "\n---")[0]), &cm); err != nil {
				t.Fatal(err)
			}
			var config struct {
				TrustedEPEIdentities []string `json:"trustedEPEIdentities"`
			}
			if err := yaml.Unmarshal([]byte(cm.Data["config"]), &config); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(config.TrustedEPEIdentities, tc.want) {
				t.Fatalf("trustedEPEIdentities=%v, want %v", config.TrustedEPEIdentities, tc.want)
			}
		})
	}
}

func TestImmutableImageDigests(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	manifest := renderAgentio(t,
		"--set", "profile=ambient",
		"--set", "egressGateway.enabled=true",
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
	gatewayImage := "registry.example/openkruise/agentio-gateway@" + digest
	porterImage := "registry.example/openkruise/agentio-porter@" + digest
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
		porterImage,
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
		render("--set", "profile=ambient", "--set", "egressGateway.enabled=true", "--set", "epe.mode=managed"),
		render("--set", "profile=sidecar", "--set", "agentiod.gatewayDeployer.enabled=true")...,
	)
	for _, image := range []string{
		`image: "` + agentiodImage + `"`,
		`image: "` + epeImage + `"`,
		`image: "` + ztunnelImage + `"`,
		`image: "` + cniImage + `"`,
		`image: "` + proxyInitImage + `"`,
		`image: "` + gatewayImage + `"`,
		`image: "` + porterImage + `"`,
	} {
		if !bytes.Contains(manifest, []byte(image)) {
			t.Errorf("prepared release manifest does not contain %q", image)
		}
	}
	if bytes.Contains(manifest, []byte(":latest")) {
		t.Errorf("prepared release manifest contains a mutable latest image:\n%s", manifest)
	}
	valuesData, err := os.ReadFile(filepath.Join(chartDir, "values.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var values map[string]any
	if err := yaml.Unmarshal(valuesData, &values); err != nil {
		t.Fatal(err)
	}
	gw := values["egressGateway"].(map[string]any)
	for backend, want := range map[string]string{"envoy": gatewayImage, "porter": porterImage} {
		component := gw
		if backend == "porter" {
			component = gw["porter"].(map[string]any)
		}
		image := component["image"].(map[string]any)
		if got := image["repository"].(string) + "@" + image["digest"].(string); got != want {
			t.Errorf("shared %s image = %s, want %s", backend, got, want)
		}
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
		"--set", "egressGateway.enabled=true",
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
		{
			name: "log format",
			want: "/agentiod/logging/format",
			args: []string{"--set", "agentiod.logging.format=console"},
		},
		{
			name: "agentgateway CA boolean",
			want: "/egressGateway/agentgateway/ca/enabled",
			args: []string{"--set-string", "egressGateway.agentgateway.ca.enabled=false"},
		},
		{name: "egress gateway", want: "/egressGateway/mode", args: []string{"--set", "egressGateway.mode=invalid"}},
		{
			name: "removed static mode field",
			want: "/egressGateway/mode",
			args: []string{"--set", "egressGateway.mode=static"},
		},
		{
			name: "removed controller backend configuration",
			want: "/agentiod/gatewayDeployer",
			args: []string{"--set", "agentiod.gatewayDeployer.envoy.replicaCount=2"},
		},
		{
			name: "native capacity requires resource patches",
			want: "/egressGateway/agentgateway",
			args: []string{"--set", "egressGateway.agentgateway.replicaCount=2"},
		},
		{
			name: "static gateway account mismatch",
			want: "egressGateway.serviceAccount.name must match the gateway name",
			args: []string{"--set", "egressGateway.enabled=true,egressGateway.serviceAccount.name=custom-account"},
		},
		{name: "EPE", want: "/epe/mode", args: []string{"--set", "epe.mode=invalid"}},
		{name: "external EPE address", want: "/epe/external/address", args: []string{"--set", "epe.mode=external"}},
		{
			name: "Gateway objects are user-managed",
			want: "/agentiod/gatewayDeployer",
			args: []string{"--set", "agentiod.gatewayDeployer.gateway.create=true"},
		},
		{
			name: "removed Gateway API root",
			want: "/gatewayAPI",
			args: []string{"--set", "gatewayAPI.enabled=true"},
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
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			requireRenderError(t, tc.want, tc.args...)
		})
	}
}

func TestEveryProfileAndModeCombinationRendersUniqueObjects(t *testing.T) {
	tests := [][]string{
		nil,
		{"--set", "profile=ambient"},
		{"--set", "profile=sidecar"},
		{
			"--set",
			"egressGateway.enabled=true",
			"--set",
			"epe.mode=managed",
			"--set",
			"epe.credentialProvider.url=https://credentials.example",
		},
		{
			"--set",
			"agentiod.gatewayDeployer.enabled=true",
			"--set",
			"epe.mode=external",
			"--set",
			"epe.external.address=epe.example.internal",
		},
	}
	for i, args := range tests {
		t.Run(fmt.Sprintf("combination-%d", i), func(t *testing.T) {
			seen := map[string]struct{}{}
			for _, object := range renderedObjects(t, renderAgentio(t, args...)) {
				key := fmt.Sprintf(
					"%s/%s/%s/%s",
					object.APIVersion,
					object.Kind,
					object.Metadata.Namespace,
					object.Metadata.Name,
				)
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
				"--set", "agentiod.gatewayDeployer.enabled=true",
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
				if g.Agentgateway.CA.Enabled != enabled || g.SDS.Token.Aud != "gateway-ca" ||
					g.TrustBundleName != "gateway-root" ||
					g.CAAddress != "agentiod.agentio-system.svc.cluster.local:15012" {
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
	requireNotContains(t, manifest, "-ca-address")
	requireContains(
		t,
		manifest,
		"workload-root",
		"workload-token",
		"--xds-address=agentiod.agentio-system.svc.cluster.local:15012",
	)

	// User-provided mounts also serve outbound provider files with inbound TLS off.
	plain := renderAgentio(t, "-f", valuesFile, "--set", "epe.tls.enabled=false",
		"--show-only", "templates/epe/deployment.yaml")
	requireContains(t, plain, "secretName: epe-server", "mountPath: /custom/trust")
	requireNotContains(t, plain, "-tls-source=", "-tls-cert-path=")
	requireContains(
		t,
		plain,
		"workload-root",
		"workload-token",
		"--xds-address=agentiod.agentio-system.svc.cluster.local:15012",
	)

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

func TestAgentiodXDSCPUBudget(t *testing.T) {
	for _, tc := range []struct {
		name string
		want string
		args []string
	}{
		{"default request", "500m", nil},
		{"CPU limit preferred", "2", []string{"--set", "agentiod.resources.limits.cpu=2"}},
		{"explicit budget", "750m", []string{"--set", "agentiod.resources.limits.cpu=2", "--set-string", "agentiod.env.AGENTIO_XDS_CPU_BUDGET=750m"}},
		{"explicit empty fallback", "", []string{"--set-string", "agentiod.env.AGENTIO_XDS_CPU_BUDGET="}},
		{"no CPU resources", "", []string{"--set", "agentiod.resources.requests.cpu=null"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manifest := renderAgentio(t, tc.args...)
			found := false
			for document := range strings.SplitSeq(manifest, "\n---") {
				var object renderedObject
				if err := yaml.Unmarshal([]byte(document), &object); err != nil {
					t.Fatal(err)
				}
				if object.Kind != "Deployment" || object.Metadata.Name != "agentiod" {
					continue
				}
				found = true
				var deployment appsv1.Deployment
				if err := yaml.Unmarshal([]byte(document), &deployment); err != nil {
					t.Fatal(err)
				}
				count := 0
				for _, variable := range deployment.Spec.Template.Spec.Containers[0].Env {
					if variable.Name != "AGENTIO_XDS_CPU_BUDGET" {
						continue
					}
					count++
					if variable.Value != tc.want {
						t.Fatalf("budget = %q, want %q", variable.Value, tc.want)
					}
				}
				wantCount := 1
				if tc.name == "no CPU resources" {
					wantCount = 0
				}
				if count != wantCount {
					t.Fatalf("budget entries = %d, want %d", count, wantCount)
				}
			}
			if !found {
				t.Fatal("agentiod deployment missing")
			}
		})
	}
}
