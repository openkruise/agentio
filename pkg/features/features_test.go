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

package features

import (
	"math"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"istio.io/istio/pkg/env"
	"istio.io/istio/pkg/test"
)

func TestRegisteredEnvironmentVariablesUseAgentioNamespace(t *testing.T) {
	for _, variable := range env.VarDescriptions() {
		if variable.Name != "ENABLE_POLICY_STATUS" && !strings.HasPrefix(variable.Name, "AGENTIO_") {
			t.Errorf("registered environment variable %q does not use the Agentio namespace", variable.Name)
		}
	}
}

func TestValidateDomains(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*testing.T)
		wantErr string
	}{
		{
			name: "xds",
			mutate: func(t *testing.T) {
				test.SetForTest(t, &KRTDebounceAfter, time.Duration(0))
			},
			wantErr: "KRT debounce quiet period",
		},
		{
			name: "xds max server connection age",
			mutate: func(t *testing.T) {
				test.SetForTest(t, &MaxServerConnectionAge, -time.Second)
			},
			wantErr: "max server connection age",
		},
		{
			name: "networking",
			mutate: func(t *testing.T) {
				test.SetForTest(t, &ClientTrustPackagePath, " ")
			},
			wantErr: "public CA trust package path is required",
		},
		{
			name: "ca rotation",
			mutate: func(t *testing.T) {
				test.SetForTest(t, &CARootLifetime, time.Duration(0))
			},
			wantErr: "invalid CA rotation durations",
		},
		{
			name: "mitm",
			mutate: func(t *testing.T) {
				test.SetForTest(t, &MITMSignMode, "unsupported")
			},
			wantErr: "unsupported MITM sign mode",
		},
		{
			name:    "MITM resource TTL",
			mutate:  func(t *testing.T) { test.SetForTest(t, &MITMResourceTTL, time.Duration(0)) },
			wantErr: "invalid MITM certificate durations",
		},
		{
			name: "workload certificates",
			mutate: func(t *testing.T) {
				test.SetForTest(t, &WorkloadCertRenewBefore, 2*time.Hour)
			},
			wantErr: "invalid workload certificate durations",
		},
		{
			name: "control plane",
			mutate: func(t *testing.T) {
				test.SetForTest(t, &TokenAudience, " ")
			},
			wantErr: "token audience is required",
		},
		{
			name: "gateway deployer",
			mutate: func(t *testing.T) {
				test.SetForTest(t, &EnableGatewayDeployer, true)
				test.SetForTest(t, &GatewayLeaseName, " ")
			},
			wantErr: "gateway deployer lease name is required",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setValidFeatures(t)
			tt.mutate(t)
			if err := Validate(); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateAllowsDisabledMaxServerConnectionAge(t *testing.T) {
	setValidFeatures(t)
	test.SetForTest(t, &MaxServerConnectionAge, time.Duration(0))
	if err := Validate(); err != nil {
		t.Fatalf("Validate() rejected disabled max server connection age: %v", err)
	}
}

func TestValidatePreservesFirstErrorOrder(t *testing.T) {
	setValidFeatures(t)
	test.SetForTest(t, &KRTDebounceAfter, time.Duration(0))
	test.SetForTest(t, &GatewayConnectTimeout, time.Duration(0))

	if err := Validate(); err == nil || !strings.Contains(err.Error(), "KRT debounce quiet period") {
		t.Fatalf("Validate() error = %v, want KRT validation before networking validation", err)
	}
}

func TestValidateNetworkingWithTrustPackage(t *testing.T) {
	test.SetForTest(t, &ClientTrustPackagePath, "/packages/ca.json")
	test.SetForTest(t, &GatewayRootCAPath, "unused-relative-path")
	if err := validateNetworking(); err != nil {
		t.Fatal(err)
	}
	test.SetForTest(t, &GatewayConnectTimeout, time.Duration(0))
	if err := validateNetworking(); err == nil {
		t.Fatal("trust package must not bypass connect timeout validation")
	}
}

func TestClientTrustPackagePathEnvironment(t *testing.T) {
	const expectedEnv = "AGENTIO_TEST_TRUST_PACKAGE_PATH"
	if want, helper := os.LookupEnv(expectedEnv); helper {
		if ClientTrustPackagePath != want {
			t.Fatalf("ClientTrustPackagePath = %q, want %q", ClientTrustPackagePath, want)
		}
		return
	}
	for _, tc := range []struct {
		name  string
		value string
		want  string
	}{
		{"default", "", "/usr/local/share/agentio/trust-package/cert-manager-package-debian.json"},
		{"override", "/packages/custom.json", "/packages/custom.json"},
		{"empty", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command := exec.Command(os.Args[0], "-test.run=^TestClientTrustPackagePathEnvironment$")
			for _, variable := range os.Environ() {
				if !strings.HasPrefix(variable, "AGENTIO_CLIENT_TRUST_PACKAGE_PATH=") &&
					!strings.HasPrefix(variable, expectedEnv+"=") {
					command.Env = append(command.Env, variable)
				}
			}
			command.Env = append(command.Env, expectedEnv+"="+tc.want)
			if tc.name != "default" {
				command.Env = append(command.Env, "AGENTIO_CLIENT_TRUST_PACKAGE_PATH="+tc.value)
			}
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("environment test: %v\n%s", err, output)
			}
		})
	}
}

func TestValidateKubernetesAPILimits(t *testing.T) {
	for _, qps := range []float64{0, -1, math.NaN(), math.Inf(1), math.MaxFloat64, math.SmallestNonzeroFloat64} {
		t.Run("invalid QPS", func(t *testing.T) {
			setValidFeatures(t)
			test.SetForTest(t, &KubernetesAPIQPS, qps)
			if err := Validate(); err == nil || !strings.Contains(err.Error(), "Kubernetes API QPS") {
				t.Fatalf("Validate() with QPS %v = %v, want Kubernetes API QPS error", qps, err)
			}
		})
	}
	for _, burst := range []int{0, -1} {
		t.Run("invalid burst", func(t *testing.T) {
			setValidFeatures(t)
			test.SetForTest(t, &KubernetesAPIBurst, burst)
			if err := Validate(); err == nil || !strings.Contains(err.Error(), "Kubernetes API burst") {
				t.Fatalf("Validate() with burst %v = %v, want Kubernetes API burst error", burst, err)
			}
		})
	}
}

func setValidFeatures(t *testing.T) {
	t.Helper()
	test.SetForTest(t, &XDSClientClasses, "")
	test.SetForTest(t, &KubernetesAPIQPS, 80)
	test.SetForTest(t, &KubernetesAPIBurst, 160)
	test.SetForTest(t, &KRTDebounceAfter, time.Millisecond)
	test.SetForTest(t, &KRTDebounceMax, 2*time.Millisecond)
	test.SetForTest(t, &PushDebounceAfter, time.Millisecond)
	test.SetForTest(t, &PushDebounceMax, 2*time.Millisecond)
	test.SetForTest(t, &PushConcurrency, 1)
	test.SetForTest(t, &XDSMaxPodStreams, 0)
	test.SetForTest(t, &XDSInitialAdmissionTimeout, time.Second)
	test.SetForTest(t, &XDSRateLimitTimeout, time.Second)
	test.SetForTest(t, &XDSSendTimeout, 5*time.Second)
	test.SetForTest(t, &XDSACKTimeout, 5*time.Second)
	test.SetForTest(t, &RequestRateLimit, 1)
	test.SetForTest(t, &ClientQueueSize, 1)
	test.SetForTest(t, &MaxServerConnectionAge, 30*time.Minute)
	test.SetForTest(t, &GatewayConnectTimeout, time.Second)
	test.SetForTest(t, &ClientTrustPackagePath, "/packages/ca.json")
	test.SetForTest(t, &CARootLifetime, 10*time.Hour)
	test.SetForTest(t, &CARenewBefore, 3*time.Hour)
	test.SetForTest(t, &CARotationCheckInterval, time.Hour)
	test.SetForTest(t, &MITMSignMode, "SELF_SIGN")
	test.SetForTest(t, &MITMRootLifetime, 10*time.Hour)
	test.SetForTest(t, &MITMRootRenewBefore, 3*time.Hour)
	test.SetForTest(t, &MITMRotationCheckInterval, time.Hour)
	test.SetForTest(t, &MITMLeafLifetime, 2*time.Hour)
	test.SetForTest(t, &MITMRenewBefore, time.Hour)
	test.SetForTest(t, &MITMCacheMaxAge, time.Hour)
	test.SetForTest(t, &MITMCacheMaxEntries, 1)
	test.SetForTest(t, &MITMSignConcurrency, 1)
	test.SetForTest(t, &WorkloadCertLifetime, 2*time.Hour)
	test.SetForTest(t, &WorkloadCertRenewBefore, time.Hour)
	test.SetForTest(t, &TokenAudience, "agentio-ca")
	test.SetForTest(t, &EnableGatewayDeployer, false)
	test.SetForTest(t, &GatewayLeaseName, "agentiod-gateway-deployer-leader")
}

func TestXDSClientClasses(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  []string
		valid bool
	}{
		{"", nil, true},
		{"shared-ztunnel,dedicated-ztunnel", []string{"shared-ztunnel", "dedicated-ztunnel"}, true},
		{"egress-gateway, agentio-egress,epe", []string{"egress-gateway", "agentio-egress", "epe"}, true},
		{"dedicated-ztunnel,", nil, false},
		{"unknown", nil, false},
	} {
		t.Run(tc.value, func(t *testing.T) {
			setValidFeatures(t)
			test.SetForTest(t, &XDSClientClasses, tc.value)
			err := Validate()
			if (err == nil) != tc.valid {
				t.Fatalf("Validate() = %v, valid=%t", err, tc.valid)
			}
			if tc.valid && !slices.Equal(AllowedXDSClientClasses(), tc.want) {
				t.Fatalf("classes=%v, want %v", AllowedXDSClientClasses(), tc.want)
			}
		})
	}
}

func TestValidateXDSFlowControlTimeouts(t *testing.T) {
	for _, timeout := range []struct {
		name  string
		value *time.Duration
	}{
		{"AGENTIO_XDS_INITIAL_ADMISSION_TIMEOUT", &XDSInitialAdmissionTimeout},
		{"AGENTIO_XDS_RATE_LIMIT_TIMEOUT", &XDSRateLimitTimeout},
		{"AGENTIO_XDS_SEND_TIMEOUT", &XDSSendTimeout},
		{"AGENTIO_XDS_ACK_TIMEOUT", &XDSACKTimeout},
	} {
		for _, invalid := range []time.Duration{0, -time.Second} {
			t.Run(timeout.name+"/"+invalid.String(), func(t *testing.T) {
				setValidFeatures(t)
				test.SetForTest(t, timeout.value, invalid)
				if err := Validate(); err == nil || !strings.Contains(err.Error(), timeout.name) {
					t.Fatalf("Validate() = %v, want named timeout validation", err)
				}
			})
		}
	}
}

func TestValidateRejectsNegativeMaxStreams(t *testing.T) {
	setValidFeatures(t)
	test.SetForTest(t, &XDSMaxPodStreams, -1)
	if err := Validate(); err == nil || !strings.Contains(err.Error(), "AGENTIO_XDS_MAX_POD_STREAMS") {
		t.Fatalf("Validate=%v", err)
	}
}

func TestValidateAllowsDisabledPushDebounce(t *testing.T) {
	setValidFeatures(t)
	test.SetForTest(t, &PushDebounceAfter, time.Duration(0))
	test.SetForTest(t, &PushDebounceMax, time.Duration(0))
	if err := Validate(); err != nil {
		t.Fatal(err)
	}
	test.SetForTest(t, &PushDebounceAfter, -time.Millisecond)
	if err := Validate(); err == nil {
		t.Fatal("negative push debounce accepted")
	}
}

func TestMITMResourceTTLEnvironment(t *testing.T) {
	const expectedEnv = "AGENTIO_MITM_RESOURCE_TTL_TEST_EXPECTED"
	if expected := os.Getenv(expectedEnv); expected != "" {
		if got := MITMResourceTTL.String(); got != expected {
			t.Fatalf("resource TTL = %s, want %s", got, expected)
		}
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		value    string
		expected string
	}{
		{"default", "", "15m0s"}, {"override", "37s", "37s"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command := exec.Command(executable, "-test.run=^TestMITMResourceTTLEnvironment$")
			for _, variable := range os.Environ() {
				if !strings.HasPrefix(variable, "AGENTIO_MITM_RESOURCE_TTL=") &&
					!strings.HasPrefix(variable, expectedEnv+"=") {
					command.Env = append(command.Env, variable)
				}
			}
			command.Env = append(command.Env, expectedEnv+"="+tc.expected)
			if tc.value != "" {
				command.Env = append(command.Env, "AGENTIO_MITM_RESOURCE_TTL="+tc.value)
			}
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("environment test: %v\n%s", err, output)
			}
		})
	}
}
