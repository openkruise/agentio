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

package gateway

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/test/e2e"
	"github.com/openkruise/agentio/test/e2e/components/echo"
	"github.com/openkruise/agentio/test/e2e/components/echo/check"
	"github.com/openkruise/agentio/test/e2e/components/forwardproxy"
	e2econfig "github.com/openkruise/agentio/test/e2e/config"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

const (
	connectProxyHost          = "connect-proxy.test"
	invalidConnectProxyHost   = "invalid-connect-proxy.test"
	connectProxyHTTPNodePort  = 32128
	connectProxyHTTPSNodePort = 32129
	connectTargetHTTPSPort    = 8443
)

func TestSandboxExternalHTTP(t *testing.T) {
	_, scope := rig.BeginScenario(t)
	src := trafficFixture.Client

	rig.ApplyConfig(t, scope, map[string]any{
		"Namespace": resolvedAgentioConfig.Namespace,
	}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    egressPolicies:
    - gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
`)

	// www.example.com is IANA-reserved and serves a stable response over plain
	// HTTP. Following redirects accepts its eventual redirect to HTTPS.
	src.CallOrFail(t, echo.CallOptions{
		Protocol:        echo.HTTP,
		Address:         "www.example.com",
		Port:            80,
		Count:           1,
		FollowRedirects: true,
		Check:           check.OK(),
		Retry:           harness.FixedRetry(2*time.Minute, 5*time.Second),
	})
}

func TestSandboxOnDemandCert(t *testing.T) {
	_, scope := rig.BeginScenario(t)

	curl := func() (string, string, error) {
		ctx, cancel := e2e.Context(t, 15*time.Second)
		defer cancel()
		return externalCurl(ctx,
			"-o", "/dev/null", "-w", "%{http_code}", "--max-time", "10", "https://example.com")
	}
	curlInsecure := func() (string, string, error) {
		ctx, cancel := e2e.Context(t, 15*time.Second)
		defer cancel()
		return externalCurl(ctx,
			"-k", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "10", "https://example.com")
	}

	t.Run("https to example.com without tls termination", func(t *testing.T) {
		rig.ApplyConfig(t, scope, map[string]any{
			"Namespace": resolvedAgentioConfig.Namespace,
		}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    egressPolicies:
    - gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
`)

		harness.RetryAssertion(t, 2*time.Minute, 5*time.Second, func() error {
			stdout, stderr, err := curl()
			if err != nil {
				return fmt.Errorf("curl failed without termination: %v\nstdout=%s\nstderr=%s", err, stdout, stderr)
			}
			return nil
		})
	})

	t.Run("https to example.com with tls termination requires insecure", func(t *testing.T) {
		applyGatewayTLSTerminationProfile(t, scope, "example.com")
		rig.ApplyConfig(t, scope, map[string]any{
			"Namespace": resolvedAgentioConfig.Namespace,
		}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    egressPolicies:
    - gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
    egressGateways:
    - name: egress-gateway
      namespace: {{ .Namespace }}
      tlsTermination:
        includeHosts:
        - "example.com"
`)

		harness.RetryAssertion(t, 2*time.Minute, 5*time.Second, func() error {
			stdout, stderr, err := curl()
			if err == nil {
				return fmt.Errorf("expected curl to fail with cert error, got success: stdout=%s", stdout)
			}
			if !strings.Contains(stderr, "SSL certificate") &&
				!strings.Contains(stderr, "self-signed") &&
				!strings.Contains(stderr, "unable to get local issuer") {
				return fmt.Errorf("expected SSL cert error, got: %v\nstderr=%s", err, stderr)
			}
			return nil
		})

		harness.RetryAssertion(t, 2*time.Minute, 5*time.Second, func() error {
			stdout, stderr, err := curlInsecure()
			if err != nil {
				return fmt.Errorf("curl -k failed under termination: %v\nstdout=%s\nstderr=%s", err, stdout, stderr)
			}
			return nil
		})
	})
}

func TestSandboxTLSExcludeHosts(t *testing.T) {
	_, scope := rig.BeginScenario(t)
	applyGatewayTLSTerminationProfile(t, scope, "example.com", "www.example.org")

	curl := func(host string) (string, string, error) {
		ctx, cancel := e2e.Context(t, 20*time.Second)
		defer cancel()
		return externalCurl(ctx,
			"-o", "/dev/null", "-w", "%{http_code}", "--max-time", "15", "https://"+host)
	}

	rig.ApplyConfig(t, scope, map[string]any{
		"Namespace": resolvedAgentioConfig.Namespace,
	}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    egressPolicies:
    - gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
    egressGateways:
    - name: egress-gateway
      namespace: {{ .Namespace }}
      tlsTermination:
        includeHosts:
        - "example.com"
        excludeHosts:
        - "www.example.org"
`)

	t.Run("excluded host bypasses termination", func(t *testing.T) {
		harness.RetryAssertion(t, 2*time.Minute, 5*time.Second, func() error {
			stdout, stderr, err := curl("www.example.org")
			if err != nil {
				return fmt.Errorf("excluded host should have used real cert, got: %v\nstderr=%s", err, stderr)
			}
			if stdout == "" {
				return fmt.Errorf("empty status from example.org, stderr=%s", stderr)
			}
			return nil
		})
	})

	t.Run("included host still terminates with sandbox CA", func(t *testing.T) {
		harness.RetryAssertion(t, 2*time.Minute, 5*time.Second, func() error {
			stdout, stderr, err := curl("example.com")
			if err == nil {
				return fmt.Errorf("expected SSL trust failure for included host, got success: stdout=%s", stdout)
			}
			if !strings.Contains(stderr, "SSL certificate") &&
				!strings.Contains(stderr, "self-signed") &&
				!strings.Contains(stderr, "unable to get local issuer") {
				return fmt.Errorf("expected SSL cert error, got: %v\nstderr=%s", err, stderr)
			}
			return nil
		})
	})
}

func TestSandboxEgressHTTP2(t *testing.T) {
	_, scope := rig.BeginScenario(t)
	applyGatewayTLSTerminationProfile(t, scope, "example.com")

	rig.ApplyConfig(t, scope, map[string]any{
		"Namespace": resolvedAgentioConfig.Namespace,
	}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    egressPolicies:
    - gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
    egressGateways:
    - name: egress-gateway
      namespace: {{ .Namespace }}
      tlsTermination:
        includeHosts:
        - "example.com"
`)

	curlVersion := func(httpFlag string) (string, error) {
		ctx, cancel := e2e.Context(t, 15*time.Second)
		defer cancel()
		stdout, stderr, err := externalCurl(ctx,
			"-k", "-o", "/dev/null", "-w", "%{http_version}", "--max-time", "10", httpFlag, "https://example.com")
		if err != nil {
			return "", fmt.Errorf("curl failed: %v, stderr: %s", err, stderr)
		}
		return strings.Trim(stdout, "' \n"), nil
	}

	t.Run("h2 through tls termination", func(t *testing.T) {
		harness.RetryAssertion(t, 2*time.Minute, 5*time.Second, func() error {
			version, err := curlVersion("--http2")
			if err != nil {
				return err
			}
			if version != "2" {
				return fmt.Errorf("expected HTTP version 2, got %s", version)
			}
			return nil
		})
	})

	t.Run("http/1.1 through tls termination", func(t *testing.T) {
		harness.RetryAssertion(t, 2*time.Minute, 5*time.Second, func() error {
			version, err := curlVersion("--http1.1")
			if err != nil {
				return err
			}
			if version != "1.1" {
				return fmt.Errorf("expected HTTP version 1.1, got %s", version)
			}
			return nil
		})
	})
}

func TestSandboxEgressSNIHostMatch(t *testing.T) {
	_, scope := rig.BeginScenario(t)
	applyGatewayTLSTerminationProfile(t, scope, "example.com")
	src := trafficFixture.Client

	rig.ApplyConfig(t, scope, map[string]any{
		"Namespace": resolvedAgentioConfig.Namespace,
	}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    egressPolicies:
    - gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
    egressGateways:
    - name: egress-gateway
      namespace: {{ .Namespace }}
      tlsTermination:
        includeHosts:
        - "example.com"
`)

	callOptions := func(hostHeader string) echo.CallOptions {
		headers := map[string]string{}
		if hostHeader != "" {
			headers["Host"] = hostHeader
		}
		return echo.CallOptions{
			Protocol:   echo.HTTPS,
			Address:    "example.com",
			Port:       443,
			Count:      1,
			Headers:    headers,
			ServerName: "example.com",
			Retry:      harness.FixedRetry(2*time.Minute, 5*time.Second),
		}
	}

	allowed := check.And(check.NoError(), check.NotStatus(http.StatusForbidden))
	denied := check.NoErrorAndStatus(http.StatusForbidden)

	t.Run("sni matches host: allowed", func(t *testing.T) {
		options := callOptions("")
		options.Check = allowed
		src.CallOrFail(t, options)
	})

	t.Run("sni matches host with port suffix: allowed", func(t *testing.T) {
		options := callOptions("example.com:443")
		options.Check = allowed
		src.CallOrFail(t, options)
	})

	t.Run("sni matches host case insensitive: allowed", func(t *testing.T) {
		options := callOptions("EXAMPLE.COM")
		options.Check = allowed
		src.CallOrFail(t, options)
	})

	t.Run("sni differs from host: denied with 403", func(t *testing.T) {
		options := callOptions("example.org")
		options.Check = denied
		ctx, cancel := e2e.Context(t, 2*time.Minute+6*time.Second)
		defer cancel()
		result, err := src.Call(ctx, options)
		if err != nil {
			t.Fatalf("expected 403 for SNI=example.com Host=example.org — egress allowlist may be bypassed: %v; attempts: %+v", err, result.Attempts)
		}
	})

	t.Run("sni differs from host different port: denied with 403", func(t *testing.T) {
		options := callOptions("example.org:443")
		options.Check = denied
		ctx, cancel := e2e.Context(t, 2*time.Minute+6*time.Second)
		defer cancel()
		result, err := src.Call(ctx, options)
		if err != nil {
			t.Fatalf("expected 403 for SNI=example.com Host=example.org:443: %v; attempts: %+v", err, result.Attempts)
		}
	})
}

func TestSandboxForwardHTTPConnect(t *testing.T) {
	environment, scope := rig.BeginScenario(t)
	applyGatewayTLSTerminationProfile(t, scope, connectProxyHost, invalidConnectProxyHost)
	proxyKey, proxyCertChain, proxyCA := generateConnectProxyCertificate(t, connectProxyHost)
	bootstrap := forwardproxy.Bootstrap()
	systemNamespace := resolvedAgentioConfig.Namespace

	e2econfig.New(scope).Eval(systemNamespace, map[string]any{
		"EnvoyYAML":         bootstrap,
		"ProxyKey":          proxyKey,
		"ProxyCertChain":    proxyCertChain,
		"ProxyCA":           proxyCA,
		"ForwardProxyImage": resolvedAgentioConfig.ForwardProxyImage,
	}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: forward-http-connect-proxy
data:
  envoy.yaml: {{ printf "%q" .EnvoyYAML }}
  external-forward-proxy-key.pem: {{ printf "%q" .ProxyKey }}
  external-forward-proxy-cert.pem: {{ printf "%q" .ProxyCertChain }}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: forward-http-connect-proxy
spec:
  replicas: 1
  selector:
    matchLabels:
      app: forward-http-connect-proxy
  template:
    metadata:
      labels:
        app: forward-http-connect-proxy
    spec:
      containers:
      - name: envoy
        image: {{ .ForwardProxyImage }}
        imagePullPolicy: IfNotPresent
        volumeMounts:
        - name: config
          mountPath: /etc/envoy
      volumes:
      - name: config
        configMap:
          name: forward-http-connect-proxy
---
apiVersion: v1
kind: Service
metadata:
  name: forward-http-connect-proxy
spec:
  type: NodePort
  selector:
    app: forward-http-connect-proxy
  ports:
  - name: http-connect
    port: 3128
    targetPort: 3128
    nodePort: 32128
  - name: https-connect
    port: 4128
    targetPort: 4128
    nodePort: 32129
---
apiVersion: v1
kind: Secret
metadata:
  name: forward-http-connect-proxy-ca
stringData:
  ca.crt: {{ printf "%q" .ProxyCA }}
`).ApplyOrFail(t, kube.CreateOnly)

	readyCtx, readyCancel := e2e.Context(t, 2*time.Minute)
	defer readyCancel()
	proxyPods, err := environment.Kube.WaitReadyPods(
		readyCtx, systemNamespace, "app=forward-http-connect-proxy", 1,
	)
	if err != nil {
		t.Fatalf("forward proxy deployment not ready: %v", err)
	}

	rig.ApplyConfig(t, scope, map[string]any{
		"Namespace": systemNamespace,
	}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    sandboxExtProc:
      service: ext-proc.{{ .Namespace }}.svc.cluster.local
      port: 9002
      failureModeAllow: false
      request:
        headerMode: SEND
        attributes:
        - destination.port
      response:
        headerMode: SEND
    egressPolicies:
    - gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
    egressGateways:
    - name: egress-gateway
      namespace: {{ .Namespace }}
      upstreamTrustBundle:
        additionalSources:
        - secretRef: {name: forward-http-connect-proxy-ca, key: ca.crt}
      tlsTermination:
        includeHosts:
        - "`+connectProxyHost+`"
        - "`+invalidConnectProxyHost+`"
`)

	nodeIP := firstNodeInternalIP(t, environment)
	// The pinned suite targets another ambient echo instance. The Agentio
	// ordinary-Pod projection gives that target a dedicated ztunnel, which an
	// unmeshed explicit proxy cannot enter. Keep the same real nested TLS flow
	// against the proxy fixture's local HTTPS listener instead.
	target := net.JoinHostPort(proxyPods[0].Status.PodIP, strconv.Itoa(connectTargetHTTPSPort))

	curlThroughProxy := func(proxyHost, scheme string, proxyPort int) (string, string, error) {
		proxyURL := fmt.Sprintf("%s://%s:%d", scheme, proxyHost, proxyPort)
		resolve := fmt.Sprintf("%s:%d:%s", proxyHost, proxyPort, nodeIP)
		ctx, cancel := e2e.Context(t, 25*time.Second)
		defer cancel()
		return externalCurl(ctx,
			"-k", "--proxy-insecure", "--noproxy", "", "-o", "/dev/null",
			"-w", "%{http_code}:%{http_connect}", "--connect-timeout", "10", "--max-time", "20",
			"--resolve", resolve, "--proxy", proxyURL, "https://"+target+"/")
	}

	for _, test := range []struct {
		name      string
		scheme    string
		proxyPort int
	}{
		{name: "HTTP proxy", scheme: "http", proxyPort: connectProxyHTTPNodePort},
		{name: "HTTPS proxy", scheme: "https", proxyPort: connectProxyHTTPSNodePort},
	} {
		t.Run(test.name, func(t *testing.T) {
			harness.RetryAssertion(t, 2*time.Minute, 5*time.Second, func() error {
				stdout, stderr, err := curlThroughProxy(connectProxyHost, test.scheme, test.proxyPort)
				if err != nil {
					return fmt.Errorf("curl through %s failed: %v; stdout=%q stderr=%q", test.name, err, stdout, stderr)
				}
				if codes := strings.TrimSpace(stdout); codes != "200:200" {
					return fmt.Errorf("curl through %s returned target:CONNECT codes %s, want 200:200; stderr=%q", test.name, codes, stderr)
				}
				return nil
			})
		})
	}

	assertTLSRejected := func(proxyHost string) {
		t.Helper()
		harness.RetryAssertion(t, 2*time.Minute, 5*time.Second, func() error {
			// An unencrypted proxy request remains a positive control for connectivity.
			stdout, stderr, err := curlThroughProxy(connectProxyHost, "http", connectProxyHTTPNodePort)
			if err != nil || strings.TrimSpace(stdout) != "200:200" {
				return fmt.Errorf("HTTP proxy control: codes=%q error=%v stderr=%q", stdout, err, stderr)
			}
			stdout, stderr, curlErr := curlThroughProxy(proxyHost, "https", connectProxyHTTPSNodePort)
			codes := strings.Split(strings.TrimSpace(stdout), ":")
			if len(codes) != 2 {
				return fmt.Errorf("parse curl target:CONNECT codes %q: curl error=%v stderr=%q", stdout, curlErr, stderr)
			}
			code, err := strconv.Atoi(codes[1])
			if err != nil {
				return fmt.Errorf("parse curl CONNECT code %q: %v; curl error=%v stderr=%q", codes[1], err, curlErr, stderr)
			}
			if code < 500 || code > 599 {
				return fmt.Errorf("untrusted HTTPS proxy returned CONNECT %d, want 5xx rejection; curl error=%v stderr=%q", code, curlErr, stderr)
			}
			return nil
		})
	}
	t.Run("HTTPS proxy certificate SAN mismatch", func(t *testing.T) {
		assertTLSRejected(invalidConnectProxyHost)
	})
	t.Run("Secret CA updates", func(t *testing.T) {
		ctx, cancel := e2e.Context(t, 5*time.Minute)
		defer cancel()
		_, _, unrelatedCA := generateConnectProxyCertificate(t, connectProxyHost)
		for _, ca := range []string{unrelatedCA, proxyCA} {
			secret, err := environment.Cluster.Kube.CoreV1().Secrets(systemNamespace).Get(ctx, "forward-http-connect-proxy-ca", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			secret.Data["ca.crt"] = []byte(ca)
			if _, err := environment.Cluster.Kube.CoreV1().Secrets(systemNamespace).Update(ctx, secret, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			if ca == unrelatedCA {
				assertTLSRejected(connectProxyHost)
				continue
			}
			harness.RetryAssertion(t, 2*time.Minute, 5*time.Second, func() error {
				stdout, stderr, err := curlThroughProxy(connectProxyHost, "https", connectProxyHTTPSNodePort)
				if err != nil || strings.TrimSpace(stdout) != "200:200" {
					return fmt.Errorf("restored HTTPS proxy CA: codes=%q error=%v stderr=%q", stdout, err, stderr)
				}
				return nil
			})
		}
	})
}

func firstNodeInternalIP(t testing.TB, environment *e2e.Environment) string {
	t.Helper()
	if environment == nil || environment.Cluster == nil || environment.Cluster.Kube == nil {
		t.Fatal("node lookup requires a Kubernetes environment")
	}
	ctx, cancel := e2e.Context(t, time.Minute)
	defer cancel()
	nodes, err := environment.Cluster.Kube.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	for _, node := range nodes.Items {
		for _, address := range node.Status.Addresses {
			if address.Type == corev1.NodeInternalIP {
				return address.Address
			}
		}
	}
	t.Fatal("no node InternalIP found")
	return ""
}
