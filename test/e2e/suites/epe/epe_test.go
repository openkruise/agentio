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
//
// The chart-owned sandboxExtProc block is applied explicitly because the suite
// keeps its shared primary ConfigMap at the PASSTHROUGH-only baseline.

package epe

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/test/e2e"
	"github.com/openkruise/agentio/test/e2e/components/echo"
	"github.com/openkruise/agentio/test/e2e/components/echo/check"
	e2econfig "github.com/openkruise/agentio/test/e2e/config"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/retry"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

const (
	epeName              = "agentio-epe"
	epeContainerName     = "epe"
	epeMetricsPort       = 9090
	epeSelectorProbeName = "not-the-calling-workload"

	statusIdentityBlock     = 452
	statusSelectorMatch     = 453
	statusSelectorMiss      = 454
	statusGlobalBlock       = 455
	statusPriorityGlobal    = 456
	statusPriorityNamespace = 457
)

func TestStrictEPEBodyContains(t *testing.T) {
	tests := []struct {
		name    string
		output  string
		wantErr bool
	}{
		{
			name: "URL metadata alone does not satisfy the body check",
			output: `[0] Url=http://server.sandbox.svc.cluster.local:80/epe-priority-global
[0] StatusCode=456
`,
			wantErr: true,
		},
		{
			name: "explicit body frame satisfies the body check",
			output: `[0] Url=http://server.sandbox.svc.cluster.local:80/epe-priority-global
[0] StatusCode=456
[0 body] epe-priority-global
`,
		},
		{
			name: "echo URL body metadata does not satisfy the body check",
			output: `[0] StatusCode=456
[0 body] URL=/epe-priority-global
`,
			wantErr: true,
		},
	}

	for _, current := range tests {
		current := current
		t.Run(current.name, func(t *testing.T) {
			responses, err := echo.ParseResponses(current.output)
			if err != nil {
				t.Fatal(err)
			}
			err = strictEPEBodyContains("epe-priority-global")(echo.Result{Responses: responses}, nil)
			if current.wantErr && err == nil {
				t.Fatal("strict EPE body checker accepted URL metadata without a body frame")
			}
			if !current.wantErr && err != nil {
				t.Fatalf("strict EPE body checker rejected an explicit body frame: %v", err)
			}
		})
	}
}

func TestEPESelectorProbeConfig(t *testing.T) {
	config := epeSelectorProbeConfig("sandbox")
	if config.Name != epeSelectorProbeName || config.Namespace != "sandbox" || config.Replicas != 1 {
		t.Fatalf("selector probe identity = %s/%s replicas=%d", config.Namespace, config.Name, config.Replicas)
	}
	if config.Image != echo.DefaultImage || !strings.Contains(config.Image, "@sha256:") {
		t.Fatalf("selector probe image = %q, want immutable default", config.Image)
	}
	wantLabels := map[string]string{"app": epeSelectorProbeName}
	if !reflect.DeepEqual(config.Labels, wantLabels) {
		t.Fatalf("selector probe labels = %#v, want %#v", config.Labels, wantLabels)
	}
	if len(config.PodAnnotations) != 0 {
		t.Fatalf("selector probe annotations contain dataplane enrollment: %#v", config.PodAnnotations)
	}
	if !reflect.DeepEqual(config.Ports, echo.DefaultPorts()) {
		t.Fatalf("selector probe ports = %#v, want default ports", config.Ports)
	}
	if !reflect.DeepEqual(config.Capabilities, harness.ClientCapabilities()) {
		t.Fatalf("selector probe capabilities = %#v, want %#v", config.Capabilities, harness.ClientCapabilities())
	}
	if config.CallTimeout != 90*time.Second || config.Converge != 3 {
		t.Fatalf("selector probe call policy = timeout %s converge %d", config.CallTimeout, config.Converge)
	}
}

// TestEPEServiceAccountCanWatchItsInputs pins EPE's RBAC to the resources its
// real informers open, including namespace-scoped Secret access. Fake clientsets
// do not enforce these permissions.
func TestEPEServiceAccountCanWatchItsInputs(t *testing.T) {
	rig.RequireLive(t)
	rig.RequireUncontaminated(t)
	environment := suite.Environment(t)
	attachEPELogsOnFailure(t, environment, "EPE container log follows")

	user := fmt.Sprintf("system:serviceaccount:%s:%s", resolvedAgentioConfig.Namespace, epeName)
	cases := []struct {
		group     string
		resource  string
		namespace string
		allowed   bool
	}{
		{"agents.kruise.io", "securityprofiles", "", true},
		{"agents.kruise.io", "globalsecurityprofiles", "", true},
		{"apiextensions.k8s.io", "customresourcedefinitions", "", true},
		{"", "secrets", resolvedAgentioConfig.Namespace, true},
		{"", "secrets", "", false},
		{"", "secrets", trafficFixture.Namespace.Name(), false},
	}

	for _, current := range cases {
		current := current
		for _, verb := range []string{"get", "list", "watch"} {
			verb := verb
			t.Run(fmt.Sprintf("%s/%s/%s", current.resource, current.namespace, verb), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				review := &authzv1.SubjectAccessReview{
					Spec: authzv1.SubjectAccessReviewSpec{
						User: user,
						ResourceAttributes: &authzv1.ResourceAttributes{
							Group:     current.group,
							Resource:  current.resource,
							Verb:      verb,
							Namespace: current.namespace,
						},
					},
				}
				got, err := environment.Cluster.Kube.AuthorizationV1().SubjectAccessReviews().
					Create(ctx, review, metav1.CreateOptions{})
				if err != nil {
					t.Fatalf("create SubjectAccessReview for %s %s: %v", verb, current.resource, err)
				}
				if got.Status.Allowed != current.allowed {
					t.Fatalf(
						"EPE ServiceAccount %s: %s %s.%s in namespace %q allowed=%t, want %t; "+
							"reason=%q evaluationError=%q",
						user,
						verb,
						current.resource,
						current.group,
						current.namespace,
						got.Status.Allowed,
						current.allowed,
						got.Status.Reason,
						got.Status.EvaluationError,
					)
				}
			})
		}
	}
}

// TestEPEMetricsEndpointServes checks that the advertised Prometheus endpoint
// is served on port 9090 to workloads in the cluster.
func TestEPEMetricsEndpointServes(t *testing.T) {
	rig.RequireLive(t)
	rig.RequireUncontaminated(t)
	environment := suite.Environment(t)
	attachEPELogsOnFailure(t, environment, "EPE container log follows")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	endpoint := fmt.Sprintf(
		"http://%s.%s.svc.cluster.local:%d/metrics",
		epeName, resolvedAgentioConfig.Namespace, epeMetricsPort,
	)
	stdout, err := waitForPrometheusMetrics(ctx, func(requestCtx context.Context) (string, string, error) {
		return trafficFixture.Client.Exec(
			requestCtx,
			[]string{"curl", "-sS", "--max-time", "10", endpoint},
		)
	})
	if err != nil {
		t.Fatalf("wait for EPE metrics on port %d: %v", epeMetricsPort, err)
	}
	t.Logf("EPE metrics endpoint returned %d bytes", len(stdout))
}

func waitForPrometheusMetrics(
	ctx context.Context,
	request func(context.Context) (string, string, error),
) (string, error) {
	var output string
	err := retry.UntilSuccess(ctx, retry.Policy{
		NoTimeout: true,
		Delay:     100 * time.Millisecond,
		Backoff:   1,
		MaxDelay:  100 * time.Millisecond,
		Converge:  1,
	}, func() error {
		stdout, stderr, err := request(ctx)
		if err != nil {
			return fmt.Errorf("request metrics: %w (stderr: %s)", err, strings.TrimSpace(stderr))
		}
		if !strings.Contains(stdout, "# HELP") && !strings.Contains(stdout, "# TYPE") {
			return fmt.Errorf("response contains no Prometheus exposition output: %q", stdout)
		}
		output = stdout
		return nil
	})
	return output, err
}

// TestPodIdentityReachesEPE proves that source pod name and namespace
// reach EPE through workload attributes (or legacy downstream_peer metadata).
// An empty selector on a namespaced profile matches only Pods in that namespace,
// so this fails open if either identity attribute is absent.
func TestPodIdentityReachesEPE(t *testing.T) {
	_, scope := beginEPEDataPathScenario(t,
		"EPE container log follows; look for 'Pod identity missing from filter_state', which means the "+
			"source workload attributes did not reach EPE")

	e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
		"Namespace": trafficFixture.Namespace.Name(),
	}, `
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: epe-identity
  namespace: {{ .Namespace }}
spec:
  selector: {}
  rules:
  - name: block-identity-path
    match:
    - domains:
      - "*"
      paths:
      - type: Exact
        value: /epe-identity
    actions:
      block:
        statusCode: 452
        body: epe-identity-block
`).ApplyOrFail(t, kube.CreateOnly)

	callEPEPathOrFail(t, trafficFixture.Client, trafficFixture.Server,
		"/epe-identity", statusIdentityBlock, "epe-identity-block")
}

// Secret credentials can be injected for ordinary Pods without a Sandbox token.
func TestWorkloadSecretTokenInjection(t *testing.T) {
	_, scope := beginEPEDataPathScenario(t, "EPE Secret token injection failed")
	e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
		"Namespace":     trafficFixture.Namespace.Name(),
		"EPENamespace":  resolvedAgentioConfig.Namespace,
		"TokenTemplate": "Bearer {{ .Token }}",
	}, `
apiVersion: v1
kind: Secret
metadata:
  name: workload-api-key
  namespace: {{ .EPENamespace }}
stringData:
  apiKey: workload-e2e-test-token
---
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: workload-token-injection
  namespace: {{ .Namespace }}
spec:
  selector:
    matchLabels:
      app: client
  rules:
  - name: inject-api-key
    match:
    - domains: ["*"]
      paths:
      - type: Exact
        value: /workload-token
    actions:
      tokenTransformation:
        type: ApiKey
        credentialRef:
          secret:
            name: workload-api-key
            namespace: {{ .EPENamespace }}
        apiKey:
          targetHeader: Authorization
          valueTemplate: "{{ .TokenTemplate }}"
`).ApplyOrFail(t, kube.CreateOnly)
	options := trafficFixture.Server.CallOptionsOrFail(t, "http")
	options.Count = 1
	options.Path = "/workload-token"
	options.Check = check.And(check.OK(), check.RequestHeader("Authorization", "Bearer workload-e2e-test-token"))
	options.Retry = harness.FixedRetry(3*time.Minute, 5*time.Second)
	trafficFixture.Client.CallOrFail(t, options)
}

// TestWorkloadLabelsReachEPE proves the agentio.workload.labels attribute contract. The
// Positive calls through both matching callers are the propagation barriers
// for the subsequent one-shot negative assertion: the shared caller proves the
// first document is active, then the dedicated caller proves the later document
// is active without changing the pinned document order.
func TestWorkloadLabelsReachEPE(t *testing.T) {
	environment, scope := beginEPEDataPathScenario(t,
		"The caller's pod labels did not reach EPE, or did not decode. Either agentio.workload.labels is missing "+
			"from the ext_proc request_attributes or the sandbox data plane did not populate it for this workload type. EPE log")
	selectorProbe := applyEPESelectorProbe(t, environment)

	e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
		"Namespace": trafficFixture.Namespace.Name(),
	}, `
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: epe-selector-match
  namespace: {{ .Namespace }}
spec:
  selector:
    matchLabels:
      app: client
  rules:
  - name: block-matching-selector
    match:
    - domains:
      - "*"
      paths:
      - type: Exact
        value: /epe-selector-match
    actions:
      block:
        statusCode: 453
        body: epe-selector-match-block
---
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: epe-selector-miss
  namespace: {{ .Namespace }}
spec:
  selector:
    matchLabels:
      app: not-the-calling-workload
  rules:
  - name: block-non-matching-selector
    match:
    - domains:
      - "*"
      paths:
      - type: Exact
        value: /epe-selector-miss
    actions:
      block:
        statusCode: 454
        body: epe-selector-miss-block
`).ApplyOrFail(t, kube.CreateOnly)

	if !t.Run("matching selector blocks", func(t *testing.T) {
		callEPEPathOrFail(t, trafficFixture.Client, trafficFixture.Server,
			"/epe-selector-match", statusSelectorMatch, "epe-selector-match-block")
		// This second positive call proves the later document reached EPE before
		// the shared client's one-shot negative selector assertion.
		callEPEPathOrFail(t, selectorProbe, trafficFixture.Server,
			"/epe-selector-miss", statusSelectorMiss, "epe-selector-miss-block")
	}) {
		return
	}

	t.Run("non-matching selector does not block", func(t *testing.T) {
		options := trafficFixture.Server.CallOptionsOrFail(t, "http")
		options.Count = 1
		options.Path = "/epe-selector-miss"
		options.Check = check.OK()
		result, err := callEchoOnce(trafficFixture.Client, options)
		if err != nil {
			t.Fatalf("a SecurityProfile whose selector does not match the caller still affected the request, "+
				"so selector evaluation is not using the caller's real labels: %v; attempts: %+v", err, result.Attempts)
		}
	})
}

// TestGlobalSecurityProfileEnforcedAndRevoked covers the cluster-scoped profile
// path and proves that a real API-server delete reaches the EPE watch.
func TestGlobalSecurityProfileEnforcedAndRevoked(t *testing.T) {
	_, scope := beginEPEDataPathScenario(t, "EPE container log follows")

	plan := e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{}, `
apiVersion: agents.kruise.io/v1alpha1
kind: GlobalSecurityProfile
metadata:
  name: epe-global
spec:
  selector: {}
  rules:
  - name: block-global-path
    match:
    - domains:
      - "*"
      paths:
      - type: Exact
        value: /epe-global
    actions:
      block:
        statusCode: 455
        body: epe-global-block
`)
	plan.ApplyOrFail(t, kube.CreateOnly)

	if !t.Run("global profile blocks", func(t *testing.T) {
		callEPEPathOrFail(t, trafficFixture.Client, trafficFixture.Server,
			"/epe-global", statusGlobalBlock, "epe-global-block")
	}) {
		return
	}

	t.Run("deleting the global profile restores traffic", func(t *testing.T) {
		plan.DeleteOrFail(t)
		options := trafficFixture.Server.CallOptionsOrFail(t, "http")
		options.Count = 1
		options.Path = "/epe-global"
		options.Check = check.OK()
		options.Retry = harness.FixedRetry(3*time.Minute, 5*time.Second)
		trafficFixture.Client.CallOrFail(t, options)
	})
}

// TestProfilePriorityOrdering pins spec.priority as the first sort key across
// the GlobalSecurityProfile/SecurityProfile scope boundary.
func TestProfilePriorityOrdering(t *testing.T) {
	rig.RequireLive(t)
	rig.RequireUncontaminated(t)

	cases := []struct {
		name           string
		path           string
		globalPriority int
		nsPriority     int
		wantStatus     int
		wantBody       string
	}{
		{
			name:           "lower priority on the global profile wins",
			path:           "/epe-priority-global",
			globalPriority: 100,
			nsPriority:     200,
			wantStatus:     statusPriorityGlobal,
			wantBody:       "epe-priority-global",
		},
		{
			name:           "lower priority on the namespaced profile wins",
			path:           "/epe-priority-namespaced",
			globalPriority: 200,
			nsPriority:     100,
			wantStatus:     statusPriorityNamespace,
			wantBody:       "epe-priority-namespaced",
		},
	}

	for _, current := range cases {
		current := current
		t.Run(current.name, func(t *testing.T) {
			_, scope := beginEPEDataPathScenario(t, "EPE container log follows")
			e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
				"Namespace":       trafficFixture.Namespace.Name(),
				"Path":            current.path,
				"GlobalPriority":  current.globalPriority,
				"NsPriority":      current.nsPriority,
				"GlobalStatus":    statusPriorityGlobal,
				"NamespaceStatus": statusPriorityNamespace,
			}, `
apiVersion: agents.kruise.io/v1alpha1
kind: GlobalSecurityProfile
metadata:
  name: epe-priority-global
spec:
  selector: {}
  priority: {{ .GlobalPriority }}
  rules:
  - name: block-from-global
    match:
    - domains:
      - "*"
      paths:
      - type: Exact
        value: {{ .Path }}
    actions:
      block:
        statusCode: {{ .GlobalStatus }}
        body: epe-priority-global
---
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: epe-priority-namespaced
  namespace: {{ .Namespace }}
spec:
  selector: {}
  priority: {{ .NsPriority }}
  rules:
  - name: block-from-namespaced
    match:
    - domains:
      - "*"
      paths:
      - type: Exact
        value: {{ .Path }}
    actions:
      block:
        statusCode: {{ .NamespaceStatus }}
        body: epe-priority-namespaced
`).ApplyOrFail(t, kube.CreateOnly)

			callEPEPathOrFail(t, trafficFixture.Client, trafficFixture.Server,
				current.path, current.wantStatus, current.wantBody)
		})
	}
}

func beginEPEDataPathScenario(t *testing.T, failureDiagnostic string) (*e2e.Environment, *kube.ResourceScope) {
	t.Helper()
	environment, scope := rig.BeginScenario(t)
	attachEPELogsOnFailure(t, environment, failureDiagnostic)
	applyEPEProviderConfig(t, scope, epeName)
	return environment, scope
}

func epeSelectorProbeConfig(namespaceName string) echo.Config {
	return echo.Config{
		Name:         epeSelectorProbeName,
		Namespace:    namespaceName,
		Replicas:     1,
		Image:        echo.DefaultImage,
		Ports:        echo.DefaultPorts(),
		CallTimeout:  90 * time.Second,
		Converge:     3,
		Labels:       map[string]string{"app": epeSelectorProbeName},
		Capabilities: harness.ClientCapabilities(),
	}
}

func applyEPESelectorProbe(t *testing.T, environment *e2e.Environment) echo.Instance {
	t.Helper()
	ctx, cancel := e2e.Context(t, 2*time.Minute)
	defer cancel()
	config := epeSelectorProbeConfig(trafficFixture.Namespace.Name())
	instance, cleanup, err := echo.Apply(ctx, environment, config)
	if err != nil {
		t.Fatalf("deploy EPE selector propagation probe: %v", err)
	}

	// Registered after the scenario cleanup, so LIFO cleanup removes this
	// caller first. Failure skips deletion and retains it with the provider and
	// profiles that produced the assertion failure.
	t.Cleanup(func() {
		if t.Failed() || environment.Retaining() {
			return
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cleanupCancel()
		if err := cleanup(cleanupCtx); err != nil {
			rig.Contaminate()
			t.Errorf("clean EPE selector propagation probe: %v", err)
		}
	})
	return instance
}

// applyEPEProviderConfig configures this scenario to route EPE traffic through
// the gateway. Cleanup restores the shared PASSTHROUGH baseline.
func applyEPEProviderConfig(t *testing.T, scope *kube.ResourceScope, service string) {
	t.Helper()
	rig.ApplyConfig(t, scope, map[string]any{
		"Namespace": resolvedAgentioConfig.Namespace,
		"Service":   service,
	}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    sandboxExtProc:
      service: {{ .Service }}.{{ .Namespace }}.svc.cluster.local
      port: 9002
      messageTimeout: 5s
      request:
        headerMode: SEND
        attributes:
        - filter_state['sandbox.id']
        - filter_state['sandbox.token']
        - filter_state['agentio.sandbox.metadata']
        - filter_state['agentio.workload.labels']
        - filter_state['sandbox.labels']
        - filter_state['agentio.workload.name']
        - filter_state['agentio.workload.namespace']
        - filter_state['downstream_peer'].name
        - filter_state['downstream_peer'].namespace
        - destination.port
        - source.address
      response:
        headerMode: SKIP
    egressPolicies:
    - gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
`)
}

func callEPEPathOrFail(
	t *testing.T,
	source, destination echo.Instance,
	path string,
	status int,
	body string,
) {
	t.Helper()
	options := destination.CallOptionsOrFail(t, "http")
	options.Count = 1
	options.Path = path
	options.Check = check.And(check.NoError(), check.Status(status), strictEPEBodyContains(body))
	options.Retry = harness.FixedRetry(3*time.Minute, 5*time.Second)
	source.CallOrFail(t, options)
}

// strictEPEBodyContains accepts only an exact raw echo frame explicitly marked
// as body. URL and other response metadata are excluded because EPE test paths
// can equal expected bodies, including URL metadata encoded by an echo backend
// inside its own response body.
func strictEPEBodyContains(want string) echo.Checker {
	return check.Each(func(response echo.Response) error {
		for _, line := range strings.Split(response.RawContent, "\n") {
			body, found := strings.CutPrefix(line, "body] ")
			if found && body == want {
				return nil
			}
		}
		return fmt.Errorf("EPE response body does not contain %q", want)
	})
}

// callEchoOnce cancels the retry context from inside the first checker call.
// This makes a failing negative assertion conclusive instead of allowing a
// later request to hide a selector that began enforcing after the barrier.
func callEchoOnce(source echo.Instance, options echo.CallOptions) (echo.Result, error) {
	checker := options.Check
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	options.Retry = retry.Policy{NoTimeout: true, Delay: time.Second, Backoff: 1, MaxDelay: time.Second, Converge: 1}
	options.Check = func(result echo.Result, callErr error) error {
		cancel()
		if checker != nil {
			return checker(result, callErr)
		}
		return callErr
	}
	result, err := source.Call(ctx, options)
	if len(result.Attempts) != 1 {
		return result, fmt.Errorf("one-shot echo call made %d attempts, want 1; call error: %v", len(result.Attempts), err)
	}
	return result, err
}

func attachEPELogsOnFailure(t *testing.T, environment *e2e.Environment, diagnostic string) {
	t.Helper()
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		t.Logf("%s:\n%s", diagnostic, epeLogs(ctx, environment))
	})
}

// epeLogs never fails the assertion that triggered it. It also searches all
// EPE Pods, not just Ready Pods, so CrashLoop diagnostics remain available.
func epeLogs(ctx context.Context, environment *e2e.Environment) string {
	if environment == nil || environment.Cluster == nil || environment.Cluster.Kube == nil || environment.Kube == nil {
		return "<could not read EPE logs: Kubernetes environment is unavailable>"
	}
	pods, err := environment.Cluster.Kube.CoreV1().Pods(resolvedAgentioConfig.Namespace).
		List(ctx, metav1.ListOptions{LabelSelector: harness.EPEPodSelector})
	if err != nil {
		return fmt.Sprintf("<could not locate EPE pod: %v>", err)
	}
	if len(pods.Items) == 0 {
		return fmt.Sprintf("<no EPE pods found in %s>", resolvedAgentioConfig.Namespace)
	}
	sort.Slice(pods.Items, func(left, right int) bool { return pods.Items[left].Name < pods.Items[right].Name })
	logs, err := environment.Kube.Logs(ctx, resolvedAgentioConfig.Namespace, pods.Items[0].Name, epeContainerName, nil)
	if err != nil {
		return fmt.Sprintf("<could not read EPE logs: %v>", err)
	}
	return logs
}
