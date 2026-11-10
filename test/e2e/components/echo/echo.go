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

package echo

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/openkruise/agentio/test/e2e"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/retry"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const DefaultImage = "gcr.io/istio-testing/app@sha256:0005e05c6fed4cd804b5de65fcae8dc9e707d36e360ec58fe8b9361bf3920bf1"

type Config struct {
	Name             string
	Namespace        string
	Image            string
	Replicas         int
	Labels           map[string]string
	PodAnnotations   map[string]string
	Ports            []Port
	Capabilities     []corev1.Capability
	CallTimeout      time.Duration
	ReadinessTimeout time.Duration
	Converge         int
}

type Protocol string

const (
	HTTP  Protocol = "http"
	HTTPS Protocol = "https"
	HTTP2 Protocol = "http2"
	GRPC  Protocol = "grpc"
	TCP   Protocol = "tcp"
	UDP   Protocol = "udp"
)

type Port struct {
	Name         string
	Protocol     Protocol
	ServicePort  int
	WorkloadPort int
	TLS          bool
	ServerFirst  bool
}

var defaultPorts = []Port{
	{Name: "http", Protocol: HTTP, ServicePort: 80, WorkloadPort: 18080},
	{Name: "https", Protocol: HTTPS, ServicePort: 443, WorkloadPort: 18443, TLS: true},
	{Name: "http2", Protocol: HTTP2, ServicePort: 85, WorkloadPort: 18085},
	{Name: "grpc", Protocol: GRPC, ServicePort: 7070, WorkloadPort: 17070},
	{Name: "tcp", Protocol: TCP, ServicePort: 9090, WorkloadPort: 19090},
	{Name: "udp", Protocol: UDP, ServicePort: 9200, WorkloadPort: 19200},
	{Name: "tcp-server", Protocol: TCP, ServicePort: 9091, WorkloadPort: 16060},
	{Name: "auto-http", Protocol: HTTP, ServicePort: 81, WorkloadPort: 18081},
	{Name: "auto-https", Protocol: HTTPS, ServicePort: 9443, WorkloadPort: 19443, TLS: true},
	{Name: "http-instance", Protocol: HTTP, ServicePort: 82, WorkloadPort: 18082},
}

func DefaultPorts() []Port {
	return append([]Port(nil), defaultPorts...)
}

type CallOptions struct {
	Protocol        Protocol
	Address         string
	Port            int
	Path            string
	Count           int
	QPS             int
	Timeout         time.Duration
	Headers         map[string]string
	FollowRedirects bool
	ServerName      string
	ServerFirst     bool
	Retry           retry.Policy
	Check           Checker
}

func CallOptionsForAddress(protocol Protocol, address string, port int) CallOptions {
	return CallOptions{Protocol: protocol, Address: address, Port: port}
}

func (o CallOptions) WithCheck(checker Checker) CallOptions {
	o.Check = checker
	return o
}

// Checker evaluates one call attempt. Returning an error makes Call retry the
// attempt according to CallOptions.Retry.
type Checker func(Result, error) error

type Attempt struct {
	Stdout string
	Stderr string
	Error  string
}

type Result struct {
	Responses []Response
	Attempts  []Attempt
	Error     string
}

type Workload struct {
	Name    string
	Address string
}

type execFunc func(context.Context, string, string, string, []string) (string, string, error)
type workloadsFunc func(context.Context) ([]Workload, error)
type serviceIPFunc func(context.Context) (string, error)

type Instance struct {
	config    Config
	pods      []string
	exec      execFunc
	workloads workloadsFunc
	serviceIP serviceIPFunc
}

func (i Instance) Name() string      { return i.config.Name }
func (i Instance) Namespace() string { return i.config.Namespace }
func (i Instance) Address() string {
	return fmt.Sprintf("%s.%s.svc.cluster.local", i.config.Name, i.config.Namespace)
}
func (i Instance) Pods() []string { return append([]string(nil), i.pods...) }
func (i Instance) Port(name string) (Port, bool) {
	for _, port := range i.config.Ports {
		if port.Name == name {
			return port, true
		}
	}
	return Port{}, false
}

func (i Instance) CallOptions(portName string) (CallOptions, error) {
	port, found := i.Port(portName)
	if !found {
		return CallOptions{}, fmt.Errorf("echo %s has no port %q", i.Name(), portName)
	}
	options := CallOptionsForAddress(port.Protocol, i.Address(), port.ServicePort)
	options.ServerFirst = port.ServerFirst
	return options, nil
}

func (i Instance) CallOptionsOrFail(t testing.TB, portName string) CallOptions {
	t.Helper()
	options, err := i.CallOptions(portName)
	if err != nil {
		t.Fatal(err)
	}
	return options
}

func (i Instance) Workloads(ctx context.Context) ([]Workload, error) {
	if i.workloads == nil {
		return nil, errors.New("echo instance cannot list current workloads")
	}
	workloads, err := i.workloads(ctx)
	if err != nil {
		return nil, err
	}
	sort.Slice(workloads, func(left, right int) bool { return workloads[left].Name < workloads[right].Name })
	return workloads, nil
}

func (i Instance) WorkloadsOrFail(t testing.TB) []Workload {
	t.Helper()
	ctx, cancel := e2e.Context(t, time.Minute)
	defer cancel()
	workloads, err := i.Workloads(ctx)
	if err != nil {
		t.Fatalf("list %s workloads: %v", i.Name(), err)
	}
	if len(workloads) == 0 {
		t.Fatalf("echo %s has no ready workloads", i.Name())
	}
	return workloads
}

func (i Instance) ServiceIP(ctx context.Context) (string, error) {
	if i.serviceIP == nil {
		return "", errors.New("echo instance cannot read its Service IP")
	}
	address, err := i.serviceIP(ctx)
	if err != nil {
		return "", err
	}
	if address == "" || address == "None" {
		return "", fmt.Errorf("Service %s/%s has no routable ClusterIP", i.Namespace(), i.Name())
	}
	return address, nil
}

func (i Instance) ServiceIPOrFail(t testing.TB) string {
	t.Helper()
	ctx, cancel := e2e.Context(t, time.Minute)
	defer cancel()
	address, err := i.ServiceIP(ctx)
	if err != nil {
		t.Fatalf("read Service %s/%s IP: %v", i.Namespace(), i.Name(), err)
	}
	return address
}

func (i Instance) Exec(ctx context.Context, args []string) (string, string, error) {
	if i.exec == nil {
		return "", "", errors.New("echo instance cannot execute commands")
	}
	workloads, err := i.Workloads(ctx)
	if err != nil {
		return "", "", err
	}
	if len(workloads) == 0 {
		return "", "", errors.New("echo instance has no ready workload")
	}
	return i.exec(ctx, i.config.Namespace, workloads[0].Name, "app", append([]string(nil), args...))
}

func Deploy(t testing.TB, environment *e2e.Environment, config Config) Instance {
	t.Helper()
	config = normalizedConfig(config)
	timeout := config.ReadinessTimeout
	ctx, cancel := testContext(t, timeout)
	defer cancel()
	instance, cleanup, err := apply(ctx, environment, environmentClient(environment, t.Name()), config)
	if err != nil {
		t.Fatalf("deploy echo %s/%s: %v", config.Namespace, config.Name, err)
	}
	t.Cleanup(func() {
		if environment.DefersResourceCleanup() || environment.Retaining() {
			return
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cleanupCancel()
		if err := cleanup(cleanupCtx); err != nil {
			t.Errorf("delete echo %s/%s: %v", config.Namespace, config.Name, err)
		}
	})
	return instance
}

func Apply(ctx context.Context, environment *e2e.Environment, config Config) (Instance, e2e.CleanupFunc, error) {
	return apply(ctx, environment, environmentClient(environment, ""), config)
}

func apply(ctx context.Context, environment *e2e.Environment, client *kube.Client, config Config) (Instance, e2e.CleanupFunc, error) {
	if environment == nil || client == nil || environment.Cluster == nil || environment.Cluster.Kube == nil {
		return Instance{}, nil, errors.New("echo deployment requires dynamic and typed Kubernetes clients")
	}
	objects, err := manifests(config)
	if err != nil {
		return Instance{}, nil, fmt.Errorf("build echo manifests: %w", err)
	}
	config = normalizedConfig(config)
	waitCtx, cancel := context.WithTimeout(ctx, config.ReadinessTimeout)
	defer cancel()
	records := make([]kube.ResourceRecord, 0, len(objects))
	for _, object := range objects {
		record, err := client.Apply(waitCtx, object, kube.CreateOnly)
		if err != nil {
			return Instance{}, nil, fmt.Errorf("deploy echo %s %s/%s: %w", object.GetKind(), object.GetNamespace(), object.GetName(), err)
		}
		records = append(records, record)
	}
	deployment := records[len(records)-1]
	if err := client.Wait(waitCtx, deployment.GVR, config.Namespace, config.Name, func(live *unstructured.Unstructured) (bool, error) {
		available, found, err := unstructured.NestedInt64(live.Object, "status", "availableReplicas")
		return found && available >= int64(config.Replicas), err
	}); err != nil {
		return Instance{}, nil, fmt.Errorf("wait for echo Deployment %s/%s: %w", config.Namespace, config.Name, err)
	}
	var pods []string
	err = retry.UntilSuccess(waitCtx, retry.Policy{Timeout: config.ReadinessTimeout, Delay: 100 * time.Millisecond, Backoff: 1.5, MaxDelay: time.Second}, func() error {
		list, err := environment.Cluster.Kube.CoreV1().Pods(config.Namespace).List(waitCtx, metav1.ListOptions{LabelSelector: "app=" + config.Name})
		if err != nil {
			return err
		}
		pods = pods[:0]
		for _, pod := range list.Items {
			if podReady(&pod) {
				pods = append(pods, pod.Name)
			}
		}
		if len(pods) < config.Replicas {
			return fmt.Errorf("%d/%d echo Pods ready", len(pods), config.Replicas)
		}
		sort.Strings(pods)
		return nil
	})
	if err != nil {
		return Instance{}, nil, fmt.Errorf("wait for echo Pods %s/%s: %w", config.Namespace, config.Name, err)
	}
	instance := Instance{
		config: config,
		pods:   append([]string(nil), pods...),
		exec: func(ctx context.Context, namespace, pod, container string, args []string) (string, string, error) {
			return environment.Kube.Exec(ctx, namespace, pod, container, args, nil)
		},
		workloads: func(ctx context.Context) ([]Workload, error) {
			list, err := environment.Cluster.Kube.CoreV1().Pods(config.Namespace).List(ctx, metav1.ListOptions{LabelSelector: "app=" + config.Name})
			if err != nil {
				return nil, err
			}
			workloads := make([]Workload, 0, len(list.Items))
			for index := range list.Items {
				pod := &list.Items[index]
				if !podReady(pod) || pod.Status.PodIP == "" {
					continue
				}
				workloads = append(workloads, Workload{Name: pod.Name, Address: pod.Status.PodIP})
			}
			return workloads, nil
		},
		serviceIP: func(ctx context.Context) (string, error) {
			service, err := environment.Cluster.Kube.CoreV1().Services(config.Namespace).Get(ctx, config.Name, metav1.GetOptions{})
			if err != nil {
				return "", err
			}
			return service.Spec.ClusterIP, nil
		},
	}
	cleanup := func(cleanupCtx context.Context) error {
		if environment.Retaining() {
			return nil
		}
		var errs []error
		for index := len(records) - 1; index >= 0; index-- {
			if err := client.DeleteOwned(cleanupCtx, records[index]); err != nil {
				errs = append(errs, fmt.Errorf("delete echo resource %s %s/%s: %w", records[index].GVR.Resource, records[index].Namespace, records[index].Name, err))
			}
		}
		return errors.Join(errs...)
	}
	return instance, cleanup, nil
}

func environmentClient(environment *e2e.Environment, testID string) *kube.Client {
	if environment == nil || environment.Kube == nil {
		return nil
	}
	if testID == "" {
		return environment.Kube
	}
	return environment.Kube.WithTestID(testID)
}

func (i Instance) Call(ctx context.Context, options CallOptions) (Result, error) {
	if len(i.pods) == 0 || i.exec == nil {
		return Result{}, errors.New("echo instance has no ready client Pod")
	}
	if options.Address == "" {
		return Result{}, errors.New("echo call address is required")
	}
	if options.Protocol == "" {
		options.Protocol = HTTP
	}
	if options.Count <= 0 {
		options.Count = 1
	}
	if options.Timeout <= 0 {
		options.Timeout = 5 * time.Second
	}
	if options.Retry.Timeout <= 0 {
		options.Retry.Timeout = i.config.CallTimeout
	}
	if options.Retry.Converge <= 0 {
		options.Retry.Converge = i.config.Converge
	}
	args, err := commandArgs(options)
	if err != nil {
		return Result{}, err
	}
	result := Result{}
	err = retry.UntilSuccess(ctx, options.Retry, func() error {
		attemptCtx, cancel := context.WithTimeout(ctx, options.Timeout+time.Second)
		stdout, stderr, execErr := i.exec(attemptCtx, i.config.Namespace, i.pods[0], "app", args)
		cancel()
		attempt := Attempt{Stdout: stdout, Stderr: stderr}
		var responses []Response
		var callErr error
		if execErr != nil {
			callErr = fmt.Errorf("%w: %s", execErr, stderr)
		} else {
			responses, callErr = ParseResponses(stdout)
			if callErr == nil && len(responses) != options.Count {
				callErr = fmt.Errorf("received %d responses, want %d", len(responses), options.Count)
			}
		}
		if callErr != nil {
			attempt.Error = callErr.Error()
			result.Error = callErr.Error()
		} else {
			result.Error = ""
		}
		result.Responses = responses
		result.Attempts = append(result.Attempts, attempt)

		checkedErr := callErr
		if options.Check != nil {
			checkedErr = options.Check(result, callErr)
		}
		if checkedErr != nil {
			result.Error = checkedErr.Error()
			if result.Attempts[len(result.Attempts)-1].Error == "" {
				result.Attempts[len(result.Attempts)-1].Error = checkedErr.Error()
			}
		}
		return checkedErr
	})
	if err != nil {
		return result, fmt.Errorf("echo call %s: %w", options.Address, err)
	}
	return result, nil
}

func (i Instance) CallOrFail(t testing.TB, options CallOptions) Result {
	t.Helper()
	timeout := options.Retry.Timeout
	if timeout <= 0 {
		timeout = normalizedConfig(i.config).CallTimeout
	}
	attemptTimeout := options.Timeout
	if attemptTimeout <= 0 {
		attemptTimeout = 5 * time.Second
	}
	ctx, cancel := e2e.Context(t, timeout+attemptTimeout+time.Second)
	defer cancel()
	result, err := i.Call(ctx, options)
	if err != nil {
		t.Fatalf("echo call from %s to %s: %v; attempts: %+v", i.Name(), options.Address, err, result.Attempts)
	}
	return result
}

func commandArgs(options CallOptions) ([]string, error) {
	port := options.Port
	scheme := string(options.Protocol)
	extra := []string{}
	switch options.Protocol {
	case HTTP:
		if port == 0 {
			port = 80
		}
	case HTTPS:
		if port == 0 {
			port = 443
		}
		extra = append(extra, "--insecure-skip-verify")
	case HTTP2:
		if port == 0 {
			port = 85
		}
		scheme = "http"
		extra = append(extra, "--http2")
	case GRPC:
		if port == 0 {
			port = 7070
		}
	case TCP:
		if port == 0 {
			port = 9090
		}
		if options.ServerFirst {
			extra = append(extra, "--server-first")
		}
	case UDP:
		if port == 0 {
			port = 9200
		}
	default:
		return nil, fmt.Errorf("unsupported echo protocol %q", options.Protocol)
	}
	if options.Path != "" && options.Path[0] != '/' {
		return nil, fmt.Errorf("echo call path %q must start with /", options.Path)
	}
	path := options.Path
	rawQuery := ""
	if queryAt := strings.IndexByte(path, '?'); queryAt >= 0 {
		rawQuery = path[queryAt+1:]
		path = path[:queryAt]
	}
	target := (&url.URL{
		Scheme:   scheme,
		Host:     net.JoinHostPort(options.Address, strconv.Itoa(port)),
		Path:     path,
		RawQuery: rawQuery,
	}).String()
	args := []string{
		"/usr/local/bin/client",
		target,
		"--count", fmt.Sprint(options.Count),
		"--timeout", options.Timeout.String(),
	}
	if options.QPS > 0 {
		args = append(args, "--qps", strconv.Itoa(options.QPS))
	}
	args = append(args, extra...)
	if options.FollowRedirects {
		args = append(args, "--follow-redirects")
	}
	if options.ServerName != "" {
		args = append(args, "--server-name", options.ServerName)
	}
	headers := make(map[string]string, len(options.Headers)+1)
	hasHost := false
	for key, value := range options.Headers {
		headers[key] = value
		hasHost = hasHost || strings.EqualFold(key, "Host")
	}
	if !hasHost && usesHTTPAuthority(options.Protocol) && options.Address != "" {
		if _, err := netip.ParseAddr(options.Address); err != nil {
			headers["Host"] = options.Address
		}
	}
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		args = append(args, "--header", key+":"+headers[key])
	}
	return args, nil
}

func usesHTTPAuthority(protocol Protocol) bool {
	switch protocol {
	case HTTP, HTTPS, HTTP2, GRPC:
		return true
	default:
		return false
	}
}

func normalizedConfig(config Config) Config {
	if config.Image == "" {
		config.Image = DefaultImage
	}
	if config.Replicas <= 0 {
		config.Replicas = 1
	}
	if config.CallTimeout <= 0 {
		config.CallTimeout = 30 * time.Second
	}
	if config.ReadinessTimeout <= 0 {
		config.ReadinessTimeout = 5 * time.Minute
	}
	if config.Converge <= 0 {
		config.Converge = 1
	}
	if len(config.Ports) == 0 {
		config.Ports = DefaultPorts()
	} else {
		config.Ports = append([]Port(nil), config.Ports...)
	}
	config.Capabilities = append([]corev1.Capability(nil), config.Capabilities...)
	return config
}

func podReady(pod *corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func testContext(t testing.TB, timeout time.Duration) (context.Context, context.CancelFunc) {
	deadline := time.Now().Add(timeout)
	if provider, ok := t.(interface{ Deadline() (time.Time, bool) }); ok {
		if testDeadline, found := provider.Deadline(); found && testDeadline.Before(deadline) {
			deadline = testDeadline
		}
	}
	return context.WithDeadline(context.Background(), deadline)
}
