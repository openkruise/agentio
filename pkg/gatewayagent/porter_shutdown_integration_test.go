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

package gatewayagent

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	extproc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	health "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/yaml"

	workload "github.com/openkruise/agentio/api/workload/v1"
)

const shutdownWorkloadType = "type.googleapis.com/istio.workload.Workload"

// The first named WDS response is gated by the test, so deletion happens while
// CONNECT is actually waiting for discovery, rather than after an arbitrary sleep.
type shutdownDiscovery struct {
	discovery.UnimplementedAggregatedDiscoveryServiceServer
	resources map[string][]*discovery.Resource
	requested chan struct{}
	release   chan struct{}
	first     sync.Once
	active    atomic.Int64
	served    atomic.Int64
}

func (s *shutdownDiscovery) DeltaAggregatedResources(
	stream discovery.AggregatedDiscoveryService_DeltaAggregatedResourcesServer,
) error {
	s.active.Add(1)
	defer s.active.Add(-1)
	for {
		r, err := stream.Recv()
		if err != nil {
			return err
		}
		if r.ErrorDetail != nil {
			return fmt.Errorf("NACK: %v", r.ErrorDetail)
		}
		if r.ResponseNonce != "" && len(r.ResourceNamesSubscribe) == 0 && len(r.ResourceNamesUnsubscribe) == 0 {
			continue
		}
		resources := s.resources[r.TypeUrl]
		if r.TypeUrl == shutdownWorkloadType {
			resources = nil
			for _, name := range r.ResourceNamesSubscribe {
				if name == "*" {
					continue
				}
				block := false
				s.first.Do(func() {
					block = true
					close(s.requested)
				})
				if block {
					select {
					case <-s.release:
					case <-stream.Context().Done():
						return stream.Context().Err()
					}
				}
				body, err := anypb.New(&workload.Workload{Uid: name, Name: "shutdown-client", Namespace: "test"})
				if err != nil {
					return err
				}
				resources = append(resources, &discovery.Resource{Name: name, Version: "1", Resource: body})
			}
		}
		if r.TypeUrl == shutdownWorkloadType {
			s.served.Add(int64(len(resources)))
		}
		if err := stream.Send(
			&discovery.DeltaDiscoveryResponse{
				TypeUrl:   r.TypeUrl,
				Nonce:     strconv.FormatInt(time.Now().UnixNano(), 10),
				Resources: resources,
			},
		); err != nil {
			return err
		}
	}
}

// Run inside the selected KinD node, sharing its network namespace and /tmp
// with a hostNetwork test Pod. This exercises a real kubelet without installing
// another control plane, changing CRDs, or modifying existing gateway Pods.
func TestPorterPodTermination(t *testing.T) {
	kubeconfig := os.Getenv("AGENTIO_TEST_KUBECONFIG")
	if kubeconfig == "" {
		t.Skip("run bin/test_porter_shutdown.sh against an existing KinD cluster")
	}
	required := func(name string) string {
		t.Helper()
		value := os.Getenv(name)
		if value == "" {
			t.Fatalf("%s required", name)
		}
		return value
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	must(err)
	kube, err := kubernetes.NewForConfig(config)
	must(err)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	dir, err := os.MkdirTemp("/tmp", "porter-shutdown-")
	must(err)
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	must(os.Chmod(dir, 0755))
	write := func(name string, data []byte) {
		t.Helper()
		must(os.WriteFile(filepath.Join(dir, name), data, 0644))
	}
	ca := newTestCA(t)
	// This fixture also authenticates the CONNECT client, so the root must allow
	// clientAuth as well as serverAuth (the older CA helper only needs serverAuth).
	ca.cert.ExtKeyUsage = nil
	der, err := x509.CreateCertificate(rand.Reader, ca.cert, ca.cert, &ca.key.PublicKey, ca.key)
	must(err)
	ca.cert, err = x509.ParseCertificate(der)
	must(err)
	ca.root = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	ca.lifetime = time.Hour
	caAddress := ca.serve(t)
	certificate := func(uid string) (tls.Certificate, []byte, []byte) {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		must(err)
		claim, err := json.Marshal(map[string]string{"registry": "test", "uid": uid})
		must(err)
		uri, err := url.Parse("spiffe://cluster.local/ns/test/sa/default")
		must(err)
		leaf := &x509.Certificate{
			SerialNumber:    big.NewInt(time.Now().UnixNano()),
			NotBefore:       time.Now().Add(-time.Minute),
			NotAfter:        time.Now().Add(time.Hour),
			IPAddresses:     []net.IP{net.ParseIP("127.0.0.1")},
			URIs:            []*url.URL{uri},
			KeyUsage:        x509.KeyUsageDigitalSignature,
			ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57874, 5, 1}, Value: claim}},
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca.cert, &key.PublicKey, ca.key)
		must(err)
		keyDER, err := x509.MarshalECPrivateKey(key)
		must(err)
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		must(err)
		return pair, certPEM, keyPEM
	}
	clientCert, _, _ := certificate("cold")
	_, warmCert, _ := certificate("after-drain")
	gatewayCert, serverCert, serverKey := certificate("gateway")
	write("root.pem", ca.root)
	write("server.pem", serverCert)
	write("server.key", serverKey)
	write("token", []byte("fixture"))

	finishHTTP := make(chan struct{})
	var finishOnce sync.Once
	finish := func() {
		finishOnce.Do(func() { close(finishHTTP) })
	}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.WriteString(w, "started\n"); err != nil {
			return
		}
		w.(http.Flusher).Flush()
		select {
		case <-finishHTTP:
		case <-r.Context().Done():
			return
		}
		if _, err := io.WriteString(w, "finished\n"); err != nil {
			t.Logf("backend client closed: %v", err)
		}
	}))
	defer backend.Close()
	defer backend.CloseClientConnections()
	defer finish()
	port, admin, status, porterPort, healthPort, metricsPort := freePort(
		t,
	), freePort(
		t,
	), freePort(
		t,
	), freePort(
		t,
	), freePort(
		t,
	), freePort(
		t,
	)
	fixture := &shutdownDiscovery{
		resources: map[string][]*discovery.Resource{},
		requested: make(chan struct{}),
		release:   make(chan struct{}),
	}
	filters := shutdownConnectFilters(t, required("AGENTIO_TEST_GATEWAY_FIXTURE"))
	filterJSON, err := json.Marshal(filters)
	must(err)
	add := func(name string, message proto.Message) {
		body, err := anypb.New(message)
		must(err)
		fixture.resources[body.TypeUrl] = append(
			fixture.resources[body.TypeUrl],
			&discovery.Resource{Name: name, Version: "1", Resource: body},
		)
	}
	for name, address := range map[string]string{"agentio-porter": fmt.Sprintf("127.0.0.1:%d", porterPort), "backend": backend.Listener.Addr().String()} {
		_, p, err := net.SplitHostPort(address)
		must(err)
		h2 := ""
		if name == "agentio-porter" {
			h2 = `,"http2_protocol_options":{}`
		}
		raw := fmt.Sprintf(
			`{
 "name": %q,
 "type": "STATIC",
 "connect_timeout": "1s"%s,
 "load_assignment": {
  "cluster_name": %q,
  "endpoints": [{"lb_endpoints": [{"endpoint": {
   "address": {"socket_address": {"address": "127.0.0.1", "port_value": %s}}
  }}]}]
 }
}`,
			name,
			h2,
			name,
			p,
		)
		cluster := &clusterv3.Cluster{}
		must(protojson.Unmarshal([]byte(raw), cluster))
		add(name, cluster)
	}
	raw := fmt.Sprintf(
		`{
  "name": "connect",
  "address": {
    "socket_address": {
      "address": "127.0.0.1",
      "port_value": %d
    }
  },
  "filter_chains": [
    {
      "transport_socket": {
        "name": "envoy.transport_sockets.tls",
        "typed_config": {
          "@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext",
          "require_client_certificate": true,
          "common_tls_context": {
            "tls_certificates": [
              {
                "certificate_chain": {
                  "filename": "/fixture/server.pem"
                },
                "private_key": {
                  "filename": "/fixture/server.key"
                }
              }
            ],
            "validation_context": {
              "trusted_ca": {
                "filename": "/fixture/root.pem"
              }
            }
          }
        }
      },
      "filters": [
        {
          "name": "envoy.filters.network.http_connection_manager",
          "typed_config": {
            "@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
            "stat_prefix": "shutdown",
            "upgrade_configs": [
              {
                "upgrade_type": "CONNECT"
              }
            ],
            "route_config": {
              "name": "connect",
              "virtual_hosts": [
                {
                  "name": "all",
                  "domains": [
                    "*"
                  ],
                  "routes": [
                    {
                      "match": {
                        "connect_matcher": {}
                      },
                      "route": {
                        "cluster": "backend",
                        "timeout": "0s",
                        "upgrade_configs": [
                          {
                            "upgrade_type": "CONNECT",
                            "connect_config": {}
                          }
                        ]
                      }
                    }
                  ]
                }
              ]
            },
            "http_filters": %s
          }
        }
      ]
    }
  ]
}`,
		port,
		filterJSON,
	)
	listener := &listenerv3.Listener{}
	must(protojson.Unmarshal([]byte(raw), listener))
	add("connect", listener)
	adsServer := grpc.NewServer()
	discovery.RegisterAggregatedDiscoveryServiceServer(adsServer, fixture)
	ads := httptest.NewUnstartedServer(adsServer)
	ads.EnableHTTP2 = true
	ads.TLS = &tls.Config{Certificates: []tls.Certificate{gatewayCert}, MinVersion: tls.VersionTLS12}
	ads.StartTLS()
	defer ads.Close()
	defer adsServer.Stop()
	write("xds.pem", ca.root)

	data, err := os.ReadFile(required("AGENTIO_TEST_GATEWAY_DEPLOYMENT"))
	must(err)
	var deployment appsv1.Deployment
	must(yaml.Unmarshal(data, &deployment))
	spec := deployment.Spec.Template.Spec.DeepCopy()
	if len(spec.Containers) != 1 || spec.Containers[0].Name != "agentio-proxy" || len(spec.InitContainers) != 1 ||
		spec.InitContainers[0].Name != "agentio-porter" ||
		spec.InitContainers[0].RestartPolicy == nil ||
		*spec.InitContainers[0].RestartPolicy != corev1.ContainerRestartPolicyAlways {
		t.Fatalf("rendered gateway must contain proxy and native Porter: %+v", spec)
	}
	if spec.TerminationGracePeriodSeconds == nil || *spec.TerminationGracePeriodSeconds != 30 {
		t.Fatal("expected default 30-second Pod budget")
	}
	namespace, err := kube.CoreV1().
		Namespaces().
		Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "porter-shutdown-", Labels: map[string]string{"agentio.kruise.io/dataplane-mode": "none"}}}, metav1.CreateOptions{})
	must(err)
	t.Cleanup(func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if err := kube.CoreV1().Namespaces().Delete(cleanupCtx, namespace.Name, metav1.DeleteOptions{}); err != nil {
			t.Error(err)
		}
	})
	spec.HostNetwork = true
	spec.DNSPolicy = corev1.DNSClusterFirstWithHostNet
	spec.NodeName = required("AGENTIO_TEST_NODE_NAME")
	spec.RestartPolicy = corev1.RestartPolicyNever
	spec.ServiceAccountName = "default"
	spec.AutomountServiceAccountToken = new(false)
	spec.SecurityContext = &corev1.PodSecurityContext{FSGroup: new(int64(1337))}
	spec.Volumes = []corev1.Volume{
		{Name: "fixture", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: dir}}},
		{Name: "config", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
		{Name: "sds", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
	}
	options, err := json.Marshal(
		map[string]any{
			"concurrency":                 1,
			"adminPort":                   admin,
			"statusPort":                  status,
			"envoyStatusPort":             freePort(t),
			"prometheusPort":              freePort(t),
			"drainDuration":               "1s",
			"terminationDrainDuration":    "40s",
			"minimumDrainDuration":        "1s",
			"exitOnZeroActiveConnections": true,
		},
	)
	must(err)
	proxy := &spec.Containers[0]
	proxy.Image = required("AGENTIO_TEST_GATEWAY_IMAGE")
	proxy.ImagePullPolicy = corev1.PullNever
	proxy.Env = []corev1.EnvVar{
		{Name: "POD_NAME", Value: "gateway"},
		{Name: "POD_NAMESPACE", Value: namespace.Name},
		{Name: "POD_UID", Value: "shutdown"},
		{Name: "SERVICE_ACCOUNT", Value: "default"},
		{Name: "INSTANCE_IP", Value: "127.0.0.1"},
		{Name: "AGENTIO_TOKEN_FILE", Value: "/fixture/token"},
		{Name: "AGENTIO_ROOT_CA", Value: "/fixture/root.pem"},
		{Name: "AGENTIO_XDS_ROOT_CA", Value: "/fixture/xds.pem"},
		{Name: "CA_ADDR", Value: caAddress},
		{Name: "AGENTIO_XDS_ADDRESS", Value: ads.Listener.Addr().String()},
		{Name: "AGENTIO_GATEWAY_CONFIG", Value: string(options)},
	}
	// Retain the production template's total-budget environment, not a test copy.
	for _, env := range deployment.Spec.Template.Spec.Containers[0].Env {
		if env.Name == "AGENTIO_TERMINATION_GRACE_PERIOD_SECONDS" {
			proxy.Env = append(proxy.Env, env)
		}
	}
	proxy.VolumeMounts = []corev1.VolumeMount{
		{Name: "fixture", MountPath: "/fixture", ReadOnly: true},
		{Name: "config", MountPath: "/etc/agentio/proxy"},
		{Name: "sds", MountPath: "/var/run/secrets/workload-spiffe-uds"},
	}
	proxy.Ports = nil
	for _, probe := range []*corev1.Probe{proxy.ReadinessProbe, proxy.StartupProbe, proxy.LivenessProbe} {
		if probe != nil && probe.HTTPGet != nil {
			probe.HTTPGet.Port = intstr.FromInt(status)
			probe.PeriodSeconds = 1
		}
	}
	porter := &spec.InitContainers[0]
	porter.Image = required("AGENTIO_TEST_PORTER_IMAGE")
	porter.ImagePullPolicy = corev1.PullNever
	porter.Args = []string{
		"--xds-address=" + ads.Listener.Addr().String(),
		"--xds-root-path=/fixture/xds.pem",
		"--xds-token-path=/fixture/token",
		fmt.Sprintf("--grpc-port=%d", porterPort),
		fmt.Sprintf("--grpc-health-port=%d", healthPort),
		fmt.Sprintf("--metrics-port=%d", metricsPort),
	}
	porter.VolumeMounts = []corev1.VolumeMount{{Name: "fixture", MountPath: "/fixture", ReadOnly: true}}
	porter.Ports = nil
	for _, probe := range []*corev1.Probe{porter.ReadinessProbe, porter.LivenessProbe} {
		probe.GRPC.Port = int32(healthPort)
		probe.PeriodSeconds = 1
	}
	pod, err := kube.CoreV1().
		Pods(namespace.Name).
		Create(ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "gateway", Finalizers: []string{"test.agentio.kruise.io/retain-status"}}, Spec: *spec}, metav1.CreateOptions{})
	must(err)
	t.Cleanup(func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), 40*time.Second)
		defer stop()
		for _, name := range []string{"agentio-proxy", "agentio-porter"} {
			logs, err := kube.CoreV1().
				Pods(namespace.Name).
				GetLogs(pod.Name, &corev1.PodLogOptions{Container: name}).
				DoRaw(cleanupCtx)
			if err != nil {
				t.Errorf("read %s logs: %v", name, err)
			} else {
				t.Logf("%s logs:\n%s", name, logs)
			}
		}
		// Kubelet may still update terminal status; patch only the test finalizer.
		current, err := kube.CoreV1().Pods(namespace.Name).Patch(
			cleanupCtx, pod.Name, types.MergePatchType, []byte(`{"metadata":{"finalizers":null}}`), metav1.PatchOptions{},
		)
		if err != nil {
			t.Error(err)
			return
		}
		zero := int64(0)
		if current.DeletionTimestamp == nil {
			if err := kube.CoreV1().
				Pods(namespace.Name).
				Delete(cleanupCtx, pod.Name, metav1.DeleteOptions{GracePeriodSeconds: &zero}); err != nil {
				t.Error(err)
			}
		}
	})
	wait := func(what string, check func() bool) {
		t.Helper()
		deadline := time.NewTimer(40 * time.Second)
		defer deadline.Stop()
		ticker := time.NewTicker(25 * time.Millisecond)
		defer ticker.Stop()
		for {
			if check() {
				return
			}
			select {
			case <-ctx.Done():
				t.Fatalf("%s: %v", what, ctx.Err())
			case <-deadline.C:
				t.Fatalf("timed out: %s", what)
			case <-ticker.C:
			}
		}
	}
	httpClient := &http.Client{Timeout: time.Second}
	ready := func(code int) bool {
		r, err := httpClient.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz/ready", status))
		if err != nil {
			return false
		}
		defer closeResource(r.Body)
		return r.StatusCode == code
	}
	healthConn, err := grpc.NewClient(
		fmt.Sprintf("127.0.0.1:%d", healthPort),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	must(err)
	defer closeResource(healthConn)
	porterReady := func() bool {
		c, stop := context.WithTimeout(ctx, time.Second)
		defer stop()
		r, err := health.NewHealthClient(healthConn).Check(c, &health.HealthCheckRequest{Service: "readiness"})
		return err == nil && r.Status == health.HealthCheckResponse_SERVING
	}
	wait("gateway and Porter ready", func() bool { return ready(200) && porterReady() })
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.root)
	connection, err := tls.Dial(
		"tcp",
		fmt.Sprintf("127.0.0.1:%d", port),
		&tls.Config{RootCAs: roots, Certificates: []tls.Certificate{clientCert}, MinVersion: tls.VersionTLS12},
	)
	must(err)
	defer closeResource(connection)
	must(connection.SetDeadline(time.Now().Add(15 * time.Second)))
	_, err = fmt.Fprintf(
		connection,
		"CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n",
		backend.Listener.Addr(),
		backend.Listener.Addr(),
	)
	must(err)
	select {
	case <-fixture.requested:
	case <-time.After(3 * time.Second):
		t.Fatal("CONNECT did not enter cold WDS demand")
	}
	must(kube.CoreV1().Pods(namespace.Name).Delete(ctx, pod.Name, metav1.DeleteOptions{}))
	wait("gateway draining", func() bool { return ready(503) })
	if !porterReady() || fixture.active.Load() < 2 {
		t.Fatalf("Porter/ADS stopped during gateway drain: active ADS=%d", fixture.active.Load())
	}
	close(fixture.release)
	reader := bufio.NewReader(connection)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	must(err)
	if response.StatusCode != 200 {
		t.Fatalf("cold CONNECT interrupted by Pod deletion: %s", response.Status)
	}
	_, err = io.WriteString(connection, "GET / HTTP/1.1\r\nHost: backend\r\nConnection: close\r\n\r\n")
	must(err)
	response, err = http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	must(err)
	defer closeResource(response.Body)
	prefix := make([]byte, len("started\n"))
	_, err = io.ReadFull(response.Body, prefix)
	must(err)
	if string(prefix) != "started\n" {
		t.Fatalf("unexpected HTTP response: %q", prefix)
	}
	// A second, uncached identity proves Porter can still issue fresh ADS demand
	// while the gateway is draining the first CONNECT's business response.
	probeConn, err := grpc.NewClient(
		fmt.Sprintf("127.0.0.1:%d", porterPort),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	must(err)
	defer closeResource(probeConn)
	probeCtx, stopProbe := context.WithTimeout(ctx, 4*time.Second)
	defer stopProbe()
	stream, err := extproc.NewExternalProcessorClient(probeConn).Process(probeCtx)
	must(err)
	attributes, err := structpb.NewStruct(
		map[string]any{"filter_state['agentio.peer.certificate']": url.PathEscape(string(warmCert))},
	)
	must(err)
	must(
		stream.Send(
			&extproc.ProcessingRequest{
				Request: &extproc.ProcessingRequest_RequestHeaders{
					RequestHeaders: &extproc.HttpHeaders{
						Headers: &core.HeaderMap{
							Headers: []*core.HeaderValue{
								{Key: ":method", RawValue: []byte("CONNECT")},
								{Key: ":authority", RawValue: []byte("backend:80")},
							},
						},
					},
				},
				Attributes: map[string]*structpb.Struct{"envoy.filters.http.ext_proc": attributes},
			},
		),
	)
	decision, err := stream.Recv()
	must(err)
	if decision.GetRequestHeaders() == nil || fixture.served.Load() != 2 {
		t.Fatalf("fresh demand during drain failed: %v, served=%d", decision, fixture.served.Load())
	}
	finish()
	rest, err := io.ReadAll(response.Body)
	must(err)
	if string(rest) != "finished\n" {
		t.Fatalf("HTTP response interrupted: %q", rest)
	}
	must(connection.Close())
	var final *corev1.Pod
	wait("gateway then Porter termination", func() bool {
		current, err := kube.CoreV1().Pods(namespace.Name).Get(ctx, pod.Name, metav1.GetOptions{})
		must(err)
		final = current
		return len(current.Status.ContainerStatuses) == 1 &&
			current.Status.ContainerStatuses[0].State.Terminated != nil &&
			len(current.Status.InitContainerStatuses) == 1 &&
			current.Status.InitContainerStatuses[0].State.Terminated != nil
	})
	gatewayExit := final.Status.ContainerStatuses[0].State.Terminated
	porterExit := final.Status.InitContainerStatuses[0].State.Terminated
	if gatewayExit.ExitCode != 0 || porterExit.ExitCode != 0 || porterExit.FinishedAt.Before(&gatewayExit.FinishedAt) {
		t.Fatalf("incorrect termination: gateway=%+v porter=%+v", gatewayExit, porterExit)
	}
	for _, status := range append(final.Status.ContainerStatuses, final.Status.InitContainerStatuses...) {
		if status.RestartCount != 0 {
			t.Fatalf("unexpected restart: %+v", status)
		}
	}
	t.Logf(
		"PASS: deletion during cold CONNECT; Porter and ADS serve during drain; complete HTTP response; gateway exited %s, Porter exited %s, both exit 0",
		gatewayExit.FinishedAt,
		porterExit.FinishedAt,
	)
}

func TestShutdownConnectFilters(t *testing.T) {
	filters := shutdownConnectFilters(t, "../networking/testdata/agentio-egress-gateway.json")
	if len(filters) != 4 {
		t.Fatalf("got %d filters, want three production identity filters and a router", len(filters))
	}
}

func shutdownConnectFilters(t *testing.T, path string) []json.RawMessage {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture any
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	// Extract only the three production CONNECT filters. The rest of the golden
	// includes unrelated dynamic-module types that this fixture does not serve.
	var find func(any) []json.RawMessage
	find = func(value any) []json.RawMessage {
		switch value := value.(type) {
		case map[string]any:
			if filters, ok := value["httpFilters"].([]any); ok {
				var selected []json.RawMessage
				for _, raw := range filters {
					filter := raw.(map[string]any)
					switch filter["name"] {
					case "agentio.connect_authority", "envoy.filters.http.ext_proc", "agentio.connect_workload":
						encoded, err := json.Marshal(filter)
						if err != nil {
							t.Fatal(err)
						}
						selected = append(selected, encoded)
					}
				}
				if len(selected) == 3 {
					return selected
				}
			}
			for _, child := range value {
				if found := find(child); found != nil {
					return found
				}
			}
		case []any:
			for _, child := range value {
				if found := find(child); found != nil {
					return found
				}
			}
		}
		return nil
	}
	selected := find(fixture)
	if selected == nil {
		t.Fatal("production CONNECT identity/Porter filters missing")
	}
	return append(selected, json.RawMessage(`{
  "name": "envoy.filters.http.router",
  "typed_config": {"@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"}
 }`))
}
