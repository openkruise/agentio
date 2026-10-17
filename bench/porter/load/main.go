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

// Synthetic inventory and real ADS/ext_proc clients for the Porter scale harness.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"math/big"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	extproc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/stats"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"

	ext "github.com/openkruise/agentio/api/extensions/v1"
	sandbox "github.com/openkruise/agentio/api/sandbox/v1"
	workload "github.com/openkruise/agentio/api/workload/v1"
	loadgen "github.com/openkruise/agentio/bench/load"
	"github.com/openkruise/agentio/pkg/features"
	cpmetrics "github.com/openkruise/agentio/pkg/metrics"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/xds"
	store "github.com/openkruise/agentio/pkg/xds/store"
	"github.com/openkruise/agentio/pkg/xdsclient"
)

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func emit(v any) {
	must(json.NewEncoder(os.Stdout).Encode(v))
}

func writeResponse(w http.ResponseWriter, value any) {
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("write benchmark response: %v", err)
	}
}

func uid(i int) string {
	return fmt.Sprintf("Kubernetes//Pod/perf/workload-%05d", i)
}

func policy(i int) string {
	return fmt.Sprintf("namespaces/perf/trafficPolicies/policy-%05d", i)
}

func anyOf(v proto.Message) *anypb.Any {
	a, e := anypb.New(v)
	must(e)
	return a
}

type auth struct{}

func (auth) Authenticate(context.Context) (model.PeerIdentity, error) {
	return model.PeerIdentity{AttestedBy: model.AttestationKubernetes}, nil
}

func sniPolicy(action ext.SniAction) *anypb.Any {
	p := &ext.SniTrafficPolicy{}
	for j := range 6 {
		p.Rules = append(p.Rules, &ext.SniRule{
			Match:  &ext.SniMatch{Sni: []string{fmt.Sprintf("unused-%d.invalid", j)}},
			Action: ext.SniAction_SNI_ACTION_DENY,
		})
	}
	p.Rules = append(
		p.Rules,
		&ext.SniRule{Match: &ext.SniMatch{Sni: []string{"blocked.example.com"}}, Action: ext.SniAction_SNI_ACTION_DENY},
		&ext.SniRule{Match: &ext.SniMatch{Sni: []string{"*.example.com"}}, Action: action},
	)
	return anyOf(p)
}

func source(i int) model.SourceRef {
	return model.SourceRef{Registry: "kubernetes/Kubernetes", Key: fmt.Sprintf("00000000-0000-4000-8000-%012d", i)}
}

func ip(i int) string {
	return fmt.Sprintf("10.%d.%d.%d", (i>>16)&255, (i>>8)&255, i&255)
}

func labels(i, revision int) map[string]string {
	m := map[string]string{
		"app.kubernetes.io/name":     fmt.Sprintf("app-%03d", i%100),
		"app.kubernetes.io/instance": fmt.Sprintf("deployment-%05d", i/10),
		"pod-template-hash":          "7b6c8d9f5",
		"revision":                   strconv.Itoa(revision),
	}
	for j := range 16 {
		m[fmt.Sprintf("example.com/label-%02d", j)] = fmt.Sprintf("value-%02d-%06d", j, i)
	}
	return m
}

// Preserve the initial test binary's wire schema even if the working branch evolves.
func instanceExtension(src model.SourceRef) *anypb.Any {
	b := protowire.AppendString(protowire.AppendTag(nil, 1, protowire.BytesType), src.Registry)
	b = protowire.AppendString(protowire.AppendTag(b, 2, protowire.BytesType), src.Key)
	return &anypb.Any{TypeUrl: "type.googleapis.com/kruise.networking.extensions.v1.WorkloadInstance", Value: b}
}

var instanceWireName bool

func workloadResource(i, revision int) model.Resource {
	src := source(i)
	w := &workload.Workload{
		Uid:            uid(i),
		Name:           fmt.Sprintf("workload-%05d", i),
		Namespace:      "perf",
		Network:        "",
		ClusterId:      "Kubernetes",
		Node:           fmt.Sprintf("node-%03d", i/500),
		TrustDomain:    "cluster.local",
		ServiceAccount: "default",
		Addresses:      [][]byte{{10, byte(i >> 16), byte(i >> 8), byte(i)}},
		TunnelProtocol: workload.TunnelProtocol_HBONE,
		Extensions: []*workload.Extension{
			{Name: "workload-instance", Config: instanceExtension(src)},
			{Name: "metadata", Config: anyOf(&ext.WorkloadMetadata{Labels: labels(i, revision)})},
			{Name: "sni-traffic-policy", Config: sniPolicy(ext.SniAction_SNI_ACTION_TLS_TERMINATION)},
			{
				Name:   "traffic-policy-reference",
				Config: anyOf(&ext.PolicyReference{TypeUrl: model.TrafficPolicyType}),
			},
			{
				Name:   "security-profile-reference",
				Config: anyOf(&ext.PolicyReference{TypeUrl: model.SecurityProfileType}),
			},
		},
	}
	p, e := model.NewPrincipal("cluster.local", "ns/perf/sa/default")
	must(e)
	wireName := ""
	if instanceWireName {
		wireName = src.WorkloadAlias()
	}
	r, e := model.NewResource(
		model.ResourceKey{TypeURL: model.AddressType, Name: uid(i)},
		wireName,
		anyOf(&workload.Address{Type: &workload.Address_Workload{Workload: w}}),
		[]string{"/" + ip(i), src.WorkloadAlias()},
		model.ResourceFacts{
			Workload: &model.WorkloadResourceFacts{
				Namespace:   "perf",
				WorkloadUID: uid(i),
				Source:      src,
				Principal:   p,
				NodeName:    w.Node,
			},
		},
	)
	must(e)
	return r
}

func resources(n int) []model.Resource {
	out := make([]model.Resource, 0, 2*n)
	for i := range n {
		out = append(out, workloadResource(i, 0))
		name := fmt.Sprintf("kruise:sandbox-%05d", i)
		b := &sandbox.Sandbox{
			Uid:        name,
			Attester:   &sandbox.Sandbox_Attester{WorkloadUid: uid(i)},
			Extensions: []*anypb.Any{sniPolicy(ext.SniAction_SNI_ACTION_PASSTHROUGH)},
		}
		r, e := model.NewResource(
			model.ResourceKey{TypeURL: model.SandboxType, Name: name},
			"",
			anyOf(b),
			nil,
			model.ResourceFacts{Sandbox: &model.SandboxResourceFacts{AttesterWorkloadUID: uid(i)}},
		)
		must(e)
		out = append(out, r)
	}
	return out
}

type connections struct {
	net.Listener
	mu  sync.Mutex
	all map[net.Conn]bool
}

func (c *connections) Accept() (net.Conn, error) {
	v, e := c.Listener.Accept()
	if e == nil {
		c.mu.Lock()
		c.all[v] = true
		c.mu.Unlock()
	}
	return v, e
}

func (c *connections) disconnect() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(c.all)
	for conn := range c.all {
		if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Printf("disconnect ADS connection: %v", err)
		}
		delete(c.all, conn)
	}
	return n
}

// Time the first Recv call without patching the control plane. The interval
// before it includes stream admission, authentication and goroutine scheduling.
type observedStream struct {
	discovery.AggregatedDiscoveryService_DeltaAggregatedResourcesServer
	started time.Time
	first   bool
}

func (s *observedStream) Recv() (*discovery.DeltaDiscoveryRequest, error) {
	first := s.first
	s.first = false
	receiving := time.Now()
	req, err := s.AggregatedDiscoveryService_DeltaAggregatedResourcesServer.Recv()
	if first && err == nil && strings.HasPrefix(req.GetNode().GetId(), "agentio-porter~") {
		emit(map[string]any{
			"event":          "ads_first_request",
			"node":           req.Node.Id,
			"started_unix":   float64(s.started.UnixNano()) / 1e9,
			"before_recv_ms": float64(receiving.Sub(s.started)) / 1e6,
			"recv_ms":        float64(time.Since(receiving)) / 1e6,
		})
	}
	return req, err
}

type observedADS struct {
	discovery.UnimplementedAggregatedDiscoveryServiceServer
	inner *xds.Server
}

func (d *observedADS) DeltaAggregatedResources(
	s discovery.AggregatedDiscoveryService_DeltaAggregatedResourcesServer,
) error {
	return d.inner.DeltaAggregatedResources(&observedStream{s, time.Now(), true})
}

func cpu() float64 {
	var r syscall.Rusage
	must(syscall.Getrusage(syscall.RUSAGE_SELF, &r))
	return float64(r.Utime.Sec+r.Stime.Sec) + float64(r.Utime.Usec+r.Stime.Usec)/1e6
}

func server(args []string) {
	f := flag.NewFlagSet("server", flag.ExitOnError)
	n := f.Int("resources", 50000, "")
	f.BoolVar(
		&instanceWireName,
		"instance-wire-name",
		false,
		"diagnostic: make the demand alias the canonical wire name",
	)
	must(f.Parse(args))
	if *n < 50000 {
		log.Fatal("at least 50000 workloads required")
	}
	rs, e := model.NewResourceSet(resources(*n))
	must(e)
	principal, e := model.NewPrincipal("cluster.local", "ns/perf/sa/default")
	must(e)
	scope := model.ClientScope{
		Class:       model.ClientAgentioEgress,
		Principal:   principal,
		GatewayKey:  "perf/gateway",
		WorkloadUID: "perf-gateway",
		Source:      model.SourceRef{Registry: "kubernetes", Key: "perf/gateway"},
	}
	st := store.New(rs)
	s, e := xds.NewServer(
		auth{},
		xds.ScopeFuncs{
			model.AttestationKubernetes: func(node *core.Node, _ model.PeerIdentity) (model.ClientScope, error) {
				if after, ok := strings.CutPrefix(node.Id, "watcher~"); ok {
					return model.ClientScope{
						Class:     model.ClientSharedZTunnel,
						Principal: principal,
						NodeName:  after,
					}, nil
				}
				return scope, nil
			},
		},
		st,
		func() bool {
			return true
		},
		features.ClientQueueSize,
		map[string]xds.ResourceGenerator{
			model.AddressType:  xds.WorkloadGenerator{},
			model.WorkloadType: xds.WorkloadGenerator{},
			model.SandboxType:  xds.SandboxGenerator{},
		},
		features.PushConcurrency,
		features.RequestRateLimit,
	)
	must(e)
	defer s.Close()
	cert, e := tls.LoadX509KeyPair("/tls/server.pem", "/tls/key.pem")
	must(e)
	l, e := net.Listen("tcp", ":15012")
	must(e)
	transport := &connections{Listener: l, all: map[net.Conn]bool{}}
	cnt := &counters{}
	g := grpc.NewServer(
		grpc.KeepaliveEnforcementPolicy(
			keepalive.EnforcementPolicy{MinTime: 30 * time.Second, PermitWithoutStream: true},
		),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionAge:      features.MaxServerConnectionAge,
			MaxConnectionAgeGrace: 10 * time.Second,
			MaxConnectionIdle:     30 * time.Minute,
			Time:                  2 * time.Hour,
			Timeout:               20 * time.Second,
		}),
		grpc.StatsHandler(cnt),
		grpc.Creds(
			credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}),
		),
		grpc.MaxRecvMsgSize(math.MaxInt32),
	)
	d := &observedADS{inner: s}
	discovery.RegisterAggregatedDiscoveryServiceServer(g, d)
	http.HandleFunc("/disconnect", func(w http.ResponseWriter, r *http.Request) {
		n := transport.disconnect()
		writeResponse(w, map[string]any{"disconnected": n})
	})
	http.HandleFunc("/mutate", mutationHandler(st, *n))

	http.Handle("/metrics", cpmetrics.Default)
	http.HandleFunc("/stats", controlPlaneStats(cnt))
	go func() {
		must(http.ListenAndServe(":8080", nil))
	}()
	emit(map[string]any{
		"server_ready":       true,
		"client_queue":       features.ClientQueueSize,
		"push_concurrency":   features.PushConcurrency,
		"stream_rate_limit":  features.RequestRateLimit,
		"resources_per_type": *n,
		"process":            porterStats(os.Getpid()),
		"gomaxprocs":         runtime.GOMAXPROCS(0),
	})
	must(g.Serve(transport))
}

func controlPlaneStats(cnt *counters) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		writeResponse(w, map[string]any{
			"cpu_seconds":     cpu(),
			"heap_alloc":      m.HeapAlloc,
			"total_alloc":     m.TotalAlloc,
			"mallocs":         m.Mallocs,
			"num_gc":          m.NumGC,
			"gc_pause_ns":     m.PauseTotalNs,
			"gc_cpu_fraction": m.GCCPUFraction,
			"heap_inuse":      m.HeapInuse,
			"heap_sys":        m.HeapSys,
			"cgroup_cpu":      cgroupCPU(),
			"process":         porterStats(os.Getpid()),
			"wire":            cnt.snapshot(),
		})
	}
}

func mutationHandler(st *store.Store, resources int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		count, e := strconv.Atoi(r.URL.Query().Get("count"))
		if e != nil || count < 1 || count > resources {
			http.Error(w, "invalid count", 400)
			return
		}
		revision, e := strconv.Atoi(r.URL.Query().Get("revision"))
		if e != nil {
			http.Error(w, "invalid revision", 400)
			return
		}
		start := time.Now()
		for base := 0; base < count; base += 1000 {
			changes := make([]model.ResourceChange, 0, 1000)
			for i := base; i < min(base+1000, count); i++ {
				v := workloadResource(i, revision)
				c := model.ResourceChange{Key: v.Key}
				if old, found := st.Snapshot().Get(v.Key); found {
					c.Old = &old
				}
				if r.URL.Query().Get("delete") != "true" {
					c.New = &v
				}
				changes = append(changes, c)
			}
			if _, err := st.Apply(changes); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
		}
		writeResponse(w, map[string]any{
			"mutated":         count,
			"workloads_after": len(st.Snapshot().List(model.AddressType)),
			"revision":        revision,
			"seconds":         time.Since(start).Seconds(),
		})
	}
}

type counters struct {
	in           atomic.Int64
	out          atomic.Int64
	received     atomic.Int64
	sent         atomic.Int64
	subscribed   atomic.Int64
	unsubscribed atomic.Int64
	resources    atomic.Int64
}

func (c *counters) TagRPC(ctx context.Context, _ *stats.RPCTagInfo) context.Context {
	return ctx
}

func (c *counters) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context {
	return ctx
}

func (c *counters) HandleConn(context.Context, stats.ConnStats) {}

func (c *counters) HandleRPC(_ context.Context, s stats.RPCStats) {
	switch p := s.(type) {
	case *stats.InPayload:
		c.in.Add(int64(p.WireLength))
		c.received.Add(1)
		if r, ok := p.Payload.(*discovery.DeltaDiscoveryRequest); ok {
			c.subscribed.Add(int64(len(r.ResourceNamesSubscribe)))
			c.unsubscribed.Add(int64(len(r.ResourceNamesUnsubscribe)))
		}
	case *stats.OutPayload:
		c.out.Add(int64(p.WireLength))
		c.sent.Add(1)
		if r, ok := p.Payload.(*discovery.DeltaDiscoveryResponse); ok {
			c.resources.Add(int64(len(r.Resources)))
		}
	}
}

func (c *counters) snapshot() map[string]int64 {
	return map[string]int64{
		"subscribe_names":        c.subscribed.Load(),
		"unsubscribe_names":      c.unsubscribed.Load(),
		"resources":              c.resources.Load(),
		"inbound_payload_bytes":  c.in.Load(),
		"outbound_payload_bytes": c.out.Load(),
		"inbound_messages":       c.received.Load(),
		"outbound_messages":      c.sent.Load(),
	}
}

func porterPID(executable string) int {
	entries, e := os.ReadDir("/proc")
	must(e)
	for _, entry := range entries {
		pid, e := strconv.Atoi(entry.Name())
		if e != nil {
			continue
		}
		v, e := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if e == nil && strings.HasPrefix(string(v), executable+"\x00") {
			return pid
		}
	}
	log.Fatal("porter process not found in shared process namespace")
	return 0
}

func porterStats(pid int) map[string]float64 {
	b, e := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	must(e)
	f := strings.Fields(string(b)[strings.LastIndex(string(b), ")")+1:])
	u, e := strconv.ParseFloat(f[11], 64)
	must(e)
	s, e := strconv.ParseFloat(f[12], 64)
	must(e)
	b, e = os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	must(e)
	m := map[string]float64{"cpu_seconds": (u + s) / 100}
	for line := range strings.SplitSeq(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		if f[0] == "VmRSS:" || f[0] == "VmHWM:" {
			v, e := strconv.ParseFloat(f[1], 64)
			must(e)
			m[strings.TrimSuffix(f[0], ":")+"_kib"] = v
		}
	}
	return m
}

func serverStats() map[string]any {
	r, e := http.Get("http://ads:8080/stats")
	must(e)
	defer func() { must(r.Body.Close()) }()
	var v map[string]any
	must(json.NewDecoder(r.Body).Decode(&v))
	return v
}

func certificates(n, offset int) []string {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(e)
	result := make([]string, n)
	for i := range result {
		src := source(i + offset)
		v, e := json.Marshal(map[string]string{"registry": src.Registry, "uid": src.Key})
		must(e)
		t := &x509.Certificate{
			SerialNumber:    big.NewInt(int64(i + offset + 1)),
			Subject:         pkix.Name{CommonName: "scale-client"},
			NotBefore:       time.Now().Add(-time.Hour),
			NotAfter:        time.Now().Add(24 * time.Hour),
			ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57874, 5, 1}, Value: v}},
		}
		der, e := x509.CreateCertificate(rand.Reader, t, t, &key.PublicKey, key)
		must(e)
		result[i] = url.PathEscape(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	}
	return result
}

var certs []string

var deletedCount int

var requestOffset int

var maxDuration time.Duration

var startUnix int64

func message(mode string, i int) *extproc.ProcessingRequest {
	attrs := &structpb.Struct{
		Fields: map[string]*structpb.Value{
			model.AttributePeerCertificate: structpb.NewStringValue(certs[i-requestOffset]),
		},
	}
	if mode == "ip" {
		attrs.Fields = map[string]*structpb.Value{
			model.AttributePeerIP:        structpb.NewStringValue(ip(i)),
			model.AttributePeerPrincipal: structpb.NewStringValue("spiffe://cluster.local/ns/perf/sa/default"),
		}
	}
	if mode == "sandbox" {
		attrs.Fields["filter_state['sandbox.id']"] = structpb.NewStringValue(fmt.Sprintf("kruise:sandbox-%05d", i))
	}
	return &extproc.ProcessingRequest{
		Request: &extproc.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extproc.HttpHeaders{
				Headers: &core.HeaderMap{
					Headers: []*core.HeaderValue{
						{Key: ":method", RawValue: []byte("CONNECT")},
						{Key: ":authority", RawValue: []byte("203.0.113.10:443")},
					},
				},
			},
		},
		Attributes: map[string]*structpb.Struct{model.ExtProcAttributesKey: attrs},
	}
}

func call(
	ctx context.Context,
	client extproc.ExternalProcessorClient,
	req *extproc.ProcessingRequest,
	mode string,
	i, revision int,
) error {
	if i < deletedCount {
		mode = "deleted"
	}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	stream, e := client.Process(ctx)
	if e != nil {
		return e
	}
	if e = stream.Send(req); e != nil {
		return e
	}
	r, e := stream.Recv()
	if e != nil {
		return e
	}
	if mode == "deleted" {
		if r.GetImmediateResponse().GetStatus().GetCode() != 403 {
			return fmt.Errorf("expected removed identity rejection")
		}
	} else {
		if r.GetRequestHeaders() == nil {
			return fmt.Errorf("unexpected denial: %v", r.GetImmediateResponse())
		}
		m := r.GetDynamicMetadata().GetFields()["agentio"].GetStructValue().GetFields()
		if got := m["workload"].GetStructValue().GetFields()["name"].GetStringValue(); got != fmt.Sprintf(
			"workload-%05d",
			i,
		) {
			return fmt.Errorf("wrong workload %q for %d", got, i)
		}
		encoded := m["workload_labels"].GetStringValue()
		b, e := base64.StdEncoding.DecodeString(encoded)
		if e != nil {
			return e
		}
		got := string(b)
		if !strings.Contains(got, fmt.Sprintf("example.com/label-00=value-00-%06d", i)) {
			return fmt.Errorf("wrong labels for %d", i)
		}
		if revision >= 0 && !strings.Contains(","+got+",", fmt.Sprintf(",revision=%d,", revision)) {
			return fmt.Errorf("stale revision expected=%d", revision)
		}
		if mode != "ip" && m["workload_instance"].GetStringValue() != source(i).WorkloadAlias() {
			return fmt.Errorf("wrong instance")
		}
		rules := m["sni"].GetStructValue().GetFields()["policy"].GetStructValue().GetFields()["rules"].GetListValue().
			GetValues()
		want := 8
		if mode == "sandbox" {
			want = 16
		}
		if len(rules) != want {
			return fmt.Errorf("SNI rules=%d want=%d", len(rules), want)
		}
	}
	if _, e = stream.Recv(); !errors.Is(e, io.EOF) {
		if e == nil {
			return fmt.Errorf("expected EOF, received another response")
		}
		return fmt.Errorf("expected EOF: %w", e)
	}
	return nil
}

type phaseResult struct {
	loadgen.Result
	RunError       string  `json:"run_error,omitempty"`
	LoadCPUSeconds float64 `json:"load_cpu_seconds"`
}

func phase(
	ctx context.Context,
	client extproc.ExternalProcessorClient,
	mode string,
	n, parallel, active, revision, rate int,
) phaseResult {
	requests := make([]*extproc.ProcessingRequest, active)
	for i := range requests {
		requests[i] = message(mode, i+requestOffset)
	}
	var start time.Time
	if startUnix != 0 {
		start = time.Unix(startUnix, 0)
	}
	var startCPU, usedCPU float64
	result, err := loadgen.Run(ctx, loadgen.Config{
		Requests:    n,
		Identities:  active,
		Offset:      requestOffset,
		Concurrency: parallel,
		Rate:        rate,
		Duration:    maxDuration,
		Start:       start,
		Started: func() {
			fmt.Fprintln(os.Stderr, "LOAD_STARTED")
			startCPU = cpu()
		},
		Finished: func() {
			usedCPU = cpu() - startCPU
		},
	}, func(ctx context.Context, identity int) error {
		return call(ctx, client, requests[identity-requestOffset], mode, identity, revision)
	})
	// Preserve partial counts on cancellation/deadline; the runner rejects incomplete phases.
	outcome := phaseResult{Result: result, LoadCPUSeconds: usedCPU}
	if err != nil {
		outcome.RunError = err.Error()
	}
	return outcome
}

func metrics() string {
	r, e := http.Get("http://127.0.0.1:9004/metrics")
	must(e)
	defer func() { must(r.Body.Close()) }()
	b, e := io.ReadAll(r.Body)
	must(e)
	return string(b)
}

func client(args []string) {
	f := flag.NewFlagSet("client", flag.ExitOnError)
	mode := f.String("mode", "workload", "")
	executable := f.String("porter-executable", "/porter", "Porter executable in shared PID namespace")
	active := f.Int("active", 50000, "")
	parallel := f.Int("concurrency", 32, "")
	n := f.Int("requests", 50000, "")
	revision := f.Int("revision", 0, "")
	rate := f.Int("rate", 0, "")
	f.IntVar(&deletedCount, "deleted", 0, "")
	f.IntVar(&requestOffset, "offset", 0, "")
	f.DurationVar(&maxDuration, "duration", 180*time.Second, "")
	f.Int64Var(&startUnix, "start-unix", 0, "common load start (Unix seconds); fail if preparation overruns")
	must(f.Parse(args))
	if *active <= 0 || *parallel <= 0 || *n <= 0 || *rate < 0 || requestOffset < 0 || maxDuration <= 0 {
		log.Fatal("invalid client workload parameters")
	}
	certs = certificates(*active, requestOffset)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	pid := porterPID(*executable)
	conn, e := grpc.NewClient("127.0.0.1:9002", grpc.WithTransportCredentials(insecure.NewCredentials()))
	must(e)
	defer func() { must(conn.Close()) }()
	before := porterStats(pid)
	sb := serverStats()
	mb := metrics()
	result := phase(ctx, extproc.NewExternalProcessorClient(conn), *mode, *n, *parallel, *active, *revision, *rate)
	emit(map[string]any{
		"mode":             *mode,
		"active_workloads": *active,
		"result":           result,
		"porter_before":    before,
		"porter_after":     porterStats(pid),
		"ads_before":       sb,
		"ads_after":        serverStats(),
		"metrics_before":   mb,
		"metrics_after":    metrics(),
		"gomaxprocs":       runtime.GOMAXPROCS(0),
	})
}

func watchers(args []string) {
	f := flag.NewFlagSet("watchers", flag.ExitOnError)
	n := f.Int("resources", 50000, "")
	observe := f.Bool("observe-updates", false, "record per-client applied revision convergence")
	must(f.Parse(args))
	if *n < 50000 {
		log.Fatal("at least 50000")
	}
	recorder := newObservations((*n + 499) / 500)
	if *observe {
		http.HandleFunc("/observe", recorder.arm)
	}
	var changes atomic.Int64
	clients := make([]*xdsclient.Client, 0, (*n+499)/500)
	ctx := context.Background()
	for i := 0; i < (*n+499)/500; i++ {
		conn, e := xdsclient.Dial("ads:15012", "/tls/ca.pem", "/tls/token")
		must(e)
		c, e := xdsclient.New(conn, xdsclient.Config{
			Node: &core.Node{Id: fmt.Sprintf("watcher~node-%03d", i)},
			Watches: []xdsclient.Watch{{
				TypeURL:  model.AddressType,
				Wildcard: true,
				Transform: func(v *anypb.Any) (any, error) {
					changes.Add(1)
					if *observe {
						return observedWorkload(v)
					}
					return v, nil
				},
			}},
		})
		must(e)
		clients = append(clients, c)
		if *observe {
			go recorder.watch(ctx, i, c)
		}
		go func() {
			must(c.Run(ctx))
		}()
	}
	http.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		total, ready := 0, 0
		for _, c := range clients {
			s := c.Snapshot()
			total += len(s.Resources[model.AddressType])
			if s.Connected && s.Synced[model.AddressType] {
				ready++
			}
		}
		writeResponse(w, map[string]any{
			"clients":     len(clients),
			"ready":       ready,
			"resources":   total,
			"transforms":  changes.Load(),
			"observation": recorder.snapshot(),
			"cpu_seconds": cpu(),
		})
	})
	must(http.ListenAndServe(":8081", nil))
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: bench server|watchers|client|get|idle")
	}
	switch os.Args[1] {
	case "get":
		r, e := http.Get(os.Args[2])
		must(e)
		defer func() { must(r.Body.Close()) }()
		_, e = io.Copy(os.Stdout, r.Body)
		must(e)
		if r.StatusCode != 200 {
			os.Exit(1)
		}
	case "server":
		server(os.Args[2:])
	case "watchers":
		watchers(os.Args[2:])
	case "client":
		client(os.Args[2:])
	case "idle":
		for {
			time.Sleep(time.Hour)
		}
	default:
		panic("server/client/idle")
	}
}
