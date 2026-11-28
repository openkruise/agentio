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

package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	agents "github.com/openkruise/agents-api/agents/v1alpha1"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/anypb"
	"istio.io/istio/pkg/test"
	corev1 "k8s.io/api/core/v1"

	sandbox "github.com/openkruise/agentio/api/sandbox/v1"
	"github.com/openkruise/agentio/bench/load"
	"github.com/openkruise/agentio/extensions/epe/pkg/metrics"
	"github.com/openkruise/agentio/extensions/epe/pkg/policy/profilestore"
	xdsstore "github.com/openkruise/agentio/extensions/epe/pkg/store/xds"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
	"github.com/openkruise/agentio/extensions/epe/pkg/wiring"
	"github.com/openkruise/agentio/pkg/compiler"
	"github.com/openkruise/agentio/pkg/demandcache"
	"github.com/openkruise/agentio/pkg/features"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/xds"
	publication "github.com/openkruise/agentio/pkg/xds/store"
)

func benchPolicySubject(i int) subject.Subject {
	return subject.Subject{Workload: subject.Workload{UID: "host", SecurityProfileReferences: []string{}},
		Sandbox: &subject.Sandbox{UID: fmt.Sprintf("sandbox:%06d", i)}}
}

// Use the same TLS credentials, policy projection, retention and asynchronous
// admission as the EPE process. Stop the ADS reader before releasing the flags.
func benchPolicyMatcher(tb testing.TB, mode, addr, root, token string, maxEntries int) *profilestore.XDSStore {
	tb.Helper()
	test.SetForTest(tb, &features.SandboxMode, true)
	test.SetForTest(tb, &metrics.Registry, prometheus.NewRegistry())
	test.SetForTest(tb, securityProfileSource, "xds")
	test.SetForTest(tb, sandboxSource, mode)
	test.SetForTest(tb, xdsAddress, addr)
	test.SetForTest(tb, xdsRootPath, root)
	test.SetForTest(tb, xdsTokenPath, token)
	test.SetForTest(tb, xdsNodeID, "epe-node")
	regs, err := wiring.BuildValidationFilters()
	if err != nil {
		tb.Fatal(err)
	}
	ctx, cancel := context.WithCancel(tb.Context())
	matcher := profilestore.NewXDSStore()
	src := xdsstore.NewProfileSource(matcher.ObserveAdmission, ctx.Done())
	client, conn, err := newEgressXDS(regs, src)
	if err != nil {
		cancel()
		tb.Fatal(err)
	}
	store, err := xdsstore.NewCached(client, demandcache.Config{IdleTTL: 10 * time.Minute, MaxEntries: maxEntries})
	if err != nil {
		tb.Fatal(err)
	}
	opts := krt.WithStop(ctx.Done())
	cms := krt.NewMutableCollection[*corev1.ConfigMap](nil, nil, opts)
	reg := matcher.RegisterCollection(src.Collection(cms.AsCollection(), opts), store.AcquireProfileReferences)
	done := make(chan error, 2)
	go func() { done <- client.Run(ctx) }()
	go func() { done <- store.Run(ctx) }()
	tb.Cleanup(func() {
		cancel()
		for range 2 {
			if err := <-done; err != nil {
				tb.Error(err)
			}
		}
		reg.UnregisterHandler()
		if err := conn.Close(); err != nil {
			tb.Error(err)
		}
	})
	if !reg.WaitUntilSynced(ctx.Done()) {
		tb.Fatal("policy collection did not sync")
	}
	return matcher
}

func benchResolve(ctx context.Context, m *profilestore.XDSStore, s subject.Subject) error {
	profiles, err := m.ResolveProfiles(ctx, s)
	if err != nil {
		return err
	}
	if len(profiles) != 1 || profiles[0].Meta.SandboxUID != s.Sandbox.UID ||
		profiles[0].Meta.SourceIdentity.UID != s.Sandbox.UID || len(profiles[0].Spec.Rules) != 1 {
		return fmt.Errorf("unexpected admitted policy for %s", s.Sandbox.UID)
	}
	return nil
}

func localPolicyBench(b *testing.B, mode string, ttl time.Duration) (*profilestore.XDSStore, *atomic.Int64) {
	const keys = 128
	resources := make([]model.Resource, 0, keys)
	for i := range keys {
		id := benchPolicySubject(i).Sandbox.UID
		spec := &agents.SecurityProfileSpec{
			Rules: []agents.SecurityRule{
				{Name: "egress", Match: []agents.RuleMatch{{Domains: []string{"example.net"}}}},
			},
		}
		sb, err := compiler.CompileSandboxPayload(
			model.Sandbox{
				UID:            id,
				Attester:       &model.Attester{WorkloadUID: "host"},
				SourceIdentity: model.SourceIdentity{UID: id},
				Policies:       &model.SandboxPolicies{SecurityProfile: spec},
			},
		)
		if err != nil {
			b.Fatal(err)
		}
		value, err := anypb.New(sb)
		if err != nil {
			b.Fatal(err)
		}
		r, err := model.NewResource(
			model.ResourceKey{TypeURL: model.SandboxType, Name: id},
			"",
			model.Prebuilt(value),
			nil,
			model.ResourceFacts{Sandbox: &model.SandboxResourceFacts{AttesterWorkloadUID: "host"}},
		)
		if err != nil {
			b.Fatal(err)
		}
		resources = append(resources, r)
	}
	snapshot, err := model.NewResourceSet(resources)
	if err != nil {
		b.Fatal(err)
	}
	scope := model.ClientScope{
		Class:       model.ClientEPE,
		WorkloadUID: "epe",
		Source:      model.SourceRef{Registry: "bench", Key: "epe"},
		Principal:   model.MustServiceAccountPrincipal("bench", "epe"),
	}
	cp, err := xds.NewServer(
		queryPeer{},
		xds.ScopeFuncs{
			model.AttestationKubernetes: func(*core.Node, model.PeerIdentity) (model.ClientScope, error) { return scope, nil },
		},
		publication.New(snapshot),
		func() bool { return true },
		16,
		map[string]xds.ResourceGenerator{model.SandboxType: xds.SandboxGenerator{}},
		2,
		0,
	)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(cp.Close)
	calls := new(atomic.Int64)
	g := grpc.NewServer(
		grpc.UnaryInterceptor(
			func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
				calls.Add(1)
				return next(ctx, req)
			},
		),
	)
	sandbox.RegisterSandboxQueryServiceServer(g, cp.SandboxQuery(nil, nil, ttl))
	discovery.RegisterAggregatedDiscoveryServiceServer(g, cp)
	srv := httptest.NewUnstartedServer(g)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	b.Cleanup(srv.Close)
	dir := b.TempDir()
	root, token := filepath.Join(dir, "root.pem"), filepath.Join(dir, "token")
	if err := os.WriteFile(root, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0600); err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(token, []byte("token"), 0600); err != nil {
		b.Fatal(err)
	}
	return benchPolicyMatcher(b, mode, strings.TrimPrefix(srv.URL, "https://"), root, token, 0), calls
}

func BenchmarkSandboxPolicyDelivery(b *testing.B) {
	for _, tc := range []struct {
		name string
		mode string
		ttl  time.Duration
	}{{"DeltaHot", "xds", time.Hour}, {"RPCHot", "rpc", time.Hour}, {"RPCRefresh", "rpc", 0}} {
		b.Run(tc.name, func(b *testing.B) {
			m, calls := localPolicyBench(b, tc.mode, tc.ttl)
			subjects := make([]subject.Subject, 128)
			for i := range subjects {
				subjects[i] = benchPolicySubject(i)
				if err := benchResolve(b.Context(), m, subjects[i]); err != nil {
					b.Fatal(err)
				}
			}
			before := calls.Load()
			b.ReportAllocs()
			b.ResetTimer()
			if tc.ttl == 0 {
				i := 0
				for b.Loop() {
					if err := benchResolve(b.Context(), m, subjects[i%len(subjects)]); err != nil {
						b.Fatal(err)
					}
					i++
				}
			} else {
				b.RunParallel(func(pb *testing.PB) {
					i := 0
					for pb.Next() {
						if err := benchResolve(b.Context(), m, subjects[i%len(subjects)]); err != nil {
							b.Error(err)
							return
						}
						i++
					}
				})
			}
			b.StopTimer()
			n := calls.Load() - before
			b.ReportMetric(float64(n)/float64(b.N), "RPC/op")
			if (tc.ttl == 0 && n != int64(b.N)) || (tc.ttl > 0 && n != 0) {
				b.Fatalf("unexpected GetSandbox count: %d for %d resolutions", n, b.N)
			}
		})
	}
}

// TestSandboxPolicyLoad drives an externally started query/ADS service. Each
// operation verifies the admitted Sandbox policy, including its source UID.
func TestSandboxPolicyLoad(t *testing.T) {
	raw := os.Getenv("AGENTIO_SANDBOX_BENCH")
	if raw == "" {
		t.Skip("set AGENTIO_SANDBOX_BENCH to a JSON run configuration")
	}
	var c struct {
		Mode       string
		Address    string
		Root       string
		Token      string
		Keys       int
		Warm       int
		Requests   int
		Workers    int
		Rate       int
		PauseMS    int
		MaxEntries int
	}
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatal(err)
	}
	if c.Keys <= 0 || c.Warm < 0 || c.Warm > c.Keys || c.Workers <= 0 || c.Requests <= 0 || c.PauseMS < 0 {
		t.Fatal("invalid query load configuration")
	}
	m := benchPolicyMatcher(t, c.Mode, c.Address, c.Root, c.Token, c.MaxEntries)
	subjects := make([]subject.Subject, c.Keys)
	for i := range subjects {
		subjects[i] = benchPolicySubject(i)
	}
	run := func(name string, keys, count, rate int) {
		probe := func(when string) {
			if file := os.Getenv("AGENTIO_QUERY_BENCH_PROBE"); file != "" {
				out, err := exec.CommandContext(t.Context(), file).Output()
				if err != nil {
					t.Fatalf("sampling %s: %v", when, err)
				}
				t.Logf("COUNTERS %s-%s %s", name, when, strings.TrimSpace(string(out)))
			}
		}
		result, err := load.Run(
			t.Context(),
			load.Config{
				Requests:    count,
				Identities:  keys,
				Concurrency: c.Workers,
				Rate:        rate,
				Duration:    5 * time.Minute,
				Started:     func() { probe("start") },
				Finished:    func() { probe("end") },
			},
			func(ctx context.Context, i int) error {
				req, cancel := context.WithTimeout(ctx, 4*time.Second)
				defer cancel()
				return benchResolve(req, m, subjects[i])
			},
		)
		result.BatchMeans = nil
		out, e := json.Marshal(result)
		if e != nil {
			t.Fatal(e)
		}
		t.Logf("SAMPLE %s %s", name, out)
		if err != nil || result.Errors != 0 || result.Operations != count {
			t.Fatalf("%s: %v, errors %d first %s", name, err, result.Errors, result.FirstError)
		}
	}
	if c.Warm > 0 {
		run("warm", c.Warm, c.Warm, 0)
	}
	time.Sleep(time.Duration(c.PauseMS) * time.Millisecond)
	run("measure", c.Keys, c.Requests, c.Rate)
	if path := os.Getenv("AGENTIO_QUERY_BENCH_HEAP"); path != "" {
		runtime.GC()
		file, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		err = pprof.WriteHeapProfile(file)
		if closeErr := file.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		if err != nil {
			t.Fatal(err)
		}
		runtime.KeepAlive(m)
	}
}
