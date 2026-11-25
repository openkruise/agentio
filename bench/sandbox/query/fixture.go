//go:build ignore

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

// Run explicitly with the bench-only pgx dependency in a temporary modfile.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	agents "github.com/openkruise/agents-api/agents/v1alpha1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/stats"
	"google.golang.org/protobuf/types/known/anypb"

	sandbox "github.com/openkruise/agentio/api/sandbox/v1"
	"github.com/openkruise/agentio/pkg/compiler"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/xds"
	xstore "github.com/openkruise/agentio/pkg/xds/store"
)

type benchmarkPeer struct{}

func (benchmarkPeer) Authenticate(ctx context.Context) (model.PeerIdentity, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	v := md.Get("authorization")
	if len(v) != 1 || v[0] != "Bearer token" {
		return model.PeerIdentity{}, errors.New("invalid benchmark credential")
	}
	return model.PeerIdentity{AttestedBy: model.AttestationKubernetes}, nil
}

type counts struct {
	gets      atomic.Int64
	sql       atomic.Int64
	deltas    atomic.Int64
	resources atomic.Int64
}

func (c *counts) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context { return ctx }
func (c *counts) HandleConn(context.Context, stats.ConnStats)                       {}
func (c *counts) TagRPC(ctx context.Context, info *stats.RPCTagInfo) context.Context {
	if info.FullMethodName == sandbox.SandboxQueryService_GetSandbox_FullMethodName {
		c.gets.Add(1)
	}
	return ctx
}
func (c *counts) HandleRPC(_ context.Context, event stats.RPCStats) {
	if p, ok := event.(*stats.OutPayload); ok {
		if d, ok := p.Payload.(*discovery.DeltaDiscoveryResponse); ok && d.TypeUrl == model.SandboxType {
			c.deltas.Add(1)
			c.resources.Add(int64(len(d.Resources)))
		}
	}
}

func compile(uid string, body []byte) (*sandbox.Sandbox, error) {
	var spec agents.SecurityProfileSpec
	if err := json.Unmarshal(body, &spec); err != nil {
		return nil, err
	}
	return compiler.CompileSandboxPayload(
		model.Sandbox{
			UID:            uid,
			Name:           uid,
			Namespace:      "bench",
			SourceIdentity: model.SourceIdentity{UID: uid},
			Attester:       &model.Attester{WorkloadUID: "host"},
			Policies:       &model.SandboxPolicies{SecurityProfile: &spec},
		},
	)
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	backend := flag.String("backend", "db", "db or snapshot")
	n := flag.Int("inventory", 50000, "number of indexed DB rows to precompile in snapshot mode")
	ttl := flag.Duration("ttl", 10*time.Second, "query cache TTL")
	flag.Parse()
	ctx := context.Background()
	config, err := pgxpool.ParseConfig("postgres://postgres@pg:5432/policyrpc?sslmode=disable")
	must(err)
	config.ConnConfig.Password = os.Getenv("BENCH_PASSWORD")
	config.MaxConns = 16
	pool, err := pgxpool.NewWithConfig(ctx, config)
	must(err)
	defer pool.Close()
	must(pool.Ping(ctx))
	count := new(counts)
	var lookup xds.SandboxLookup
	var resources []model.Resource
	switch *backend {
	case "db":
		lookup = func(ctx context.Context, _ model.ClientScope, uid string) (*sandbox.Sandbox, error) {
			count.sql.Add(1)
			var body []byte
			err := pool.QueryRow(ctx, "SELECT body FROM sandbox_policy WHERE uid=$1", uid).Scan(&body)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, nil
			}
			if err != nil {
				return nil, err
			}
			return compile(uid, body)
		}
	case "snapshot":
		rows, err := pool.Query(ctx, "SELECT uid,body FROM sandbox_policy ORDER BY uid LIMIT $1", *n)
		must(err)
		for rows.Next() {
			var uid string
			var body []byte
			must(rows.Scan(&uid, &body))
			sb, err := compile(uid, body)
			must(err)
			val, err := anypb.New(sb)
			must(err)
			r, err := model.NewResource(
				model.ResourceKey{TypeURL: model.SandboxType, Name: uid},
				"",
				model.Prebuilt(val),
				nil,
				model.ResourceFacts{Sandbox: &model.SandboxResourceFacts{AttesterWorkloadUID: "host"}},
			)
			must(err)
			resources = append(resources, r)
		}
		must(rows.Err())
		rows.Close()
		if len(resources) != *n {
			log.Fatalf("preloaded %d, want %d", len(resources), *n)
		}
	default:
		log.Fatal("invalid backend")
	}
	set, err := model.NewResourceSet(resources)
	must(err)
	scope := func(n *core.Node, _ model.PeerIdentity) (model.ClientScope, error) {
		s := model.ClientScope{
			Class:       model.ClientEPE,
			WorkloadUID: "epe",
			Source:      model.SourceRef{Registry: "bench", Key: "client"},
			Principal:   model.MustServiceAccountPrincipal("bench", "client"),
		}
		if n.Id == "porter" {
			s.Class = model.ClientAgentioEgress
			s.GatewayKey = "bench/gw"
			s.WorkloadUID = "porter"
		}
		return s, nil
	}
	cp, err := xds.NewServer(
		benchmarkPeer{},
		xds.ScopeFuncs{model.AttestationKubernetes: scope},
		xstore.New(set),
		func() bool { return true },
		16,
		map[string]xds.ResourceGenerator{model.SandboxType: xds.SandboxGenerator{}},
		2,
		0,
	)
	must(err)
	defer cp.Close()
	creds, err := credentials.NewServerTLSFromFile("/tmp/bench.crt", "/tmp/bench.key")
	must(err)
	g := grpc.NewServer(grpc.Creds(creds), grpc.StatsHandler(count))
	discovery.RegisterAggregatedDiscoveryServiceServer(g, cp)
	sandbox.RegisterSandboxQueryServiceServer(g, cp.SandboxQuery(lookup, nil, *ttl))
	listener, err := net.Listen("tcp", ":9000")
	must(err)
	http.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		var u syscall.Rusage
		err := syscall.Getrusage(syscall.RUSAGE_SELF, &u)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		var cpu string
		if err := pool.QueryRow(r.Context(), "SELECT pg_read_file('/sys/fs/cgroup/cpu.stat')").Scan(&cpu); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		var us int64
		if _, err := fmt.Sscanf(cpu, "usage_usec %d", &us); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		data, err := os.ReadFile("/proc/self/statm")
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		pages, err := strconv.ParseInt(strings.Fields(string(data))[1], 10, 64)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		err = json.NewEncoder(w).Encode(map[string]any{
			"gets":      count.gets.Load(),
			"sql":       count.sql.Load(),
			"deltas":    count.deltas.Load(),
			"resources": count.resources.Load(),
			"cp_cpu":    float64(u.Utime.Nano()+u.Stime.Nano()) / 1e9,
			"db_cpu":    float64(us) / 1e6,
			"pool_wait": pool.Stat().EmptyAcquireWaitTime().Seconds(),
			"rss_mib":   float64(pages) * float64(os.Getpagesize()) / (1 << 20),
		})
		if err != nil {
			log.Print(err)
		}
	})
	runtime.GC()
	go func() { log.Fatal(http.ListenAndServe(":9001", nil)) }()
	log.Printf("ready backend=%s inventory=%d ttl=%s", *backend, len(resources), *ttl)
	must(g.Serve(listener))
}
