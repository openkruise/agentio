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
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type options struct {
	Action           string
	Kubeconfig       string
	Prefix           string
	System           string
	Output           string
	CA               string
	CAServerName     string
	PolicyKind       string
	Gateway          string
	Target           string
	Path             string
	ExpectedBody     string
	StartFile        string
	TrafficRateFile  string
	ExpectedStatus   int
	Count            int
	Offset           int
	Workers          int
	APIQPS           int
	Revision         int
	Requests         int
	Rate             int
	Active           int
	ConnectionRate   int
	VirtualNodeCount int
	ReuseConnections bool
	Acknowledge      bool
	ReadDelay        time.Duration
	Duration         time.Duration
}

type runner struct {
	options
	kube    kubernetes.Interface
	dynamic dynamic.Interface
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func parseOptions() options {
	o := options{}
	flag.StringVar(
		&o.Action,
		"action",
		"seed",
		"seed, labels, recreate, delete, configure, traffic-policy, policy, lifecycle, watch, traffic, or backend",
	)
	flag.StringVar(&o.Kubeconfig, "kubeconfig", "", "explicit test kubeconfig")
	flag.StringVar(&o.Prefix, "prefix", "sandbox-scale", "owned namespace and node prefix")
	flag.StringVar(&o.System, "system", "sandbox-scale-system", "Agentio installation namespace")
	flag.StringVar(&o.Output, "output", "", "JSON result path")
	flag.StringVar(&o.CA, "ca", "", "CA gRPC host:port; TLS server name is agentiod.SYSTEM.svc")
	flag.StringVar(&o.CAServerName, "ca-server-name", "", "override CA/ADS TLS server name for group-admission probes")
	flag.StringVar(&o.PolicyKind, "policy-kind", "security", "policy probe kind: security or traffic")
	flag.StringVar(&o.Gateway, "gateway", "", "gateway TLS host:port")
	flag.StringVar(&o.Target, "target", "", "CONNECT target host:port (traffic also accepts comma-separated upstreams)")
	flag.IntVar(&o.Count, "count", 10000, "inventory or mutation count")
	flag.IntVar(&o.Offset, "offset", 0, "first resource index")
	flag.IntVar(&o.Workers, "workers", 32, "bounded concurrent operations")
	flag.IntVar(&o.APIQPS, "api-qps", 200, "API request rate per client")
	flag.IntVar(&o.Revision, "revision", 0, "label revision")
	flag.IntVar(&o.Requests, "requests", 10000, "traffic operations")
	flag.IntVar(&o.Rate, "rate", 100, "offered CONNECT requests per second")
	flag.IntVar(&o.Active, "active", 1000, "number of traffic identities")
	flag.IntVar(&o.ConnectionRate, "connection-rate", 100, "new sidecar ADS connections per second")
	flag.IntVar(
		&o.VirtualNodeCount,
		"virtual-node-count",
		0,
		"reuse this many KWOK nodes as inventory grows; zero uses 100 Pods per node",
	)
	flag.BoolVar(&o.ReuseConnections, "reuse-connections", false, "reuse HTTP/2 connections per traffic identity")
	flag.BoolVar(&o.Acknowledge, "ack", true, "acknowledge ADS responses; false simulates a non-ACKing client")
	flag.DurationVar(&o.ReadDelay, "read-delay", 0, "delay the first ADS receive to simulate a slow receiver")
	flag.DurationVar(&o.Duration, "duration", 3*time.Minute, "traffic deadline")
	flag.StringVar(&o.StartFile, "start-file", "", "wait for this shared file after certificate preparation")
	flag.StringVar(
		&o.TrafficRateFile,
		"traffic-rate-file",
		"",
		"continuous traffic: read QPS between 10-second batches; 0 pauses, -1 stops; preserve HTTP/2 connections",
	)
	flag.StringVar(&o.Path, "path", "/", "HTTP request path inside CONNECT")
	flag.StringVar(&o.ExpectedBody, "expected-body", "sandbox-scale-ok\n", "exact expected HTTP response body")
	flag.IntVar(&o.ExpectedStatus, "expected-status", 200, "expected inner HTTP status")
	flag.Parse()
	return o
}

func run() error {
	o := parseOptions()
	if o.Action == "backend" {
		return backend()
	}
	if o.Kubeconfig == "" || o.Count < 1 || o.Workers < 1 || o.APIQPS < 1 || o.Offset < 0 || o.VirtualNodeCount < 0 {
		return fmt.Errorf("explicit kubeconfig and positive counts are required")
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", o.Kubeconfig)
	if err != nil {
		return err
	}
	cfg.Timeout = 30 * time.Second
	cfg.QPS = float32(o.APIQPS)
	cfg.Burst = 2 * o.APIQPS
	cfg.UserAgent = "agentio-sandbox-bench"
	k, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return err
	}
	d, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return err
	}
	r := &runner{options: o, kube: k, dynamic: d}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	started := time.Now()
	result, err := r.execute(ctx)
	record := map[string]any{
		"action":  o.Action,
		"count":   o.Count,
		"offset":  o.Offset,
		"started": started,
		"seconds": time.Since(started).Seconds(),
		"result":  result,
	}
	if err != nil {
		record["error"] = err.Error()
	}
	data, e := json.MarshalIndent(record, "", "  ")
	if e != nil {
		return e
	}
	fmt.Println(string(data))
	if o.Output != "" {
		if e = os.WriteFile(o.Output, append(data, '\n'), 0600); e != nil {
			return e
		}
	}
	return err
}

func (r *runner) parallel(ctx context.Context, operation func(context.Context, int) error) error {
	group, ctx := errgroup.WithContext(ctx)
	jobs := make(chan int)
	group.Go(func() error {
		defer close(jobs)
		for i := r.Offset; i < r.Offset+r.Count; i++ {
			select {
			case jobs <- i:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	})
	for range r.Workers {
		group.Go(func() error {
			for i := range jobs {
				if err := operation(ctx, i); err != nil {
					return fmt.Errorf("resource %d: %w", i, err)
				}
			}
			return nil
		})
	}
	return group.Wait()
}

func (r *runner) execute(ctx context.Context) (any, error) {
	var err error
	var result any
	switch r.Action {
	case "configure":
		err = r.configure(ctx)
	case "traffic-policy":
		err = r.trafficPolicy(ctx)
	case "seed":
		err = r.seed(ctx)
	case "labels":
		err = r.parallel(ctx, r.updateLabels)
	case "delete":
		err = r.parallel(ctx, r.deletePair)
	case "recreate":
		err = r.parallel(ctx, func(ctx context.Context, i int) error {
			if e := r.deletePair(ctx, i); e != nil {
				return e
			}
			return r.createPair(ctx, i)
		})
	case "policy":
		result, err = r.policy(ctx)
	case "lifecycle":
		result, err = r.lifecycle(ctx)
	case "watch", "watch-sidecar":
		result, err = r.watch(ctx)
	case "traffic":
		result, err = r.traffic(ctx)
	default:
		return nil, fmt.Errorf("unknown action %q", r.Action)
	}
	return result, err
}
