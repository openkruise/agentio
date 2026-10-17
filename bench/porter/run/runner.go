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
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/openkruise/agentio/bench/load"
)

type runner struct {
	cfg          config
	kube         kubernetes.Interface
	rest         *rest.Config
	namespaceUID types.UID
	variant      variant
	before       *corev1.PodList
	phases       []string
	mu           sync.Mutex
}

type workerResult struct {
	load.Result
	RunError       string  `json:"run_error,omitempty"`
	LoadCPUSeconds float64 `json:"load_cpu_seconds"`
}

type processStats struct {
	CPU float64 `json:"cpu_seconds"`
	RSS float64 `json:"VmRSS_kib"`
}

type worker struct {
	Result        workerResult `json:"result"`
	Before        processStats `json:"porter_before"`
	After         processStats `json:"porter_after"`
	MetricsBefore string       `json:"metrics_before"`
	MetricsAfter  string       `json:"metrics_after"`
}

type watcherStats struct {
	Clients    int     `json:"clients"`
	CPU        float64 `json:"cpu_seconds"`
	Ready      int     `json:"ready"`
	Resources  int     `json:"resources"`
	Transforms int     `json:"transforms"`
}

type snapshot struct {
	Time     float64             `json:"time"`
	ADS      map[string]adsStats `json:"ads"`
	Watchers watcherStats        `json:"watchers"`
}

type adsStats struct {
	CPU     float64      `json:"cpu_seconds"`
	Process processStats `json:"process"`
	Wire    struct {
		Outbound float64 `json:"outbound_payload_bytes"`
	} `json:"wire"`
}

type summary struct {
	Name       string         `json:"name"`
	Variant    string         `json:"variant"`
	Phase      string         `json:"phase"`
	Concurrent bool           `json:"concurrent"`
	Planned    int            `json:"planned_operations"`
	Operations int            `json:"operations"`
	Errors     int            `json:"errors"`
	RunErrors  []string       `json:"run_errors,omitempty"`
	Rate       int            `json:"offered_rate"`
	QPS        float64        `json:"global_qps"`
	P99        float64        `json:"worst_p99_ms"`
	Max        float64        `json:"worst_max_ms"`
	Results    []workerResult `json:"results"`
}

func (r *runner) write(name string, data []byte) error {
	return os.WriteFile(filepath.Join(r.cfg.Output, name), data, 0600)
}

func (r *runner) save(name string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return r.write(name, append(data, '\n'))
}

func (r *runner) execute(ctx context.Context) (result error) {
	if err := os.MkdirAll(r.cfg.Output, 0700); err != nil {
		return err
	}
	entries, err := os.ReadDir(r.cfg.Output)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return fmt.Errorf("output directory must be empty")
	}
	r.before, err = r.kube.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	if err = r.save("original-pods.json", r.before); err != nil {
		return err
	}
	if err = r.save("config.json", r.cfg); err != nil {
		return err
	}
	defer func() {
		// Cancellation must not cancel cleanup. Keep both the original and cleanup errors.
		cleanup, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
		defer cancel()
		if r.namespaceUID != "" {
			result = errors.Join(result, r.logs(cleanup, "final"))
			if !r.cfg.KeepNamespace {
				result = errors.Join(result, r.deleteNamespace(cleanup))
			}
			result = errors.Join(result, r.checkOriginalPods(cleanup))
		}
		result = errors.Join(result, r.save("completed-phases.json", r.phases))
		if result != nil {
			result = errors.Join(result, r.write("failure.txt", []byte(result.Error()+"\n")))
		}
		result = errors.Join(result, analyze(r.cfg.Output))
	}()
	if err = r.create(ctx); err != nil {
		return err
	}
	for _, v := range r.cfg.Variants {
		r.variant = v
		for _, suite := range r.cfg.Suites {
			if err = r.setup(ctx); err != nil {
				return err
			}
			switch suite {
			case "controlplane":
				err = r.controlPlaneSuite(ctx)
			case "reconnect":
				err = r.reconnectSuite(ctx)
			case "mixed":
				err = r.mixedSuite(ctx)
			case "lifecycle":
				err = r.lifecycleSuite(ctx)
			case "failover":
				err = r.failoverSuite(ctx)
			}
			if err != nil {
				return fmt.Errorf("%s/%s: %w", v.Name, suite, err)
			}
			if err = r.logs(ctx, v.Name+"-"+suite+"-final"); err != nil {
				return err
			}
		}
	}
	return nil
}

type podState struct {
	UID      types.UID        `json:"uid"`
	Phase    corev1.PodPhase  `json:"phase"`
	Restarts map[string]int32 `json:"restarts"`
}

func podStates(pods *corev1.PodList) map[string]podState {
	states := map[string]podState{}
	for _, pod := range pods.Items {
		state := podState{UID: pod.UID, Phase: pod.Status.Phase, Restarts: map[string]int32{}}
		for _, container := range append(pod.Status.ContainerStatuses, pod.Status.InitContainerStatuses...) {
			state.Restarts[container.Name] = container.RestartCount
		}
		states[pod.Namespace+"/"+pod.Name] = state
	}
	return states
}

func (r *runner) checkOriginalPods(ctx context.Context) error {
	after, err := r.kube.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	if err = r.save("final-pods.json", after); err != nil {
		return err
	}
	beforeStates, afterStates := podStates(r.before), podStates(after)
	changes := map[string]any{}
	additional := []string{}
	for name, before := range beforeStates {
		after, found := afterStates[name]
		if !found || !reflect.DeepEqual(before, after) {
			changes[name] = map[string]any{"before": before, "after": after}
		}
	}
	for name := range afterStates {
		if r.cfg.KeepNamespace && strings.HasPrefix(name, r.cfg.Namespace+"/") {
			continue
		}
		if _, found := beforeStates[name]; !found {
			additional = append(additional, name)
		}
	}
	deletedNamespace, retainedNamespace := r.cfg.Namespace, ""
	if r.cfg.KeepNamespace {
		deletedNamespace, retainedNamespace = "", r.cfg.Namespace
	}
	if err = r.save("cleanup.json", map[string]any{
		"deleted_namespace":    deletedNamespace,
		"retained_namespace":   retainedNamespace,
		"original_pods":        len(beforeStates),
		"remaining_pods":       len(afterStates),
		"original_pod_changes": changes,
		"additional_pods":      additional,
	}); err != nil {
		return err
	}
	if len(changes) > 0 || len(additional) > 0 {
		return fmt.Errorf("cluster Pod inventory changed; see cleanup.json")
	}
	return nil
}

func (r *runner) watchers(ctx context.Context) (watcherStats, error) {
	var stats watcherStats
	data, err := r.get(ctx, "http://watchers:8081/stats", "porter-0")
	if err == nil {
		err = json.Unmarshal(data, &stats)
	}
	return stats, err
}

func (r *runner) waitWatchers(ctx context.Context, resources, transforms int) (watcherStats, error) {
	var stats watcherStats
	err := wait.PollUntilContextTimeout(
		ctx,
		200*time.Millisecond,
		90*time.Second,
		true,
		func(ctx context.Context) (bool, error) {
			var err error
			stats, err = r.watchers(ctx)
			return stats.Ready == r.cfg.Workloads/500 && stats.Resources == resources &&
				stats.Transforms >= transforms, err
		},
	)
	if err != nil {
		return stats, fmt.Errorf("WDS did not converge (%+v): %w", stats, err)
	}
	return stats, nil
}

func (r *runner) snapshot(ctx context.Context, prefix string) error {
	pods, err := r.kube.CoreV1().Pods(r.cfg.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	if err = r.save(prefix+".pods.json", pods); err != nil {
		return err
	}
	watchers, err := r.watchers(ctx)
	if err != nil {
		return err
	}
	snapshotTime := unixNow()
	ads := map[string]json.RawMessage{}
	for _, pod := range pods.Items {
		if !strings.HasPrefix(pod.Name, "ads-") {
			continue
		}
		data, err := r.get(ctx, "http://"+pod.Name+":8080/stats", "porter-0")
		if err != nil {
			return err
		}
		ads[strings.TrimPrefix(pod.Name, "ads-")] = data
		data, err = r.get(ctx, "http://"+pod.Name+":8080/metrics", "porter-0")
		if err != nil {
			return err
		}
		if err = r.write(prefix+"."+pod.Name+".metrics", data); err != nil {
			return err
		}
	}
	for i := range r.cfg.Gateways {
		name := fmt.Sprintf("porter-%d", i)
		data, err := r.get(ctx, "http://127.0.0.1:9004/metrics", name)
		if err != nil {
			return err
		}
		if err = r.write(prefix+"."+name+".metrics", data); err != nil {
			return err
		}
	}
	return r.save(prefix+".snapshot.json", map[string]any{
		"time":     snapshotTime,
		"ads":      ads,
		"watchers": watchers,
	})
}

func unixNow() float64 {
	return float64(time.Now().UnixNano()) / 1e9
}

type phase struct {
	Label       string
	Count       int
	Active      int
	Offset      int
	Concurrency int
	Rate        int
	Mode        string
	Revision    int
	Deleted     int
	Trigger     func(context.Context) (any, error)
	Start       int64
	Concurrent  bool
}

func (r *runner) phase(ctx context.Context, p phase) error {
	if p.Count == 0 {
		p.Count = r.cfg.Workloads
	}
	if p.Active == 0 {
		p.Active = r.cfg.Workloads / r.cfg.Gateways
	}
	if p.Concurrency == 0 {
		p.Concurrency = 32
	}
	if p.Mode == "" {
		p.Mode = "workload"
	}
	if p.Count%r.cfg.Gateways != 0 || p.Rate%r.cfg.Gateways != 0 {
		return fmt.Errorf("phase counts and rates must divide across gateways")
	}
	name := r.variant.Name + "-" + p.Label
	if err := r.snapshot(ctx, name+".before"); err != nil {
		return err
	}
	if p.Start == 0 {
		p.Start = int64(math.Ceil(unixNow())) + int64(r.cfg.PrepareSeconds)
	}
	duration := 180
	if p.Rate > 0 {
		duration = max(90, int(math.Ceil(float64(p.Count)/float64(p.Rate)))+15)
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(duration+r.cfg.PrepareSeconds+120)*time.Second)
	defer cancel()
	group, workCtx := errgroup.WithContext(ctx)
	values := make([]worker, r.cfg.Gateways)
	for i := range r.cfg.Gateways {
		group.Go(func() error {
			return r.runWorker(workCtx, p, duration, name, i, &values[i])
		})
	}
	if p.Trigger != nil {
		group.Go(func() error {
			return r.triggerPhase(workCtx, p, name)
		})
	}
	if err := group.Wait(); err != nil {
		return err
	}
	// Snapshots retain parent cancellation after the worker group finishes.
	afterCtx, afterCancel := context.WithTimeout(ctx, 60*time.Second)
	defer afterCancel()
	result := summary{
		Name:       name,
		Variant:    r.variant.Name,
		Phase:      p.Label,
		Concurrent: p.Concurrent,
		Planned:    p.Count,
		Rate:       p.Rate,
	}
	start, finish := math.Inf(1), float64(0)
	for _, value := range values {
		v := value.Result
		result.Results = append(result.Results, v)
		result.Operations += v.Operations
		result.Errors += v.Errors
		if v.RunError != "" {
			result.RunErrors = append(result.RunErrors, v.RunError)
		}
		result.P99 = max(result.P99, v.P99MS)
		result.Max = max(result.Max, v.MaxMS)
		start = min(start, v.StartedUnix)
		finish = max(finish, v.FinishedUnix)
	}
	result.QPS = float64(result.Operations) / (finish - start)
	if err := r.save(name+".summary.json", result); err != nil {
		return err
	}
	r.mu.Lock()
	r.phases = append(r.phases, name)
	r.mu.Unlock()
	if err := r.snapshot(afterCtx, name+".after"); err != nil {
		return err
	}
	if p.Trigger != nil {
		if err := r.logs(afterCtx, name); err != nil {
			return err
		}
	}
	if result.Operations != p.Count || result.Errors != 0 || len(result.RunErrors) > 0 {
		return fmt.Errorf(
			"failed phase %s: completed %d/%d, errors %d, run errors %v",
			name,
			result.Operations,
			p.Count,
			result.Errors,
			result.RunErrors,
		)
	}
	result.Results = nil
	return json.NewEncoder(os.Stdout).Encode(result)
}

func (r *runner) runWorker(
	ctx context.Context,
	p phase,
	duration int,
	name string,
	i int,
	value *worker,
) (result error) {
	args := []string{
		"/bench",
		"client",
		fmt.Sprintf("--active=%d", p.Active),
		fmt.Sprintf("--offset=%d", p.Offset+i*(r.cfg.Workloads/r.cfg.Gateways)),
		fmt.Sprintf("--requests=%d", p.Count/r.cfg.Gateways),
		fmt.Sprintf("--concurrency=%d", p.Concurrency),
		"--mode=" + p.Mode,
		fmt.Sprintf("--rate=%d", p.Rate/r.cfg.Gateways),
		fmt.Sprintf("--revision=%d", p.Revision),
		fmt.Sprintf("--deleted=%d", p.Deleted),
		fmt.Sprintf("--duration=%ds", duration),
		fmt.Sprintf("--start-unix=%d", p.Start),
		"--porter-executable=" + r.variant.Command,
	}
	base := filepath.Join(r.cfg.Output, fmt.Sprintf("%s.porter-%d", name, i))
	stdout, err := os.Create(base + ".json")
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, stdout.Close()) }()
	stderr, err := os.Create(base + ".stderr")
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, stderr.Close()) }()
	if err = r.exec(ctx, fmt.Sprintf("porter-%d", i), args, stdout, stderr); err != nil {
		return fmt.Errorf("worker %d: %w (see %s.stderr)", i, err, base)
	}
	return readJSON(base+".json", value)
}

func (r *runner) triggerPhase(ctx context.Context, p phase, name string) error {
	err := wait.PollUntilContextTimeout(
		ctx,
		100*time.Millisecond,
		time.Until(time.Unix(p.Start+10, 0)),
		true,
		func(context.Context) (bool, error) {
			for i := range r.cfg.Gateways {
				data, err := os.ReadFile(
					filepath.Join(r.cfg.Output, fmt.Sprintf("%s.porter-%d.stderr", name, i)),
				)
				if errors.Is(err, os.ErrNotExist) {
					return false, nil
				}
				if err != nil {
					return false, err
				}
				if !strings.Contains(string(data), "LOAD_STARTED") {
					return false, nil
				}
			}
			return true, nil
		},
	)
	if err != nil {
		return fmt.Errorf("load did not start on schedule: %w", err)
	}
	if err = pause(ctx, 2*time.Second); err != nil {
		return err
	}
	start := unixNow()
	result, err := p.Trigger(ctx)
	return errors.Join(
		err,
		r.save(name+".trigger.json", map[string]any{"started": start, "finished": unixNow(), "result": result}),
	)
}

func pause(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func readJSON(path string, value any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(data, value); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}
