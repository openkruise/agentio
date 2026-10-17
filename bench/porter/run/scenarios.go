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
	"fmt"
	"maps"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func startup(url string) *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler:     corev1.ProbeHandler{Exec: &corev1.ExecAction{Command: []string{"/bench", "get", url}}},
		PeriodSeconds:    1,
		FailureThreshold: 180,
	}
}

func (r *runner) setup(ctx context.Context) error {
	pods, err := r.kube.CoreV1().Pods(r.cfg.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, pod := range pods.Items {
		if err = r.deletePod(ctx, pod.Name); err != nil {
			return err
		}
	}
	for i := range r.cfg.ControlPlanes {
		name := fmt.Sprintf("ads-%d", i)
		container := r.container(
			"ads",
			[]string{"server", fmt.Sprintf("--resources=%d", r.cfg.Workloads)},
			r.cfg.CPCPU,
			r.cfg.CPMemory,
			r.cfg.ControlPlaneImage,
			"/bench",
			map[string]string{"AGENTIO_MAX_REQUESTS_PER_SECOND": strconv.FormatFloat(r.cfg.AdmissionRate, 'g', -1, 64)},
		)
		container.StartupProbe = startup("http://127.0.0.1:8080/stats")
		if err = r.pod(
			ctx,
			name,
			[]corev1.Container{container},
			false,
			map[string]string{"app": "ads", "instance": name},
		); err != nil {
			return err
		}
	}
	watcherArgs := []string{"watchers", fmt.Sprintf("--resources=%d", r.cfg.Workloads)}
	if slices.Contains(r.cfg.Suites, "controlplane") {
		watcherArgs = append(watcherArgs, "--observe-updates")
	}
	container := r.container(
		"watchers",
		watcherArgs,
		2,
		"2Gi",
		"",
		"/bench",
		nil,
	)
	container.StartupProbe = startup("http://127.0.0.1:8081/stats")
	if err = r.pod(
		ctx,
		"watchers",
		[]corev1.Container{container},
		false,
		map[string]string{"instance": "watchers"},
	); err != nil {
		return err
	}
	if err = r.reset(ctx, 2*r.cfg.Workloads+1000, "30m", false); err != nil {
		return err
	}
	_, err = r.waitWatchers(ctx, r.cfg.Workloads, 0)
	return err
}

func (r *runner) reset(ctx context.Context, capacity int, ttl string, service bool) error {
	group, ctx := errgroup.WithContext(ctx)
	for i := range r.cfg.Gateways {
		group.Go(func() error {
			name := fmt.Sprintf("porter-%d", i)
			if err := r.deletePod(ctx, name); err != nil {
				return err
			}
			address := fmt.Sprintf("ads-%d", i%r.cfg.ControlPlanes)
			if service {
				address = "ads"
			}
			env := map[string]string{"TOKIO_WORKER_THREADS": strconv.Itoa(r.cfg.PorterCPU)}
			maps.Copy(env, r.variant.Env)
			container := r.container(
				"porter",
				[]string{
					"--xds-address=" + address + ":15012",
					"--xds-root-path=/tls/ca.pem",
					"--xds-token-path=/tls/token",
					fmt.Sprintf("--xds-cache-max-entries=%d", capacity),
					"--xds-cache-idle-ttl=" + ttl,
				},
				r.cfg.PorterCPU,
				r.cfg.PorterMemory,
				r.variant.Image,
				r.variant.Command,
				env,
			)
			for _, field := range [][2]string{{"POD_NAME", "metadata.name"}, {"POD_NAMESPACE", "metadata.namespace"}, {"POD_UID", "metadata.uid"}, {"POD_IP", "status.podIP"}} {
				container.Env = append(container.Env, corev1.EnvVar{
					Name:      field[0],
					ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: field[1]}},
				})
			}
			container.ReadinessProbe = &corev1.Probe{
				ProbeHandler:  corev1.ProbeHandler{GRPC: &corev1.GRPCAction{Port: 9003, Service: new("readiness")}},
				PeriodSeconds: 1,
			}
			loader := r.container("load", []string{"idle"}, r.cfg.LoadCPU, "2Gi", "", "/bench", nil)
			return r.pod(ctx, name, []corev1.Container{container, loader}, true, nil)
		})
	}
	return group.Wait()
}

func (r *runner) reconnect(ctx context.Context) (any, error) {
	before, err := r.watchers(ctx)
	if err != nil {
		return nil, err
	}
	start := time.Now()
	closed := make([]json.RawMessage, r.cfg.ControlPlanes)
	group, workCtx := errgroup.WithContext(ctx)
	for i := range r.cfg.ControlPlanes {
		group.Go(func() error {
			data, err := r.get(workCtx, fmt.Sprintf("http://ads-%d:8080/disconnect", i), "porter-0")
			if err == nil {
				err = json.Unmarshal(data, &closed[i])
			}
			return err
		})
	}
	if err = group.Wait(); err != nil {
		return nil, err
	}
	watchers, err := r.waitWatchers(ctx, r.cfg.Workloads, before.Transforms+r.cfg.Workloads)
	return map[string]any{
		"disconnected":            closed,
		"wds_resync_seconds":      time.Since(start).Seconds(),
		"poll_resolution_seconds": .2,
		"watchers":                watchers,
	}, err
}

func (r *runner) mutate(ctx context.Context, count, revision int, deleted bool) (any, error) {
	before, err := r.watchers(ctx)
	if err != nil {
		return nil, err
	}
	expected, transforms := r.cfg.Workloads, before.Transforms+count
	if deleted {
		expected = before.Resources - count
		transforms = before.Transforms
	}
	published := make([]json.RawMessage, r.cfg.ControlPlanes)
	group, workCtx := errgroup.WithContext(ctx)
	for i := range r.cfg.ControlPlanes {
		group.Go(func() error {
			url := fmt.Sprintf("http://ads-%d:8080/mutate?count=%d&revision=%d&delete=%t", i, count, revision, deleted)
			data, err := r.get(workCtx, url, "porter-0")
			if err != nil {
				return err
			}
			var inventory struct {
				Workloads int `json:"workloads_after"`
			}
			if err = json.Unmarshal(data, &inventory); err != nil {
				return err
			}
			if inventory.Workloads != expected {
				return fmt.Errorf("wrong published inventory: %d != %d", inventory.Workloads, expected)
			}
			published[i] = data
			return nil
		})
	}
	if err = group.Wait(); err != nil {
		return nil, err
	}
	watchers, err := r.waitWatchers(ctx, expected, transforms)
	return map[string]any{"published": published, "watchers": watchers}, err
}

func (r *runner) phasesInOrder(ctx context.Context, phases ...phase) error {
	for _, p := range phases {
		if err := r.phase(ctx, p); err != nil {
			return err
		}
	}
	return nil
}

func (r *runner) reconnectSuite(ctx context.Context) error {
	if err := r.phase(ctx, phase{Label: "cold", Concurrency: 1024}); err != nil {
		return err
	}
	for i := range r.cfg.Trials {
		if err := r.phasesInOrder(ctx,
			phase{Label: fmt.Sprintf("hot-%d", i+1), Count: r.cfg.HotRequests},
			phase{
				Label:       fmt.Sprintf("reconnect-%d", i+1),
				Count:       r.cfg.ReconnectRequests,
				Concurrency: 128,
				Rate:        r.cfg.HotRate,
				Trigger:     r.reconnect,
			},
		); err != nil {
			return err
		}
	}
	return r.phase(ctx, phase{Label: "verify-reconnect"})
}

func (r *runner) checkCache(ctx context.Context, label string, maximum float64) error {
	entries := []float64{}
	for i := range r.cfg.Gateways {
		data, err := r.get(ctx, "http://127.0.0.1:9004/metrics", fmt.Sprintf("porter-%d", i))
		if err != nil {
			return err
		}
		found := false
		for line := range strings.SplitSeq(string(data), "\n") {
			if !strings.HasPrefix(line, "agentio_porter_demand_cache_entries ") {
				continue
			}
			value, err := strconv.ParseFloat(strings.TrimPrefix(line, "agentio_porter_demand_cache_entries "), 64)
			if err != nil {
				return err
			}
			if found || value > maximum {
				return fmt.Errorf("%s porter-%d: cache %g exceeds %g or duplicated", label, i, value, maximum)
			}
			found = true
			entries = append(entries, value)
		}
		if !found {
			return fmt.Errorf("%s: missing cache metric", label)
		}
	}
	return r.save(r.variant.Name+"-"+label+".cache.json", map[string]any{"maximum": maximum, "entries": entries})
}

func (r *runner) mixed(
	ctx context.Context,
	prefix string,
	seconds int,
	trigger func(context.Context) (any, error),
) error {
	start := int64(math.Ceil(unixNow())) + int64(r.cfg.PrepareSeconds) + 5
	group, ctx := errgroup.WithContext(ctx)
	group.Go(func() error {
		return r.phase(ctx, phase{
			Label:       prefix + "-hot",
			Count:       r.cfg.HotRate * seconds,
			Active:      1000,
			Concurrency: 128,
			Rate:        r.cfg.HotRate,
			Start:       start,
			Concurrent:  true,
			Trigger:     trigger,
		})
	})
	group.Go(func() error {
		return r.phase(ctx, phase{
			Label:       prefix + "-cold",
			Count:       r.cfg.ColdRate * seconds,
			Active:      r.cfg.Workloads/r.cfg.Gateways - 1000,
			Offset:      1000,
			Concurrency: 1024,
			Rate:        r.cfg.ColdRate,
			Start:       start,
			Concurrent:  true,
		})
	})
	return group.Wait()
}

func (r *runner) mixedSuite(ctx context.Context) error {
	if err := r.reset(ctx, 10000, "1m", false); err != nil {
		return err
	}
	for _, p := range []phase{{Label: "bounded-cold", Concurrency: 1024}, {Label: "bounded-rescan"}} {
		if err := r.phase(ctx, p); err != nil {
			return err
		}
		if err := r.checkCache(ctx, p.Label, 10000); err != nil {
			return err
		}
	}
	if err := r.reset(ctx, 10000, "1m", false); err != nil {
		return err
	}
	if err := r.phase(
		ctx,
		phase{Label: "mixed-warmup", Count: 1000 * r.cfg.Gateways, Active: 1000, Concurrency: 8},
	); err != nil {
		return err
	}
	if err := r.mixed(ctx, "mixed", r.cfg.MixedSeconds, nil); err != nil {
		return err
	}
	return r.checkCache(ctx, "mixed", 10000)
}

func (r *runner) lifecycleSuite(ctx context.Context) error {
	if err := r.reset(ctx, 2*r.cfg.Workloads+1000, "30m", false); err != nil {
		return err
	}
	if err := r.phasesInOrder(
		ctx,
		phase{Label: "sandbox-cold", Mode: "sandbox", Concurrency: 128},
		phase{Label: "sandbox-hot", Mode: "sandbox", Count: 2 * r.cfg.Workloads},
	); err != nil {
		return err
	}
	if err := r.reset(ctx, 10000, "1m", false); err != nil {
		return err
	}
	if err := r.phasesInOrder(ctx,
		phase{Label: "update-warmup", Count: 1000 * r.cfg.Gateways, Active: 1000, Concurrency: 8},
		phase{
			Label:       "update",
			Count:       r.cfg.ReconnectRequests,
			Active:      1000,
			Concurrency: 128,
			Rate:        r.cfg.HotRate,
			Revision:    -1,
			Trigger: func(ctx context.Context) (any, error) {
				return r.mutate(ctx, r.cfg.Workloads, 1, false)
			},
		},
		phase{Label: "verify-update", Active: 1000, Revision: 1},
		phase{
			Label:       "hot-reconnect",
			Count:       r.cfg.ReconnectRequests,
			Active:      1000,
			Concurrency: 128,
			Rate:        r.cfg.HotRate,
			Revision:    1,
			Trigger:     r.reconnect,
		},
	); err != nil {
		return err
	}
	if _, err := r.mutate(ctx, 1000, 1, true); err != nil {
		return err
	}
	if err := r.phase(ctx, phase{Label: "verify-delete", Active: 1000, Revision: 1, Deleted: 1000}); err != nil {
		return err
	}
	if _, err := r.mutate(ctx, 1000, 1, false); err != nil {
		return err
	}
	if err := r.phase(ctx, phase{Label: "verify-restore", Active: 1000, Revision: 1}); err != nil {
		return err
	}
	if err := r.reset(ctx, 10000, "2s", false); err != nil {
		return err
	}
	if err := r.phase(
		ctx,
		phase{Label: "ttl-warmup", Count: 1000 * r.cfg.Gateways, Active: 1000, Concurrency: 8, Revision: 1},
	); err != nil {
		return err
	}
	if err := pause(ctx, 3*time.Second); err != nil {
		return err
	}
	if err := r.snapshot(ctx, r.variant.Name+"-ttl-expired"); err != nil {
		return err
	}
	if err := r.checkCache(ctx, "ttl-expired", 0); err != nil {
		return err
	}
	return r.phase(
		ctx,
		phase{Label: "ttl-reload", Count: 1000 * r.cfg.Gateways, Active: 1000, Concurrency: 8, Revision: 1},
	)
}

func (r *runner) failoverSuite(ctx context.Context) error {
	if err := r.reset(ctx, 10000, "1m", true); err != nil {
		return err
	}
	if err := r.phase(
		ctx,
		phase{Label: "failover-warmup", Count: 1000 * r.cfg.Gateways, Active: 1000, Concurrency: 8},
	); err != nil {
		return err
	}
	return r.mixed(ctx, "failover", 60, func(ctx context.Context) (any, error) {
		start := time.Now()
		target, connections, err := r.deleteServingControlPlane(ctx)
		if err != nil {
			return nil, err
		}
		watchers, err := r.waitWatchers(ctx, r.cfg.Workloads, 0)
		return map[string]any{
			"target":               target,
			"porter_connections":   connections,
			"wds_recovery_seconds": time.Since(start).Seconds(),
			"watchers":             watchers,
		}, err
	})
}

// Service routing is random. Deleting a fixed replica can leave every Porter
// connected and turn the failover test into a WDS-only disruption.
func (r *runner) deleteServingControlPlane(ctx context.Context) (string, float64, error) {
	var target string
	var connections float64
	for i := range r.cfg.ControlPlanes {
		name := fmt.Sprintf("ads-%d", i)
		data, err := r.get(ctx, "http://"+name+":8080/metrics", "porter-0")
		if err != nil {
			return "", 0, err
		}
		count, err := metric(string(data), `agentio_xds_connections_by_class{class="agentio-egress"}`)
		if err != nil {
			return "", 0, err
		}
		if count > connections {
			target, connections = name, count
		}
	}
	if target == "" {
		return "", 0, fmt.Errorf("failover requires a control plane serving Porter connections")
	}
	return target, connections, r.deletePod(ctx, target)
}
