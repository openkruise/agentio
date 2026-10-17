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
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sync/errgroup"
	"k8s.io/apimachinery/pkg/util/wait"
)

type convergence struct {
	Observation struct {
		Participants int       `json:"participants"`
		Completed    int       `json:"completed"`
		Times        []float64 `json:"client_seconds"`
	} `json:"observation"`
}

func (r *runner) observedChange(ctx context.Context, count, revision int, deleted, reconnect bool) (any, error) {
	arm := fmt.Sprintf(
		"http://watchers:8081/observe?count=%d&revision=%d&delete=%t&fresh=%t",
		count,
		revision,
		deleted,
		reconnect,
	)
	armed, err := r.get(ctx, arm, "porter-0")
	if err != nil {
		return nil, err
	}
	group, workCtx := errgroup.WithContext(ctx)
	published := make([]json.RawMessage, r.cfg.ControlPlanes)
	for i := range r.cfg.ControlPlanes {
		group.Go(func() error {
			url := fmt.Sprintf("http://ads-%d:8080/mutate?count=%d&revision=%d&delete=%t", i, count, revision, deleted)
			if reconnect {
				url = fmt.Sprintf("http://ads-%d:8080/disconnect", i)
			}
			data, err := r.get(workCtx, url, "porter-0")
			published[i] = data
			return err
		})
	}
	if err = group.Wait(); err != nil {
		return nil, err
	}
	var result convergence
	err = wait.PollUntilContextTimeout(
		ctx,
		200*time.Millisecond,
		90*time.Second,
		true,
		func(ctx context.Context) (bool, error) {
			data, err := r.get(ctx, "http://watchers:8081/stats", "porter-0")
			if err != nil {
				return false, err
			}
			if err = json.Unmarshal(data, &result); err != nil {
				return false, err
			}
			return result.Observation.Participants > 0 &&
				result.Observation.Completed == result.Observation.Participants, nil
		},
	)
	return map[string]any{
		"armed":       json.RawMessage(armed),
		"published":   published,
		"convergence": result.Observation,
	}, err
}

func (r *runner) cpAction(ctx context.Context, label string, action func(context.Context) (any, error)) error {
	name := r.variant.Name + "-" + label
	if err := r.snapshot(ctx, name+".before"); err != nil {
		return err
	}
	started := unixNow()
	result, err := action(ctx)
	return errors.Join(
		err,
		r.save(name+".controlplane.json", map[string]any{"started": started, "finished": unixNow(), "result": result}),
		r.snapshot(ctx, name+".after"),
	)
}

func (r *runner) cpMixed(
	ctx context.Context,
	label string,
	seconds int,
	trigger func(context.Context) (any, error),
) error {
	name := r.variant.Name + "-" + label
	if err := r.snapshot(ctx, name+".before"); err != nil {
		return err
	}
	start := int64(unixNow()) + int64(r.cfg.PrepareSeconds) + 6
	group, workCtx := errgroup.WithContext(ctx)
	for _, cold := range []bool{false, true} {
		group.Go(func() error {
			p := phase{
				Label:       label + "-hot",
				Count:       r.cfg.HotRate * seconds,
				Active:      1000,
				Concurrency: 128,
				Rate:        r.cfg.HotRate,
				Revision:    -1,
				Start:       start,
				Concurrent:  true,
				Trigger:     trigger,
			}
			if cold {
				p.Label = label + "-cold"
				p.Count = r.cfg.ColdRate * seconds
				p.Active = r.cfg.Workloads/r.cfg.Gateways - 1000
				p.Offset = 1000
				p.Concurrency = 1024
				p.Rate = r.cfg.ColdRate
				p.Trigger = nil
			}
			return r.phase(workCtx, p)
		})
	}
	err := group.Wait()
	return errors.Join(err, r.snapshot(ctx, name+".after"))
}

func (r *runner) controlPlaneSuite(ctx context.Context) error {
	for trial := range r.cfg.Trials {
		if trial > 0 {
			if err := r.setup(ctx); err != nil {
				return err
			}
		}
		if err := r.controlPlaneTrial(ctx, trial); err != nil {
			return err
		}
	}
	return nil
}

func (r *runner) controlPlaneTrial(ctx context.Context, trial int) error {
	var failures []error
	// A failed request phase is useful regression evidence. Preserve its complete
	// summary and continue independent scenarios; infrastructure errors still stop.
	runPhase := func(p phase) error {
		err := r.phase(ctx, p)
		if err == nil {
			return nil
		}
		if _, statErr := os.Stat(
			filepath.Join(r.cfg.Output, r.variant.Name+"-"+p.Label+".summary.json"),
		); statErr != nil {
			return err
		}
		failures = append(failures, err)
		return nil
	}
	prefix := fmt.Sprintf("cp-%d", trial)
	if err := r.cpWDS(ctx, prefix); err != nil {
		return err
	}
	if err := runPhase(phase{Label: prefix + "-full-cold", Concurrency: 1024, Revision: 3}); err != nil {
		return err
	}
	if err := runPhase(
		phase{
			Label:       prefix + "-full-reconnect",
			Count:       r.cfg.HotRate * 30,
			Rate:        r.cfg.HotRate,
			Concurrency: 1024,
			Revision:    3,
			Trigger:     func(ctx context.Context) (any, error) { return r.observedChange(ctx, r.cfg.Workloads, 3, false, true) },
		},
	); err != nil {
		return err
	}
	if err := r.reset(ctx, 10000, "1m", false); err != nil {
		return err
	}
	for _, suffix := range []string{"bounded-fill", "bounded-rescan"} {
		if err := runPhase(phase{Label: prefix + "-" + suffix, Concurrency: 32, Revision: 3}); err != nil {
			return err
		}
	}
	if err := r.reset(ctx, 10000, "1m", false); err != nil {
		return err
	}
	if err := runPhase(
		phase{Label: prefix + "-mixed-warmup", Count: 4000, Active: 1000, Concurrency: 8, Revision: 3},
	); err != nil {
		return err
	}
	// Measure plain mixed load and then repeated WDS updates under identical load.
	for _, updates := range []bool{false, true} {
		label := prefix + "-mixed"
		var trigger func(context.Context) (any, error)
		if updates {
			label += "-updates"
			trigger = r.cpUpdates
		}
		if err := r.cpMixed(ctx, label, r.cfg.MixedSeconds, trigger); err != nil {
			failures = append(failures, err)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	if err := r.cpMixed(
		ctx,
		prefix+"-mixed-reconnect",
		30,
		func(ctx context.Context) (any, error) { return r.observedChange(ctx, r.cfg.Workloads, 6, false, true) },
	); err != nil {
		failures = append(failures, err)
	}
	if r.cfg.ControlPlanes > 1 {
		if err := r.cpFailover(ctx, prefix); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (r *runner) cpWDS(ctx context.Context, prefix string) error {
	// No Porter requests yet: measure ordinary WDS independently of demand.
	for step, count := range []int{500, 5000, r.cfg.Workloads} {
		revision := step + 1
		if err := r.cpAction(
			ctx,
			fmt.Sprintf("%s-wds-update-%d", prefix, count),
			func(ctx context.Context) (any, error) { return r.observedChange(ctx, count, revision, false, false) },
		); err != nil {
			return err
		}
	}
	if err := r.cpAction(
		ctx,
		prefix+"-wds-reconnect",
		func(ctx context.Context) (any, error) { return r.observedChange(ctx, r.cfg.Workloads, 3, false, true) },
	); err != nil {
		return err
	}
	for _, deleted := range []bool{true, false} {
		label := "restore"
		if deleted {
			label = "delete"
		}
		if err := r.cpAction(
			ctx,
			prefix+"-wds-"+label,
			func(ctx context.Context) (any, error) { return r.observedChange(ctx, 1000, 3, deleted, false) },
		); err != nil {
			return err
		}
	}

	return nil
}

func (r *runner) cpFailover(ctx context.Context, prefix string) error {

	if err := r.reset(ctx, 10000, "1m", true); err != nil {
		return err
	}
	if err := r.phase(
		ctx,
		phase{Label: prefix + "-failover-warmup", Count: 4000, Active: 1000, Concurrency: 8, Revision: 6},
	); err != nil {
		return err
	}
	if err := r.cpMixed(ctx, prefix+"-failover", 30, func(ctx context.Context) (any, error) {
		started := time.Now()
		target, connections, err := r.deleteServingControlPlane(ctx)
		if err != nil {
			return nil, err
		}
		stats, err := r.waitWatchers(ctx, r.cfg.Workloads, 0)
		return map[string]any{
			"target":             target,
			"porter_connections": connections,
			"seconds":            time.Since(started).Seconds(),
			"watchers":           stats,
		}, err
	}); err != nil {
		return err
	}
	return nil
}

func (r *runner) cpUpdates(ctx context.Context) (any, error) {
	results := []any{}
	for revision := 4; revision < 7; revision++ {
		result, err := r.observedChange(ctx, r.cfg.Workloads, revision, false, false)
		if err != nil {
			return results, err
		}
		results = append(results, result)
		if err := pause(ctx, 3*time.Second); err != nil {
			return results, err
		}
	}
	return results, nil
}
