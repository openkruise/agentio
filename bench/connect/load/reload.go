// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strconv"
	"time"
)

type reloadResult struct {
	rows []map[string]any
	err  error
}

func startReloads(ctx context.Context, c config) <-chan reloadResult {
	done := make(chan reloadResult, 1)
	go func() {
		var result reloadResult
		for _, mode := range []string{"rate", "grouping"} {
			if result.err = pause(ctx, c.Duration/3); result.err != nil {
				break
			}
			var row map[string]any
			row, result.err = reload(ctx, c, mode)
			if result.err != nil {
				break
			}
			result.rows = append(result.rows, row)
		}
		done <- result
	}()
	return done
}

// mutatePolicy preserves the resident rate so seeded debt remains resident.
func mutatePolicy(resource map[string]any, mode string) {
	object := func(v any) map[string]any { return v.(map[string]any) }
	extension := object(resource["resources"].([]any)[0])
	module := object(object(extension["typed_config"])["value"])
	policy := object(object(module["filter_config"])["value"])
	descriptors := policy["descriptors"].([]any)
	if mode == "rate" {
		object(object(descriptors[0])["bandwidth_limit"])["download_bytes_per_second"] = "2199023255552"
	} else {
		for _, rule := range policy["rate_limits"].([]any) {
			slices.Reverse(object(rule)["actions"].([]any))
		}
		for _, d := range descriptors {
			slices.Reverse(object(d)["entries"].([]any))
		}
	}
	resource["version_info"] = strconv.FormatInt(time.Now().UnixNano(), 10)
}

func extensionUpdates(ctx context.Context, admin string) (uint64, error) {
	req, err := http.NewRequestWithContext(
		ctx,
		"GET",
		"http://"+admin+"/stats?format=json&filter=extension_config_discovery.*update_success",
		nil,
	)
	if err != nil {
		return 0, err
	}
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	var data struct {
		Stats []struct{ Value uint64 }
	}
	err = errors.Join(json.NewDecoder(response.Body).Decode(&data), response.Body.Close())
	if err != nil {
		return 0, err
	}
	if response.StatusCode != http.StatusOK || len(data.Stats) == 0 {
		return 0, fmt.Errorf("missing ECDS update counters: %s", response.Status)
	}
	var total uint64
	for _, stat := range data.Stats {
		total += stat.Value
	}
	return total, nil
}

func reload(parent context.Context, c config, mode string) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	data, err := os.ReadFile(c.ReloadPath)
	if err != nil {
		return nil, err
	}
	var resource map[string]any
	if err := json.Unmarshal(data, &resource); err != nil {
		return nil, err
	}
	mutatePolicy(resource, mode)
	data, err = json.Marshal(resource)
	if err != nil {
		return nil, err
	}
	before, err := extensionUpdates(ctx, c.Admin)
	if err != nil {
		return nil, err
	}
	started := time.Now()
	if err := os.WriteFile(c.ReloadPath+".new", data, 0600); err != nil {
		return nil, err
	}
	if err := os.Rename(c.ReloadPath+".new", c.ReloadPath); err != nil {
		return nil, err
	}
	for {
		got, err := extensionUpdates(ctx, c.Admin)
		if err != nil {
			return nil, err
		}
		if got > before {
			return map[string]any{"kind": mode, "ecds_observed_ms": time.Since(started).Seconds() * 1000}, nil
		}
		if err := pause(ctx, time.Millisecond); err != nil {
			return nil, fmt.Errorf("waiting for %s policy: %w", mode, err)
		}
	}
}
