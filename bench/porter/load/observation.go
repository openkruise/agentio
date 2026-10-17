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
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/anypb"

	ext "github.com/openkruise/agentio/api/extensions/v1"
	workload "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/xdsclient"
)

type observedResource struct {
	Index    int
	Revision int
	Received time.Time
}

func observedWorkload(value *anypb.Any) (any, error) {
	var address workload.Address
	if err := value.UnmarshalTo(&address); err != nil {
		return nil, err
	}
	w := address.GetWorkload()
	index, err := strconv.Atoi(strings.TrimPrefix(w.GetName(), "workload-"))
	if err != nil {
		return nil, err
	}
	for _, extension := range w.GetExtensions() {
		if extension.GetName() != "metadata" {
			continue
		}
		var metadata ext.WorkloadMetadata
		if err := extension.GetConfig().UnmarshalTo(&metadata); err != nil {
			return nil, err
		}
		revision, err := strconv.Atoi(metadata.Labels["revision"])
		if err != nil {
			return nil, err
		}
		return observedResource{Index: index, Revision: revision, Received: time.Now()}, nil
	}
	return nil, fmt.Errorf("workload %s lacks benchmark revision", w.GetName())
}

type observations struct {
	mu       sync.Mutex
	wake     chan struct{}
	start    time.Time
	count    int
	revision int
	deleted  bool
	fresh    bool
	times    []float64
}

func newObservations(clients int) *observations {
	return &observations{wake: make(chan struct{}), times: make([]float64, clients)}
}

func (o *observations) arm(w http.ResponseWriter, r *http.Request) {
	count, err := strconv.Atoi(r.URL.Query().Get("count"))
	if err != nil || count <= 0 || count > len(o.times)*500 {
		http.Error(w, "invalid count", 400)
		return
	}
	revision, err := strconv.Atoi(r.URL.Query().Get("revision"))
	if err != nil {
		http.Error(w, "invalid revision", 400)
		return
	}
	o.mu.Lock()
	o.start, o.count, o.revision = time.Now(), count, revision
	o.deleted, o.fresh = r.URL.Query().Get("delete") == "true", r.URL.Query().Get("fresh") == "true"
	clear(o.times)
	close(o.wake)
	o.wake = make(chan struct{})
	o.mu.Unlock()
	writeResponse(w, o.snapshot())
}

func (o *observations) watch(ctx context.Context, node int, client *xdsclient.Client) {
	for {
		// Capture the observation notification before the client snapshot so arming
		// cannot be lost between checking state and waiting for the next change.
		o.mu.Lock()
		wake := o.wake
		o.mu.Unlock()
		state := client.Snapshot()
		o.mu.Lock()
		if !o.start.IsZero() && node*500 < o.count && o.times[node] == 0 && state.Connected &&
			state.Synced[model.AddressType] {
			affected := min(500, o.count-node*500)
			expected := 500
			if o.deleted {
				expected -= affected
			}
			resources := state.Resources[model.AddressType]
			ready := len(resources) == expected
			for _, resource := range resources {
				value := resource.Value.(observedResource)
				if value.Index < o.count &&
					(o.deleted || (o.revision >= 0 && value.Revision != o.revision) || (o.fresh && value.Received.Before(o.start))) {
					ready = false
					break
				}
			}
			if ready {
				o.times[node] = time.Since(o.start).Seconds()
			}
		}
		o.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-state.Changed:
		case <-wake:
		}
	}
}

func (o *observations) snapshot() any {
	o.mu.Lock()
	defer o.mu.Unlock()
	completed := 0
	participants := (o.count + 499) / 500
	for _, t := range o.times[:participants] {
		if t > 0 {
			completed++
		}
	}
	return map[string]any{
		"started_unix":   float64(o.start.UnixNano()) / 1e9,
		"count":          o.count,
		"revision":       o.revision,
		"participants":   participants,
		"completed":      completed,
		"client_seconds": append([]float64(nil), o.times[:participants]...),
	}
}

func cgroupCPU() map[string]uint64 {
	// The benchmark requires Linux Kubernetes nodes with cgroup v2.
	data, err := os.ReadFile("/sys/fs/cgroup/cpu.stat")
	must(err)
	result := map[string]uint64{}
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		must(err)
		result[fields[0]] = value
	}
	return result
}
