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
	"maps"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"time"
)

var boundsMS = histogramBounds()

func histogramBounds() []float64 {
	bounds := make([]float64, 0, 212)
	for i := 1; i <= 200; i++ {
		bounds = append(bounds, float64(i)/10)
	}
	for i := range 12 {
		bounds = append(bounds, 20.48*float64(int64(1)<<i))
	}
	return bounds
}

func ms(span time.Duration) float64 {
	return float64(span) / float64(time.Millisecond)
}

func unixSeconds() float64 {
	return float64(time.Now().UnixNano()) / float64(time.Second)
}

type certificate struct {
	Serial    string        `json:"serialNumber"`
	NotBefore string        `json:"notBefore,omitempty"`
	NotAfter  string        `json:"notAfter"`
	Issuer    [][][2]string `json:"issuer"`
}

type groupStats struct {
	Requests       int            `json:"requests"`
	Errors         int            `json:"errors"`
	Histogram      []int          `json:"histogram"`
	QueueHistogram []int          `json:"queue_histogram"`
	Statuses       map[string]int `json:"statuses"`
	ErrorTypes     map[string]int `json:"error_types"`
}

func (c *client) addSample(sample map[string]any) {
	if len(c.samples) == cap(c.samples) {
		copy(c.samples, c.samples[1:])
		c.samples = c.samples[:len(c.samples)-1]
	}
	c.samples = append(c.samples, sample)
}

func (c *client) record(group, host string, elapsed, queued time.Duration, outcome observation) {
	c.mu.Lock()
	defer c.mu.Unlock()
	data := c.groups[group]
	if data == nil {
		data = &groupStats{
			Histogram:      make([]int, len(boundsMS)+1),
			QueueHistogram: make([]int, len(boundsMS)+1),
			Statuses:       make(map[string]int),
			ErrorTypes:     make(map[string]int),
		}
		c.groups[group] = data
	}
	data.Requests++
	data.Histogram[sort.SearchFloat64s(boundsMS, ms(elapsed))]++
	data.QueueHistogram[sort.SearchFloat64s(boundsMS, ms(queued))]++
	if outcome.status != 0 {
		data.Statuses[strconv.Itoa(outcome.status)]++
	}
	if outcome.cert != nil {
		prior, ok := c.certificates[host]
		c.certificates[host] = *outcome.cert
		if ok && prior.Serial != outcome.cert.Serial {
			c.addSample(map[string]any{
				"time":   unixSeconds(),
				"event":  "leaf-rotated",
				"host":   host,
				"before": prior,
				"after":  *outcome.cert,
			})
		}
	}
	if outcome.err != nil {
		data.Errors++
		data.ErrorTypes[outcome.errorType]++
		var stage any
		if outcome.stage != "" {
			stage = outcome.stage
		}
		c.addSample(map[string]any{
			"time":       unixSeconds(),
			"group":      group,
			"error":      outcome.err.Error(),
			"error_type": outcome.errorType,
			"stage":      stage,
		})
	}
}

type snapshot struct {
	Time         float64                `json:"time"`
	Config       config                 `json:"config"`
	Stopped      bool                   `json:"stopped"`
	Queue        int                    `json:"queue"`
	Bounds       []float64              `json:"bounds_ms"`
	Groups       map[string]groupStats  `json:"groups"`
	DomainsSeen  int                    `json:"domains_seen"`
	Certificates map[string]certificate `json:"certificates"`
	Samples      []map[string]any       `json:"samples"`
}

func (c *client) snapshot() snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	groups := make(map[string]groupStats, len(c.groups))
	for name, group := range c.groups {
		groups[name] = groupStats{
			Requests:       group.Requests,
			Errors:         group.Errors,
			Histogram:      slices.Clone(group.Histogram),
			QueueHistogram: slices.Clone(group.QueueHistogram),
			Statuses:       maps.Clone(group.Statuses),
			ErrorTypes:     maps.Clone(group.ErrorTypes),
		}
	}
	return snapshot{
		Time:         unixSeconds(),
		Config:       c.config,
		Stopped:      c.stopped || (c.runContext != nil && c.runContext.Err() != nil),
		Queue:        c.queue.Pending(),
		Bounds:       boundsMS,
		Groups:       groups,
		DomainsSeen:  len(c.seen),
		Certificates: maps.Clone(c.certificates),
		Samples:      slices.Clone(c.samples),
	}
}

func (c *client) status(w http.ResponseWriter, _ *http.Request) {
	respond(w, http.StatusOK, c.snapshot())
}
