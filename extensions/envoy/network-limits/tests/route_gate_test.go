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

package networklimits

import (
	"bytes"
	"fmt"
	"io"
	"testing"
	"time"
)

func TestEnvoyRDSConcurrencyGate(t *testing.T) {
	const name = "agentio.connect_concurrency"
	origin := startOrigin(t, false)
	r := startEnvoyConfig(t, origin.port(), freePort(t), func(l object) {
		concurrencyConfig(t, l, false)
		filter := obj(filters(l)[1])
		filter["disabled"] = true
		policy(filter)["enabled"] = false
		obj(policy(filter)["descriptors"].([]any)[0])["max_concurrent_streams"] = 1
	}, true)
	// Keep one HTTP/2 connection throughout: route updates must affect its new streams.
	c := newClient(t, r.port)
	beforeEnable := c.open(t, "test", "a", "plain:80", 200)
	setEnabled := func(enabled bool) {
		r.reloadECDS(t, name, func(p object) { p["enabled"] = enabled }, false)
	}
	setEnabled(true)
	beforeGate := c.open(t, "test", "a", "plain:80", 200)
	// ECDS alone cannot create a filter for a stream while the route gate is closed.
	finish(t, c.open(t, "test", "", "plain:80", 200))
	r.routeGate(t, name, true)
	managed := c.open(t, "test", "a", "plain:80", 200)
	c.open(t, "test", "a", "plain:80", 429).close()
	c.open(t, "test", "", "plain:80", 403).close()

	// Closing RDS first stops new registrations, while ECDS releases existing limits.
	r.routeGate(t, name, false)
	duringDisable := c.open(t, "test", "a", "plain:80", 200)
	setEnabled(false)
	disabled := c.open(t, "test", "a", "plain:80", 200)
	setEnabled(true)
	r.routeGate(t, name, true)
	// The managed stream remains counted; all streams created with the gate closed do not.
	c.open(t, "test", "a", "plain:80", 429).close()
	managed.close()
	replacement := c.eventuallyOpen(t, "a")
	c.open(t, "test", "a", "plain:80", 429).close()
	for _, s := range []*stream{beforeEnable, beforeGate, duringDisable, disabled, replacement} {
		finish(t, s)
	}
}

func TestEnvoyRDSBandwidthGate(t *testing.T) {
	const name = "agentio.bandwidth"
	origin := startOrigin(t, false)
	r := startEnvoyConfig(t, origin.port(), freePort(t), func(l object) {
		obj(filters(l)[1])["disabled"] = true
		policy(filters(l)[1])["enabled"] = false
	}, true)
	c := newClient(t, r.port)
	old := c.open(t, "test", "a", "plain:80", 200)
	setEnabled := func(enabled bool) {
		r.reloadECDS(t, name, func(p object) { p["enabled"] = enabled }, false)
	}
	download := func(s *stream, slow bool) {
		t.Helper()
		started := time.Now()
		_, err := fmt.Fprintf(s.writer, "D %d\n", size)
		must(t, err)
		data, err := io.ReadAll(s.response.Body)
		must(t, err)
		if !bytes.Equal(data, payload(size)) {
			t.Fatalf("download payload mismatch: received %d bytes", len(data))
		}
		if slow {
			durationBetween(t, time.Since(started), 2.5, 10)
		} else {
			durationBetween(t, time.Since(started), 0, 1.5)
		}
		s.close()
	}
	setEnabled(true)
	r.routeGate(t, name, true)
	download(old, false)
	download(c.open(t, "test", "a", "plain:80", 200), true)

	// Stop a transfer while it is throttled, then disable both the new-stream gate
	// and its policy. ECDS must wake the existing instance and flush its buffered data.
	active := c.open(t, "test", "a", "plain:80", 200)
	_, err := fmt.Fprintf(active.writer, "D %d\n", size)
	must(t, err)
	first := make([]byte, 1)
	_, err = io.ReadFull(active.response.Body, first)
	must(t, err)
	r.routeGate(t, name, false)
	setEnabled(false)
	started := time.Now()
	rest, err := io.ReadAll(active.response.Body)
	must(t, err)
	if !bytes.Equal(append(first, rest...), payload(size)) {
		t.Fatalf("disabled transfer payload mismatch: received %d bytes", len(rest)+1)
	}
	durationBetween(t, time.Since(started), 0, 1.5)
	active.close()

	duringDisable := c.open(t, "test", "a", "plain:80", 200)
	setEnabled(true)
	r.routeGate(t, name, true)
	download(duringDisable, false)
	download(c.open(t, "test", "a", "plain:80", 200), true)
}
