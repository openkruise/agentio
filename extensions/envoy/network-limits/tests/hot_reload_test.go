// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

package networklimits

import (
	"fmt"
	"io"
	"maps"
	"testing"
	"time"
)

func TestEnvoyECDSConcurrencyRules(t *testing.T) {
	var enabled object
	origin := startOrigin(t, false)
	r := startEnvoyConfig(t, origin.port(), freePort(t), func(l object) {
		concurrencyConfig(t, l, false)
		enabled = clone(t, policy(filters(l)[1]))
		nested(filters(l)[1], "typed_config", "value", "filter_config")["value"] = object{
			"enabled":     false,
			"budget_name": enabled["budget_name"],
		}
	}, true)
	a, b := newClient(t, r.port), newClient(t, r.port)
	// These streams stay idle across the update, on both workers.
	a1 := a.open(t, "test", "a", "plain:80", 200)
	a2 := b.open(t, "test", "a", "plain:80", 200)
	b1 := b.open(t, "test", "b", "plain:80", 200)
	update := func(edit func(object)) { r.reloadECDS(t, "agentio.connect_concurrency", edit, false) }
	update(func(p object) {
		maps.Copy(p, enabled)
		p["enabled"] = true
	})
	a.open(t, "test", "a", "plain:80", 429).close()
	a1.close()
	a3 := a.eventuallyOpen(t, "a")
	// Exact override and reordered descriptors must count pre-existing streams.
	update(func(p object) {
		p["descriptors"] = []any{
			object{"entries": []any{object{"key": "sandbox", "value": "a"}}, "max_concurrent_streams": 3},
			obj(p["descriptors"].([]any)[1]), obj(p["descriptors"].([]any)[0]),
		}
	})
	a4 := a.open(t, "test", "a", "plain:80", 200)
	b.open(t, "test", "a", "plain:80", 429).close()
	update(func(p object) { p["descriptors"] = p["descriptors"].([]any)[1:] })
	b.open(t, "test", "a", "plain:80", 429).close() // Removing the override retains over-limit live streams.
	// Regroup by a previously unused identity. All four live streams share tenant=test.
	update(func(p object) {
		p["rate_limits"] = []any{
			object{"actions": []any{object{"filter_state": object{"key": "tenant.id", "descriptor_key": "tenant"}}}},
		}
		p["descriptors"] = []any{object{"entries": []any{object{"key": "tenant"}}, "max_concurrent_streams": 4}}
	})
	b.open(t, "test", "new-sandbox", "plain:80", 429).close()
	// Invalid update cannot mutate the accepted shared policy.
	r.reloadECDS(t, "agentio.connect_concurrency", func(p object) { p["enabled"] = false }, true)
	b.open(t, "test", "new-sandbox", "plain:80", 429).close()
	a2.close()
	replacement := a.eventuallyOpen(t, "new-sandbox")
	update(func(p object) { p["enabled"] = false })
	extra := b.open(t, "test", "extra", "plain:80", 200)
	update(func(p object) { p["enabled"] = true })
	a.open(t, "test", "another", "plain:80", 429).close()
	for _, s := range []*stream{a3, a4, b1, replacement, extra} {
		finish(t, s)
	}
	finish(t, a.eventuallyOpen(t, "after-close"))
}

func TestEnvoyECDSBandwidthExistingStream(t *testing.T) {
	origin := startOrigin(t, false)
	r := startEnvoyConfig(t, origin.port(), freePort(t), func(l object) {
		policy(filters(l)[1])["enabled"] = false
	}, true)
	c := newClient(t, r.port)
	stream := c.open(t, "test", "a", "plain:80", 200)
	r.reloadECDS(t, "agentio.bandwidth", func(p object) { p["enabled"] = true }, false)
	started := time.Now()
	_, err := fmt.Fprintf(stream.writer, "D %d\n", size)
	must(t, err)
	data, err := io.ReadAll(stream.response.Body)
	must(t, err)
	if len(data) != size {
		t.Fatalf("received %d bytes, want %d", len(data), size)
	}
	durationBetween(t, time.Since(started), 2.5, 10)
	stream.close()
}

func TestEnvoyECDSIdleCensus(t *testing.T) {
	origin := startOrigin(t, false)
	r := startEnvoyConfig(t, origin.port(), freePort(t), func(l object) {
		concurrencyConfig(t, l, false)
		policy(filters(l)[1])["enabled"] = false
	}, true)
	const count = 512
	streams := make([]*stream, 0, count)
	for range 8 {
		client := newClient(t, r.port)
		for range count / 8 {
			streams = append(streams, client.open(t, "test", fmt.Sprintf("sandbox-%d", len(streams)), "plain:80", 200))
		}
	}
	started := time.Now()
	r.reloadECDS(t, "agentio.connect_concurrency", func(p object) {
		p["enabled"] = true
		p["rate_limits"] = []any{
			object{
				"actions": []any{
					object{"generic_key": object{"descriptor_key": "scope", "descriptor_value": "gateway"}},
				},
			},
		}
		p["descriptors"] = []any{
			object{"entries": []any{object{"key": "scope", "value": "gateway"}}, "max_concurrent_streams": count},
		}
	}, false)
	client := newClient(t, r.port)
	client.open(t, "test", "new", "plain:80", 429).close()
	t.Logf("enabled quota over %d idle streams in %s (ECDS observation plus admission)", count, time.Since(started))
	for _, s := range streams {
		s.close()
	}
	finish(t, client.eventuallyOpen(t, "after-close"))
}

func TestEnvoyECDSMissingNewIdentity(t *testing.T) {
	for _, name := range []string{"agentio.bandwidth", "agentio.connect_concurrency"} {
		t.Run(name, func(t *testing.T) {
			origin := startOrigin(t, false)
			r := startEnvoyConfig(t, origin.port(), freePort(t), func(l object) {
				if name == "agentio.connect_concurrency" {
					concurrencyConfig(t, l, false)
				}
				policy(filters(l)[1])["enabled"] = false
			}, true)
			client := newClient(t, r.port)
			existing := client.open(t, "test", "a", "plain:80", 200)
			r.reloadECDS(t, name, func(p object) {
				p["enabled"] = true
				first := obj(obj(p["rate_limits"].([]any)[0])["actions"].([]any)[0])
				nested(first, "filter_state")["key"] = "identity.not.stored"
			}, false)
			if _, err := io.ReadAll(existing.response.Body); err == nil {
				t.Fatal("existing stream missing newly required identity was not reset")
			}
			existing.close()
			client.open(t, "test", "a", "plain:80", 403).close()
		})
	}
}
