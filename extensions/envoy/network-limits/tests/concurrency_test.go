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
	"fmt"
	"io"
	"os"
	"testing"
)

func concurrencyConfig(t *testing.T, l object, combined bool) {
	fs := filters(l)
	concurrency := clone(t, obj(fs[1]))
	concurrency["name"] = "agentio.connect_concurrency"
	m := nested(concurrency, "typed_config", "value")
	m["filter_name"] = "envoy_agentio_connect_concurrency"
	nested(m, "filter_config")["value"] = object{
		"budget_name":         "concurrency-test",
		"max_dynamic_buckets": 8,
		"rate_limits": []any{
			object{
				"actions": []any{
					object{"filter_state": object{"key": "agentio.sandbox.uid", "descriptor_key": "sandbox"}},
				},
			},
			object{
				"actions": []any{
					object{"generic_key": object{"descriptor_key": "scope", "descriptor_value": "gateway"}},
				},
			},
		},
		"descriptors": []any{
			object{"entries": []any{object{"key": "sandbox"}}, "max_concurrent_streams": 2},
			object{"entries": []any{object{"key": "scope", "value": "gateway"}}, "max_concurrent_streams": 4},
		},
	}
	if !combined {
		setFilters(l, []any{fs[0], concurrency, fs[2]})
		return
	}
	ratelimit := object{
		"name": "envoy.filters.http.local_ratelimit",
		"typed_config": object{
			"@type":           "type.googleapis.com/envoy.extensions.filters.http.local_ratelimit.v3.LocalRateLimit",
			"stat_prefix":     "connect_rate",
			"token_bucket":    object{"max_tokens": 1000, "tokens_per_fill": 1000, "fill_interval": "1s"},
			"filter_enabled":  object{"default_value": object{"numerator": 100, "denominator": "HUNDRED"}},
			"filter_enforced": object{"default_value": object{"numerator": 100, "denominator": "HUNDRED"}},
		}}
	setFilters(l, []any{fs[0], ratelimit, concurrency, fs[1], fs[2]})
}
func TestEnvoyConcurrency(t *testing.T) {
	if os.Getenv("AGENTIO_TEST_ENVOY_BINARY") == "" {
		t.Skip("real Envoy test; run bin/test_network_limits.sh")
	}
	for _, combined := range []bool{false, true} {
		t.Run(fmt.Sprintf("combined=%t", combined), func(t *testing.T) {
			origin := startOrigin(t, false)
			r := startEnvoy(t, origin.port(), freePort(t), func(l object) { concurrencyConfig(t, l, combined) })
			a, b, c := newClient(t, r.port), newClient(t, r.port), newClient(t, r.port)
			a1, a2 := a.open(t, "test", "a", "plain:80", 200), b.open(t, "test", "a", "plain:80", 200)
			c.open(t, "test", "a", "plain:80", 429).close()
			b1, b2 := b.open(t, "test", "b", "plain:80", 200), c.open(t, "test", "b", "plain:80", 200)
			c.open(t, "test", "c", "plain:80", 429).close()
			a1.close()
			a3 := c.eventuallyOpen(t, "a")
			_, err := io.WriteString(b1.writer, "hold\n")
			must(t, err)
			must(t, b1.writer.Close())
			a.open(t, "test", "b", "plain:80", 429).close()
			close(origin.release)
			body, err := io.ReadAll(b1.response.Body)
			must(t, err)
			if string(body) != "done" {
				t.Fatalf("half-close response %q", body)
			}
			b1.close()
			b3 := a.eventuallyOpen(t, "b")
			c.open(t, "test", "", "plain:80", 403).close()
			for _, s := range []*stream{a2, a3, b2, b3} {
				finish(t, s)
			}
			disconnected := newClient(t, r.port)
			disconnected.open(t, "test", "disconnect", "plain:80", 200)
			disconnected.open(t, "test", "disconnect", "plain:80", 200)
			must(t, disconnected.conn.Close())
			finish(t, a.eventuallyOpen(t, "disconnect"))
			for range 5 {
				s := a.open(t, "test", "failure", "tls:443", 503)
				_, err = io.Copy(io.Discard, s.response.Body)
				must(t, err)
				s.close()
			}
			first := tunnel(t, r.port, "reload", false)
			defer closeTest(t, first)
			update := func(limit int, reject bool) {
				r.reload(t, func(l object) {
					for _, f := range filters(l) {
						if obj(f)["name"] == "agentio.connect_concurrency" {
							obj(policy(f)["descriptors"].([]any)[0])["max_concurrent_streams"] = limit
						}
					}
				}, reject)
			}
			update(1, false)
			newClient(t, r.port).open(t, "test", "reload", "plain:80", 429).close()
			update(3, false)
			fresh, last := newClient(t, r.port), newClient(t, r.port)
			second := fresh.open(t, "test", "reload", "plain:80", 200)
			update(1, true)
			third := last.open(t, "test", "reload", "plain:80", 200)
			last.open(t, "test", "reload", "plain:80", 429).close()
			_, err = io.WriteString(first, "done\n")
			must(t, err)
			data := make([]byte, 4)
			_, err = io.ReadFull(first, data)
			must(t, err)
			if string(data) != "done" {
				t.Fatal(string(data))
			}
			finish(t, second)
			finish(t, third)
		})
	}
}
