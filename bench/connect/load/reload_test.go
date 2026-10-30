// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"testing"

	"github.com/openkruise/agentio/bench/connect/fixture"
)

func TestReloadPreservesDebtAndDescriptorMatching(t *testing.T) {
	var b map[string]any
	if err := json.Unmarshal(fixture.Bootstrap, &b); err != nil {
		t.Fatal(err)
	}
	object := func(v any) map[string]any { return v.(map[string]any) }
	l := object(object(b["static_resources"])["listeners"].([]any)[0])
	hcm := object(object(object(l["filter_chains"].([]any)[0])["filters"].([]any)[0])["typed_config"])
	filter := object(hcm["http_filters"].([]any)[1])
	p := object(object(object(object(filter["typed_config"])["value"])["filter_config"])["value"])
	descriptors := p["descriptors"].([]any)
	// Treat the second descriptor as resident debt; its limit must not change.
	old, err := json.Marshal(object(descriptors[1])["bandwidth_limit"])
	if err != nil {
		t.Fatal(err)
	}
	resource := map[string]any{"resources": []any{filter}}
	mutatePolicy(resource, "rate")
	got, err := json.Marshal(object(descriptors[1])["bandwidth_limit"])
	if err != nil || string(got) != string(old) {
		t.Fatalf("resident debt rate changed: %s / %s: %v", old, got, err)
	}
	actions := object(p["rate_limits"].([]any)[0])["actions"].([]any)
	mutatePolicy(resource, "grouping")
	for _, d := range descriptors {
		for i, e := range object(d)["entries"].([]any) {
			if object(e)["key"] != object(object(actions[i])["filter_state"])["descriptor_key"] {
				t.Fatal("new descriptor layout does not match the action group")
			}
		}
	}
}
