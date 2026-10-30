// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
)

func discoverBandwidth(data []byte, path string) ([]byte, error) {
	var b map[string]any
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	b["node"] = map[string]any{"id": "connect-bench", "cluster": "connect-bench"}
	listener := object(object(b["static_resources"])["listeners"].([]any)[0])
	hcm := object(object(object(listener["filter_chains"].([]any)[0])["filters"].([]any)[0])["typed_config"])
	for _, f := range hcm["http_filters"].([]any) {
		filter := object(f)
		if filter["name"] != "agentio.bandwidth" {
			continue
		}
		resource, err := json.Marshal(map[string]any{
			"version_info": "initial",
			"resources": []any{map[string]any{
				"@type":        "type.googleapis.com/envoy.config.core.v3.TypedExtensionConfig",
				"name":         filter["name"],
				"typed_config": filter["typed_config"],
			}},
		})
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, resource, 0600); err != nil {
			return nil, err
		}
		delete(filter, "typed_config")
		filter["config_discovery"] = map[string]any{
			"config_source": map[string]any{
				"resource_api_version": "V3",
				"path_config_source":   map[string]any{"path": path},
			},
			"type_urls": []any{
				"type.googleapis.com/envoy.extensions.filters.http.dynamic_modules.v3.DynamicModuleFilter",
			},
		}
	}
	return json.MarshalIndent(b, "", "  ")
}
