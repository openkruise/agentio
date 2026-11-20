// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

package networking

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	udpa "github.com/cncf/xds/go/udpa/type/v1"
	access "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	cel "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/filters/cel/v3"
	stream "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/stream/v3"
	common "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/common/set_filter_state/v3"
	state "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
)

func (b *resourceBuilder) contentGuardConfig() ([]*hcm.HttpFilter, []*access.AccessLog, error) {
	cfg := b.contentGuard.AsMap()
	var filters []*hcm.HttpFilter
	// The HTTP module ABI exposes only top-level metadata. Envoy's native
	// formatter can resolve a nested path and publish it as a stream-local string.
	audit, _ := cfg["audit"].(map[string]any)
	attrs, _ := audit["attributes"].(map[string]any)
	projection := &state.Config{}
	for _, name := range slices.Sorted(maps.Keys(attrs)) {
		source, _ := attrs[name].(map[string]any)
		raw, found := source["dynamicMetadata"]
		if !found {
			continue
		}
		meta, _ := raw.(map[string]any)
		ns, _ := meta["namespace"].(string)
		path, _ := meta["path"].([]any)
		if len(source) != 1 || len(meta) != 2 || len(path) == 0 {
			return nil, nil, fmt.Errorf("contentGuard attribute %q requires a metadata namespace and path", name)
		}
		parts := []string{ns}
		for _, key := range path {
			s, _ := key.(string)
			parts = append(parts, s)
		}
		for _, part := range parts {
			if part == "" || strings.ContainsAny(part, ":()%\r\n") {
				return nil, nil, fmt.Errorf("invalid contentGuard metadata path for %q", name)
			}
		}
		key := "agentio.contentguard.metadata." + name
		projection.OnRequestHeaders = append(projection.OnRequestHeaders, &common.FilterStateValue{
			Key:         &common.FilterStateValue_ObjectKey{ObjectKey: key},
			FactoryKey:  "envoy.string",
			ReadOnly:    true,
			SkipIfEmpty: true,
			Value:       &common.FilterStateValue_FormatString{FormatString: formatString("%DYNAMIC_METADATA(" + strings.Join(parts, ":") + ")%")},
		})
		attrs[name] = map[string]any{"filterState": key}
	}
	if len(projection.OnRequestHeaders) > 0 {
		filters = append(filters, httpFilter("agentio.contentguard.metadata", b.pack(projection)))
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return nil, nil, err
	}
	filters = append(filters, httpFilter("agentio.contentguard", b.pack(&udpa.TypedStruct{
		TypeUrl: "type.googleapis.com/envoy.extensions.filters.http.dynamic_modules.v3.DynamicModuleFilter",
		Value: b.structure(map[string]any{
			"dynamic_module_config": map[string]any{
				"name":         "envoy_agentio_contentguard",
				"do_not_close": true,
				"module":       map[string]any{"local": map[string]any{"filename": "/usr/local/lib/libenvoy_agentio_contentguard.so"}},
			},
			"filter_name":   "contentguard",
			"filter_config": map[string]any{"@type": "type.googleapis.com/google.protobuf.StringValue", "value": string(data)},
		}),
	})))
	var logs []*access.AccessLog
	for _, direction := range []string{"request", "response"} {
		if cfg[direction] == nil {
			continue
		}
		key := "agentio.contentguard." + direction
		predicate := &access.ExtensionFilter{
			Name: "envoy.access_loggers.extension_filters.cel",
			ConfigType: &access.ExtensionFilter_TypedConfig{TypedConfig: b.pack(&cel.ExpressionFilter{
				Expression: "'" + key + "' in filter_state",
			})},
		}
		logger := &stream.StdoutAccessLog{
			AccessLogFormat: &stream.StdoutAccessLog_LogFormat{
				LogFormat: formatString("%FILTER_STATE(" + key + ":PLAIN)%\n"),
			},
		}
		logs = append(logs, &access.AccessLog{
			Name: "envoy.access_loggers.stdout",
			Filter: &access.AccessLogFilter{
				FilterSpecifier: &access.AccessLogFilter_ExtensionFilter{ExtensionFilter: predicate},
			},
			ConfigType: &access.AccessLog_TypedConfig{TypedConfig: b.pack(logger)},
		})
	}
	return filters, logs, b.err
}
