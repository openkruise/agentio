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

package networking

import (
	"encoding/json"

	access "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	cel "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/filters/cel/v3"
	stream "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/stream/v3"
	dynamicmodule "github.com/envoyproxy/go-control-plane/envoy/extensions/dynamic_modules/v3"
	dynamicfilter "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/dynamic_modules/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	bodyProcessingName  = "agentio.body_processing"
	bodyProcessingType  = "type.googleapis.com/envoy.extensions.filters.http.dynamic_modules.v3.DynamicModuleFilter"
	emptyBodyProcessing = `{"filterChains":[]}`
	auditStateKey       = "agentio.body_processing.audit"
)

func (b *resourceBuilder) bodyProcessingModule(rules string) *anypb.Any {
	return b.pack(&dynamicfilter.DynamicModuleFilter{
		DynamicModuleConfig: &dynamicmodule.DynamicModuleConfig{
			Name: "envoy_agentio_body_processing", DoNotClose: true,
			Module: &core.AsyncDataSource{Specifier: &core.AsyncDataSource_Local{Local: &core.DataSource{
				Specifier: &core.DataSource_Filename{Filename: "/usr/local/lib/libenvoy_agentio_body_processing.so"},
			}}},
		},
		FilterName:   "body_processing",
		FilterConfig: b.pack(wrapperspb.String(rules)),
	})
}

func (b *resourceBuilder) bodyProcessingExtension(settings *structpb.Struct) (*core.TypedExtensionConfig, error) {
	rules := emptyBodyProcessing
	if settings != nil {
		data, err := json.Marshal(settings.AsMap())
		if err != nil {
			return nil, err
		}
		rules = string(data)
	}
	return &core.TypedExtensionConfig{Name: bodyProcessingName, TypedConfig: b.bodyProcessingModule(rules)}, b.err
}

func (b *resourceBuilder) bodyProcessingFilter() *hcm.HttpFilter {
	return &hcm.HttpFilter{
		Name: bodyProcessingName,
		ConfigType: &hcm.HttpFilter_ConfigDiscovery{ConfigDiscovery: &core.ExtensionConfigSource{
			ConfigSource:                     adsConfigSource(),
			TypeUrls:                         []string{bodyProcessingType},
			DefaultConfig:                    b.bodyProcessingModule(emptyBodyProcessing),
			ApplyDefaultConfigWithoutWarming: true,
		}},
	}
}

func (b *resourceBuilder) bodyProcessingLogger() *access.AccessLog {
	predicate := &access.ExtensionFilter{
		Name: "envoy.access_loggers.extension_filters.cel",
		ConfigType: &access.ExtensionFilter_TypedConfig{TypedConfig: b.pack(&cel.ExpressionFilter{
			Expression: "'" + auditStateKey + "' in filter_state",
		})},
	}
	return &access.AccessLog{
		Name: "envoy.access_loggers.stdout",
		Filter: &access.AccessLogFilter{
			FilterSpecifier: &access.AccessLogFilter_ExtensionFilter{ExtensionFilter: predicate},
		},
		ConfigType: &access.AccessLog_TypedConfig{TypedConfig: b.pack(&stream.StdoutAccessLog{
			AccessLogFormat: &stream.StdoutAccessLog_LogFormat{LogFormat: formatString("%FILTER_STATE(" + auditStateKey + ":PLAIN)%")},
		})},
	}
}
