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

package telemetry

import (
	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	celv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/filters/cel/v3"
	"google.golang.org/protobuf/proto"

	"github.com/openkruise/agentio/pkg/util/protoutil"
)

const celFilterName = "envoy.access_loggers.extension_filters.cel"

func buildAccessLog(template *accesslogv3.AccessLog, filter *string) (*accesslogv3.AccessLog, error) {
	result := proto.Clone(template).(*accesslogv3.AccessLog)
	if filter == nil {
		return result, nil
	}
	result.Filter = celAccessLogFilter(filter)
	return result, nil
}

// buildConnectAccessLog mirrors release-0.1 hboneTerminationAccessLog: the
// CONNECT termination HCM logs only responses with status >= 400 because
// successful tunnel streams are already logged at the forward layer. When a
// Telemetry CEL filter is configured both filters are AND-ed, matching
// release-0.1 buildAccessLogFromTelemetry ordering.
func buildConnectAccessLog(template *accesslogv3.AccessLog, filter *string) (*accesslogv3.AccessLog, error) {
	status := &accesslogv3.AccessLogFilter{
		FilterSpecifier: &accesslogv3.AccessLogFilter_StatusCodeFilter{
			StatusCodeFilter: &accesslogv3.StatusCodeFilter{
				Comparison: &accesslogv3.ComparisonFilter{
					Op: accesslogv3.ComparisonFilter_GE,
					Value: &corev3.RuntimeUInt32{
						DefaultValue: 400,
						// Required by the API but useless for us; always use DefaultValue.
						RuntimeKey: "istio.io/unset",
					},
				},
			},
		},
	}
	return buildAccessLogWithBaseFilter(template, filter, status), nil
}

// Listener logs cover filter-chain misses and direct TCP denials; forwarded
// connections are logged by their HTTP manager or TCP proxy instead.
func buildListenerAccessLog(template *accesslogv3.AccessLog, filter *string) (*accesslogv3.AccessLog, error) {
	noRoute := &accesslogv3.AccessLogFilter{
		FilterSpecifier: &accesslogv3.AccessLogFilter_ResponseFlagFilter{
			ResponseFlagFilter: &accesslogv3.ResponseFlagFilter{Flags: []string{"NR"}},
		},
	}
	denied := "'" + DenialReasonFilterStateKey + "' in filter_state || 'io.kruise.egress_denial_reason' in filter_state"
	return buildAccessLogWithBaseFilter(template, filter, &accesslogv3.AccessLogFilter{
		FilterSpecifier: &accesslogv3.AccessLogFilter_OrFilter{
			OrFilter: &accesslogv3.OrFilter{
				Filters: []*accesslogv3.AccessLogFilter{noRoute, celAccessLogFilter(&denied)},
			},
		},
	}), nil
}

func buildAccessLogWithBaseFilter(
	template *accesslogv3.AccessLog,
	filter *string,
	base *accesslogv3.AccessLogFilter,
) *accesslogv3.AccessLog {
	result := proto.Clone(template).(*accesslogv3.AccessLog)
	if filter == nil {
		result.Filter = base
		return result
	}
	result.Filter = &accesslogv3.AccessLogFilter{
		FilterSpecifier: &accesslogv3.AccessLogFilter_AndFilter{
			AndFilter: &accesslogv3.AndFilter{
				Filters: []*accesslogv3.AccessLogFilter{base, celAccessLogFilter(filter)},
			},
		},
	}
	return result
}

func celAccessLogFilter(filter *string) *accesslogv3.AccessLogFilter {
	typed, err := protoutil.MarshalAny(&celv3.ExpressionFilter{Expression: *filter})
	if err != nil {
		// ExpressionFilter marshalling only fails on nil input, which cannot
		// happen here because filter is a valid pointer.
		panic(err)
	}
	return &accesslogv3.AccessLogFilter{
		FilterSpecifier: &accesslogv3.AccessLogFilter_ExtensionFilter{
			ExtensionFilter: &accesslogv3.ExtensionFilter{
				Name:       celFilterName,
				ConfigType: &accesslogv3.ExtensionFilter_TypedConfig{TypedConfig: typed},
			},
		},
	}
}
