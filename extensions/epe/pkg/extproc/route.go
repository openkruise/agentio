// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package extproc

import (
	"strconv"

	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	structpb "google.golang.org/protobuf/types/known/structpb"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

// These names form the route metadata emitted by the ext_proc adapter.
const (
	routeMetadataNamespace = "agentio.route"
	routeUpstreamField     = "upstream"
	upstreamAddressField   = "address"
	upstreamIPField        = "ip"
	upstreamPortField      = "port"
)

// applyRouteMutation translates routing intent without choosing a cluster type.
// Always clone before writing: passthrough responses may be shared singletons.
// A local reply never carries route metadata or requests cache invalidation.
func applyRouteMutation(response *extProcPb.ProcessingResponse, route *filter.RouteMutation) *extProcPb.ProcessingResponse {
	if route == nil || response.GetImmediateResponse() != nil {
		return response
	}
	invalid := func() *extProcPb.ProcessingResponse {
		return immediateFromReply(filter.Reply{Status: 500, Details: "epe_invalid_route_mutation"})
	}
	if err := route.Validate(); err != nil {
		return invalid()
	}
	if route.Upstream == nil && !route.ClearCache {
		return response
	}

	out := cloneResponse(response)
	var common *extProcPb.CommonResponse
	switch r := out.Response.(type) {
	case *extProcPb.ProcessingResponse_RequestHeaders:
		if r.RequestHeaders.Response == nil {
			r.RequestHeaders.Response = &extProcPb.CommonResponse{}
		}
		common = r.RequestHeaders.Response
	case *extProcPb.ProcessingResponse_RequestBody:
		if r.RequestBody.Response == nil {
			r.RequestBody.Response = &extProcPb.CommonResponse{}
		}
		common = r.RequestBody.Response
	default:
		return invalid()
	}
	common.ClearRouteCache = common.ClearRouteCache || route.ClearCache
	if route.Upstream == nil {
		return out
	}

	address := *route.Upstream.Address
	if out.DynamicMetadata == nil {
		out.DynamicMetadata = &structpb.Struct{}
	}
	if out.DynamicMetadata.Fields == nil {
		out.DynamicMetadata.Fields = map[string]*structpb.Value{}
	}
	namespace := metadataObject(out.DynamicMetadata, routeMetadataNamespace)
	if namespace == nil {
		return invalid()
	}
	upstream := metadataObject(namespace, routeUpstreamField)
	if upstream == nil {
		return invalid()
	}
	// An already encoded destination must agree with the new mutation.
	if existing, ok := upstream.Fields[upstreamAddressField]; ok && existing.GetStringValue() != address.String() {
		return immediateFromReply(filter.Reply{Status: 500, Details: "epe_conflicting_upstream_target"})
	}
	upstream.Fields[upstreamAddressField] = structpb.NewStringValue(address.String())
	upstream.Fields[upstreamIPField] = structpb.NewStringValue(address.Addr().String())
	upstream.Fields[upstreamPortField] = structpb.NewStringValue(strconv.Itoa(int(address.Port())))
	return out
}

// metadataObject preserves existing object fields and refuses incompatible
// values. Its caller owns the parent and may mutate the returned object.
func metadataObject(parent *structpb.Struct, key string) *structpb.Struct {
	if value, ok := parent.Fields[key]; ok {
		object := value.GetStructValue()
		if object != nil && object.Fields == nil {
			object.Fields = map[string]*structpb.Value{}
		}
		return object
	}
	object := &structpb.Struct{Fields: map[string]*structpb.Value{}}
	parent.Fields[key] = structpb.NewStructValue(object)
	return object
}

func responseUpstream(response *extProcPb.ProcessingResponse) *structpb.Struct {
	return response.GetDynamicMetadata().GetFields()[routeMetadataNamespace].
		GetStructValue().GetFields()[routeUpstreamField].GetStructValue()
}
