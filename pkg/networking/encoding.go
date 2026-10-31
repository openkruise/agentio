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
	"fmt"

	"github.com/openkruise/agentio/pkg/util/protoutil"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"

	configv1 "github.com/openkruise/agentio/api/config/v1"
)

// resourceBuilder belongs to one build. Nested helpers record the first encoding
// failure; the entry points discard the entire result if any extension failed.
type resourceBuilder struct {
	legacyGateway bool
	extensions    []*corev3.TypedExtensionConfig
	err           error
}

func (b *resourceBuilder) pack(message proto.Message) *anypb.Any {
	if b.err != nil {
		return nil
	}
	value, err := protoutil.MarshalAny(message)
	if err != nil {
		b.err = fmt.Errorf("marshal gateway extension %T: %w", message, err)
	}
	return value
}

// mustPack is for fixed configuration encoded during package initialization.
// Dynamic configuration must use resourceBuilder.pack so errors reach the caller.
func mustPack(message proto.Message) *anypb.Any {
	value, err := protoutil.MarshalAny(message)
	if err != nil {
		panic(fmt.Errorf("marshal static gateway extension %T: %w", message, err))
	}
	return value
}

func (b *resourceBuilder) clusters(config effectiveConfig) ([]*clusterv3.Cluster, error) {
	result, err := b.buildClusters(config)
	if b.err != nil {
		return nil, b.err
	}
	return result, err
}

func (b *resourceBuilder) listeners(config effectiveConfig, trustDomain string) ([]*listenerv3.Listener, error) {
	result, err := b.buildListeners(config, trustDomain)
	if b.err != nil {
		return nil, b.err
	}
	return result, err
}

func (b *resourceBuilder) routes(config *configv1.EgressGateway) ([]*routev3.RouteConfiguration, error) {
	result, err := b.buildRoutes(config)
	if b.err != nil {
		return nil, b.err
	}
	return result, err
}

func (b *resourceBuilder) structure(fields map[string]any) *structpb.Struct {
	if b.err != nil {
		return nil
	}
	value, err := structpb.NewStruct(fields)
	if err != nil {
		b.err = fmt.Errorf("marshal gateway extension fields: %w", err)
	}
	return value
}
