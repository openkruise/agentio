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

package xdsclient

import (
	"fmt"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/protobuf/proto"
)

func transformResources(resources []*discovery.Resource, watch Watch) ([]*Resource, *discovery.Resource, error) {
	result := make([]*Resource, len(resources))
	for i, resource := range resources {
		// Named watches leave unselected response positions empty.
		if resource == nil {
			continue
		}
		var value any
		if watch.Transform == nil {
			value = proto.Clone(resource.Resource)
		} else {
			var err error
			value, err = watch.Transform(resource.Resource)
			if err != nil {
				return nil, resource, fmt.Errorf("transform %s %q: %w", watch.TypeURL, resource.Name, err)
			}
		}
		result[i] = &Resource{Value: value}
	}
	return result, nil, nil
}
