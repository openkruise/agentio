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

// Package httpreq holds the neutral request tuple shared by the filter
// framework and the policy model. It is a leaf: importing it pulls in no
// policy API, no protos, nothing but the standard library — which is what
// lets the engine's dependency closure stay free of agents-api.
package attributes

import (
	"fmt"

	"github.com/dunglas/httpsfv"
)

// Reject the entire field on failure so a partial list cannot become DNS evidence.
func parseDNSCandidates(raw string) ([]string, error) {
	if raw == "" {
		return nil, nil
	}
	if len(raw) > 8192 {
		return nil, fmt.Errorf("DNS candidates header exceeds 8192 bytes")
	}
	list, err := httpsfv.UnmarshalList([]string{raw})
	if err != nil {
		return nil, fmt.Errorf("invalid Structured Fields DNS list: %w", err)
	}
	result := make([]string, 0, len(list))
	for _, member := range list {
		item, ok := member.(httpsfv.Item)
		name, isString := item.Value.(string)
		if !ok || !isString || name == "" {
			return nil, fmt.Errorf("DNS candidates must be nonempty String Items")
		}
		result = append(result, name)
	}
	return result, nil
}
