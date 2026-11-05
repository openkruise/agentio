// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

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
