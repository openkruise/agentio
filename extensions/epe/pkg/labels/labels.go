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
// Package labels parses label key/value pair encodings.
package labels

import (
	"encoding/base64"
	"strings"
)

// ParseSandboxLabels decodes the base64-encoded workload labels string and returns
// the resulting label map.
//
// The encoded string follows the Kubernetes label format: "key1=value1,key2=value2"
// For example: "app.kubernetes.io/name=sleep,agentio.kruise.io/dataplane-mode=sidecar"
//
// If the input is empty or invalid, an empty map is returned.
func ParseSandboxLabels(encoded string) map[string]string {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return make(map[string]string)
	}
	return ParseLabelPairs(string(decoded))
}

// ParseLabelPairs parses a plain (not base64-encoded) comma-separated
// "key1=value1,key2=value2" label string into a map. Empty pairs and pairs
// without an "=" separator are skipped. An empty input yields an empty map.
func ParseLabelPairs(raw string) map[string]string {
	result := make(map[string]string)
	if raw == "" {
		return result
	}

	pairs := strings.Split(raw, ",")
	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 {
			result[parts[0]] = parts[1]
		}
	}

	return result
}
