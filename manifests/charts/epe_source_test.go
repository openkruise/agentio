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

package charts_test

import (
	"strings"
	"testing"
)

func TestEPEProfileSource(t *testing.T) {
	for _, source := range []string{"kubernetes", "xds"} {
		args := []string{"--set", "epe.mode=managed"}
		if source == "xds" {
			args = append(args, "--set", "epe.securityProfileSource=xds")
		}
		output := renderAgentio(t, args...)
		if !strings.Contains(output, "--security-profile-source="+source) ||
			!strings.Contains(output, "--profile-deletion-grace-period=60s") {
			t.Fatalf("%s source or legacy grace flag missing", source)
		}
	}
	if _, err := helmTemplate(
		t,
		"--set",
		"epe.mode=managed",
		"--set",
		"epe.securityProfileSource=invalid",
	); err == nil {
		t.Fatal("invalid profile source accepted")
	}
}
