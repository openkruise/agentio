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
package cmd

import (
	"github.com/spf13/cobra"
	"istio.io/istio/pkg/log"
	"testing"
)

func TestAgentioCommandAlias(t *testing.T) {
	root := &cobra.Command{Use: "pilot-agent"}
	iptables := GetCommand(log.DefaultOptions())
	root.AddCommand(iptables)
	for _, name := range []string{"agentio-iptables", "istio-iptables"} {
		cmd, args, err := root.Find([]string{name, "-k", "eth1"})
		if err != nil || cmd != iptables {
			t.Fatalf("%s: command=%v, error=%v", name, cmd, err)
		}
		if err := cmd.ParseFlags(args); err != nil {
			t.Fatal(err)
		}
		if value, _ := cmd.Flags().GetString("kube-virt-interfaces"); value != "eth1" {
			t.Fatalf("interface flag = %q", value)
		}
	}
}
