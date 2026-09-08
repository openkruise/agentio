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

package compiler

import (
	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/policy"
	"sync/atomic"
	"testing"
)

func TestSandboxSNIPolicyLifecycle(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	builder := krt.NewOptionsBuilder(stop, "inline-test", nil)
	options := func(name string) []krt.CollectionOption { return builder.WithName(name) }
	bindings := krt.NewStaticCollection[policy.SandboxPolicyBindings](nil, nil, options("bindings")...)
	payloads := krt.NewStaticCollection[policy.CompiledSNIPolicy](nil, nil, options("payloads")...)
	resolved := newSandboxSNIPolicies(bindings, payloads, options)
	var changes atomic.Int64
	resolved.RegisterBatch(func(events []krt.Event[SandboxSNIPolicy]) { changes.Add(int64(len(events))) }, false)
	binding := func(names ...string) policy.SandboxPolicyBindings {
		return policy.SandboxPolicyBindings{SandboxUID: "sandbox", Groups: []policy.PolicyBindingGroup{{Kind: policy.PolicyKindSNIPolicy, Names: names}}}
	}
	payload := func(name, host string) policy.CompiledSNIPolicy {
		return policy.CompiledSNIPolicy{Name: name, Policy: &extensionsv1.SniTrafficPolicy{Rules: []*extensionsv1.SniRule{{Match: &extensionsv1.SniMatch{Sni: []string{host}}}}}}
	}
	expect := func(hosts ...string) {
		t.Helper()
		eventually(t, func() bool {
			got := resolved.GetKey("sandbox")
			if got == nil || len(got.Policy.Rules) != len(hosts) {
				return false
			}
			for i, host := range hosts {
				if got.Policy.Rules[i].Match.Sni[0] != host {
					return false
				}
			}
			return true
		}, "complete ordered inline policy")
	}
	bindings.UpdateObject(binding("second", "first"))
	if !resolved.WaitUntilSynced(stop) {
		t.Fatal("sync failed")
	}
	if resolved.GetKey("sandbox") != nil {
		t.Fatal("published incomplete policy")
	}
	payloads.UpdateObject(payload("first", "first.example"))
	payloads.UpdateObject(payload("second", "second.example"))
	expect("second.example", "first.example")
	// Rules-only edits must propagate without a binding event.
	payloads.UpdateObject(payload("first", "updated.example"))
	expect("second.example", "updated.example")
	// Unrelated policy changes must not invalidate this Sandbox.
	settle()
	before := changes.Load()
	payloads.UpdateObject(payload("unrelated", "other.example"))
	settle()
	if changes.Load() != before {
		t.Fatal("unrelated payload invalidated inline policy")
	}
	// Missing replacement retains the complete prior payload and watches the new key.
	bindings.UpdateObject(binding("replacement"))
	settle()
	expect("second.example", "updated.example")
	payloads.UpdateObject(payload("replacement", "replacement.example"))
	expect("replacement.example")
	// Removing the attachment removes the extension instead of retaining old rules.
	bindings.UpdateObject(binding())
	eventually(t, func() bool { return resolved.GetKey("sandbox") == nil }, "policy removal")
	bindings.UpdateObject(binding("first"))
	expect("updated.example")
	bindings.DeleteObject("sandbox")
	eventually(t, func() bool { return resolved.GetKey("sandbox") == nil }, "Sandbox deletion")
}
