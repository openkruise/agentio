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

// Package testutil provides small helpers shared by tests across the module.
package testutil

import (
	"testing"
	"time"
)

// Eventually polls condition until it holds or a 10s deadline elapses, and
// fails the test with message on timeout.
func Eventually(t testing.TB, condition func() bool, message string) {
	t.Helper()
	WaitFor(t, 10*time.Second, condition, message)
}

// WaitFor polls condition until it holds or timeout elapses, and fails the
// test with message on timeout.
func WaitFor(t testing.TB, timeout time.Duration, condition func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if condition() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("condition never held: %s", message)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
