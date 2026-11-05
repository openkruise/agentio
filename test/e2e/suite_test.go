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

package e2e

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/openkruise/agentio/test/e2e/cluster"
)

func TestSetupFailureUnwindsCompletedSetupsInReverse(t *testing.T) {
	var got []string
	s, source := newUnitSuite(t, true)
	s.Setup("one", setupAppending(&got, "setup-one", "clean-one", nil))
	s.Setup("two", setupAppending(&got, "setup-two", "clean-two", errors.New("boom")))
	testsCalled := false
	code := s.run(context.Background(), func() int {
		testsCalled = true
		return 0
	})
	if code == 0 {
		t.Fatal("Run succeeded")
	}
	if testsCalled {
		t.Fatal("tests ran after setup failure")
	}
	want := []string{"setup-one", "setup-two", "clean-one"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
	if source.closeCalls != 1 {
		t.Fatalf("close calls = %d", source.closeCalls)
	}
}

func TestReconnectInstructionsForKindDoNotUseRemovedTemporaryKubeconfig(t *testing.T) {
	environment := &Environment{Cluster: &cluster.Cluster{
		Name:       "retained",
		Context:    "kind-retained",
		Kubeconfig: "/tmp/removed-kubeconfig.yaml",
		Mode:       cluster.ModeKind,
		Owned:      true,
	}}
	instructions := strings.Join(reconnectInstructions(environment), "\n")
	if strings.Contains(instructions, environment.Cluster.Kubeconfig) {
		t.Fatalf("instructions reference removed kubeconfig: %s", instructions)
	}
	if !strings.Contains(instructions, `kind export kubeconfig --name "retained"`) || !strings.Contains(instructions, `kind delete cluster --name "retained"`) {
		t.Fatalf("instructions = %s", instructions)
	}
}

func TestSuiteExposesEnvironmentOnlyWhileTestsRun(t *testing.T) {
	s, _ := newUnitSuite(t, true)
	if code := s.run(context.Background(), func() int {
		env := s.Environment(t)
		if env.RunID == "" || env.Kube == nil || env.Kube == s.environment.Kube {
			t.Fatalf("environment = %+v", env)
		}
		return 0
	}); code != 0 {
		t.Fatalf("Run code = %d", code)
	}
}

func TestRetentionMatrix(t *testing.T) {
	tests := []struct {
		name         string
		owned        bool
		testCode     int
		policy       RetainPolicy
		wantCleanup  bool
		wantPreserve bool
	}{
		{name: "owned success never", owned: true, policy: RetainNever, wantCleanup: true},
		{name: "owned failure never", owned: true, testCode: 1, policy: RetainNever, wantCleanup: true},
		{name: "owned success on failure", owned: true, policy: RetainOnFailure, wantCleanup: true},
		{name: "owned failure on failure", owned: true, testCode: 1, policy: RetainOnFailure, wantPreserve: true},
		{name: "owned success always", owned: true, policy: RetainAlways, wantPreserve: true},
		{name: "owned failure always", owned: true, testCode: 1, policy: RetainAlways, wantPreserve: true},
		{name: "borrowed success never", policy: RetainNever, wantCleanup: true},
		{name: "borrowed failure never", testCode: 1, policy: RetainNever, wantCleanup: true},
		{name: "borrowed success on failure", policy: RetainOnFailure, wantCleanup: true},
		{name: "borrowed failure on failure", testCode: 1, policy: RetainOnFailure, wantPreserve: true},
		{name: "borrowed success always", policy: RetainAlways, wantPreserve: true},
		{name: "borrowed failure always", testCode: 1, policy: RetainAlways, wantPreserve: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, source := newUnitSuite(t, tc.owned)
			s.config.Lifecycle.Retain = tc.policy
			cleaned := false
			s.cleanupResources = func(context.Context, *Environment) error {
				cleaned = true
				return nil
			}
			code := s.run(context.Background(), func() int {
				deferred := s.Environment(t).DefersResourceCleanup()
				if want := tc.policy != RetainNever; deferred != want {
					t.Fatalf("defer per-test resource cleanup = %v, want %v", deferred, want)
				}
				return tc.testCode
			})
			if code != tc.testCode {
				t.Fatalf("code = %d, want %d", code, tc.testCode)
			}
			if cleaned != tc.wantCleanup {
				t.Fatalf("resource cleanup = %v, want %v", cleaned, tc.wantCleanup)
			}
			if source.preserve != tc.wantPreserve {
				t.Fatalf("preserve = %v, want %v", source.preserve, tc.wantPreserve)
			}
		})
	}
}

func TestCleanupFailureFailsRunAndPreservesOnFailure(t *testing.T) {
	s, source := newUnitSuite(t, true)
	s.config.Lifecycle.Retain = RetainOnFailure
	s.Setup("broken-cleanup", func(context.Context, *Environment) (CleanupFunc, error) {
		return func(context.Context) error { return errors.New("cleanup failed") }, nil
	})
	code := s.run(context.Background(), func() int { return 0 })
	if code != 1 || !source.preserve {
		t.Fatalf("code = %d, preserve = %v", code, source.preserve)
	}
}

func setupAppending(events *[]string, setup, cleanup string, setupErr error) SetupFunc {
	return func(context.Context, *Environment) (CleanupFunc, error) {
		*events = append(*events, setup)
		return func(context.Context) error {
			*events = append(*events, cleanup)
			return nil
		}, setupErr
	}
}

func newUnitSuite(t *testing.T, owned bool) (*Suite, *fakeClusterSource) {
	t.Helper()
	config := DefaultConfig()
	config.Artifacts.Dir = t.TempDir()
	config.Cluster.Name = "unit"
	s := NewSuite(SuiteSpec{Name: "unit"}, config)
	source := &fakeClusterSource{opened: &cluster.Cluster{Name: "unit", Context: "kind-unit", Owned: owned}}
	s.source = source
	s.lookupTool = func(string) (string, error) { return "/test/tool", nil }
	return s, source
}

type fakeClusterSource struct {
	opened     *cluster.Cluster
	openErr    error
	closeErr   error
	closeCalls int
	preserve   bool
}

func (f *fakeClusterSource) Open(context.Context, cluster.Config) (*cluster.Cluster, error) {
	return f.opened, f.openErr
}

func (f *fakeClusterSource) Close(_ context.Context, _ *cluster.Cluster, options cluster.CloseOptions) error {
	f.closeCalls++
	f.preserve = options.Preserve
	return f.closeErr
}
