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

package securityprofile

import (
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/openkruise/agentio/extensions/epe/pkg/filters/tokentransform"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube/kclient"

	"github.com/openkruise/agentio/extensions/epe/pkg/audit"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/extensionprovider"
	"github.com/openkruise/agentio/extensions/epe/pkg/policy/profilestore"
	policysecurityprofile "github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"
	"github.com/openkruise/agentio/extensions/epe/pkg/testing/enginetest"
	"github.com/openkruise/agentio/extensions/epe/pkg/wiring"
	"github.com/openkruise/agentio/pkg/kube"
)

// Options configures the SecurityProfile-specific test harness.
type Options struct {
	Providers        *extensionprovider.Registry
	AuthorizeRequest engine.RequestAuthorizer
	// Filters overrides the production filter chain.
	Filters       []filter.Registration
	StreamLoggers []filter.StreamLogger
	AuditRouter   *audit.Router
	// Kube backs the token Secret cache. Nil means an empty fake cluster.
	Kube                   kube.Client
	SecretNamespace        string
	DisableResolutionProbe bool
}

// Harness adds a SecurityProfile fixture to the policy-neutral wire harness.
type Harness struct {
	*enginetest.Harness
	Fixture *Fixture
}

// New builds a SecurityProfile resolver and delegates wire processing to
// enginetest.
func New(t testing.TB, opts Options) *Harness {
	t.Helper()
	kubeClient := opts.Kube
	if kubeClient == nil {
		kubeClient = kube.NewFakeClient()
	}
	regs := opts.Filters
	providers := opts.Providers
	// len, not nil: an explicitly empty slice must take the same branch the
	// fixture does, or the store would project against the default chain while
	// the resolver evaluates against an empty one.
	if len(regs) == 0 {
		var err error
		namespace := opts.SecretNamespace
		if namespace == "" {
			namespace = "test-ns"
		}
		secrets := krt.NewFilteredInformer[*corev1.Secret](kubeClient, kclient.Filter{Namespace: namespace},
			krt.WithStop(t.Context().Done()))
		kubeClient.Run(t.Context().Done())
		if !secrets.WaitUntilSynced(t.Context().Done()) {
			t.Fatal("token Secret cache failed to sync")
		}
		deps := wiring.Deps{Secrets: tokentransform.NewSecretSource(secrets, namespace)}
		if providers == nil {
			providers = &extensionprovider.Registry{}
			t.Cleanup(providers.Close)
		}
		deps.Providers = providers
		regs, err = wiring.BuildFilters(deps)
		if err != nil {
			t.Fatalf("securityprofile: BuildFilters: %v", err)
		}
	}

	// The fixture projects seeded profiles against the same chain the resolver
	// evaluates them with; a mismatch fails every request closed.
	fixture := NewFixture(t, regs...)
	var auditSink audit.Sink
	if opts.AuditRouter != nil {
		auditSink = opts.AuditRouter
	}
	core := enginetest.New(t, enginetest.Options{
		Resolve:                policysecurityprofile.NewResolver(fixture.Store, regs, auditSink, nil),
		Registrations:          regs,
		AuthorizeRequest:       opts.AuthorizeRequest,
		StreamLoggers:          opts.StreamLoggers,
		DisableResolutionProbe: opts.DisableResolutionProbe,
	})
	return &Harness{Harness: core, Fixture: fixture}
}

// Store exposes the fixture's seedable profile store.
func (h *Harness) Store() *profilestore.FakeStore { return h.Fixture.Store }
