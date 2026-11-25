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

package main

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"istio.io/istio/pkg/test"
	corev1 "k8s.io/api/core/v1"

	sandboxv1 "github.com/openkruise/agentio/api/sandbox/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/metrics"
	"github.com/openkruise/agentio/extensions/epe/pkg/policy/profilestore"
	xdsstore "github.com/openkruise/agentio/extensions/epe/pkg/store/xds"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
	"github.com/openkruise/agentio/pkg/compiler"
	"github.com/openkruise/agentio/pkg/demandcache"
	"github.com/openkruise/agentio/pkg/features"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/xds"
	publication "github.com/openkruise/agentio/pkg/xds/store"
)

type queryPeer struct{}

func (queryPeer) Authenticate(ctx context.Context) (model.PeerIdentity, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	auth := md.Get("authorization")
	if len(auth) != 1 || auth[0] != "Bearer token" {
		return model.PeerIdentity{}, errors.New("bad credential")
	}
	return model.PeerIdentity{AttestedBy: model.AttestationKubernetes}, nil
}

func TestEPEAcquiresInlinePolicyOverRPC(t *testing.T) {
	scopes := xds.ScopeFuncs{
		model.AttestationKubernetes: func(node *core.Node, _ model.PeerIdentity) (model.ClientScope, error) {
			if node.Id != "epe-node" || node.Metadata.GetFields()["POD_NAME"].GetStringValue() != "epe" {
				return model.ClientScope{}, errors.New("unknown EPE")
			}
			return model.ClientScope{
				Class:       model.ClientEPE,
				Principal:   model.MustServiceAccountPrincipal("ns", "epe"),
				WorkloadUID: "epe",
				Source:      model.SourceRef{Registry: "test", Key: "epe"},
			}, nil
		},
	}
	cp, err := xds.NewServer(
		queryPeer{},
		scopes,
		publication.New(model.ResourceSet{}),
		func() bool { return true },
		1,
		nil,
		1,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cp.Close)
	var reads atomic.Int32
	lookup := func(_ context.Context, _ model.ClientScope, name string) (*sandboxv1.Sandbox, error) {
		reads.Add(1)
		uid, host := "sandbox", "work"
		switch name {
		case "ns/work", "sandbox", "wrong-uid":
		case "wrong-host":
			uid, host = "wrong-host", "other"
		case "missing", "ns/missing":
			return nil, nil
		default:
			return nil, errors.New("backend unavailable")
		}
		return compiler.CompileSandboxPayload(model.Sandbox{
			UID:            uid,
			Name:           "inline",
			Attester:       &model.Attester{WorkloadUID: host},
			SourceIdentity: model.SourceIdentity{UID: "policy-source"},
			Policies:       &model.SandboxPolicies{SecurityProfile: &agentsv1alpha1.SecurityProfileSpec{}},
		})
	}
	g := grpc.NewServer()
	sandboxv1.RegisterSandboxQueryServiceServer(g, cp.SandboxQuery(lookup, nil, time.Minute))
	srv := httptest.NewUnstartedServer(g)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	root, token := filepath.Join(dir, "root.pem"), filepath.Join(dir, "token")
	if err := os.WriteFile(root, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(token, []byte("token"), 0600); err != nil {
		t.Fatal(err)
	}
	test.SetForTest(t, &features.SandboxMode, true)
	test.SetForTest(t, &metrics.Registry, prometheus.NewRegistry())
	test.SetForTest(t, securityProfileSource, "xds")
	test.SetForTest(t, sandboxSource, "rpc")
	test.SetForTest(t, xdsNodeID, "epe-node")
	test.SetForTest(t, xdsAddress, strings.TrimPrefix(srv.URL, "https://"))
	test.SetForTest(t, xdsTokenPath, token)
	test.SetForTest(t, xdsRootPath, root)
	t.Setenv("POD_NAME", "epe")
	matcher := profilestore.NewXDSStore()
	source := xdsstore.NewProfileSource(matcher.ObserveAdmission, t.Context().Done())
	c, conn, err := newEgressXDS(nil, source)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	})
	s, err := xdsstore.NewCached(c, demandcache.Config{MaxEntries: 10})
	if err != nil {
		t.Fatal(err)
	}
	opts := krt.WithStop(t.Context().Done())
	configMaps := krt.NewMutableCollection[*corev1.ConfigMap](nil, nil, opts)
	reg := matcher.RegisterCollection(source.Collection(configMaps.AsCollection(), opts), s.AcquireProfileReferences)
	t.Cleanup(reg.UnregisterHandler)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if !reg.WaitUntilSynced(ctx.Done()) {
		t.Fatal("policy collection did not sync")
	}
	subj := subject.Subject{
		Workload: subject.Workload{UID: "work", Namespace: "ns", Name: "work", SecurityProfileReferences: []string{}},
	}
	check := func(uid string, wantProfile, wantErr bool) {
		t.Helper()
		subj.Sandbox = nil
		if uid != "" {
			subj.Sandbox = &subject.Sandbox{UID: uid}
		}
		profiles, err := matcher.ResolveProfiles(ctx, subj)
		if (err != nil) != wantErr {
			t.Fatal(uid, err)
		}
		if wantProfile &&
			(len(profiles) != 1 || profiles[0].Meta.Name != "inline" || profiles[0].Meta.SandboxUID != "sandbox") {
			t.Fatal(uid, profiles)
		}
		if !wantProfile && len(profiles) != 0 {
			t.Fatal(uid, profiles)
		}
	}
	check("sandbox", true, false)
	check("sandbox", true, false)
	check("", true, false)
	check("wrong-host", false, true)
	check("wrong-uid", false, true)
	check("missing", false, true)
	check("missing", false, true)
	subj.Workload.Name = "missing"
	check("", false, false)
	check("failure", false, true)
	check("failure", false, true)
	if n := reads.Load(); n != 8 {
		t.Fatalf("GetSandbox calls = %d, want 8", n)
	}
}
