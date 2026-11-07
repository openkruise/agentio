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

package xds

import (
	"context"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	sandboxv1 "github.com/openkruise/agentio/api/sandbox/v1"
	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/policy/profilestore"
	"github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
	"github.com/openkruise/agentio/extensions/epe/pkg/wiring"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/xdsclient"
)

func profilePayload(namespace string) *securityv1.SecurityProfile {
	return &securityv1.SecurityProfile{
		Name:       "policy",
		Namespace:  namespace,
		Uid:        "source",
		PolicyJson: []byte(`{}`),
	}
}

func TestProfileAdmissionAndOrderedDemand(t *testing.T) {
	regs, err := wiring.BuildValidationFilters()
	if err != nil {
		t.Fatal(err)
	}
	global := profilePayload("")
	local := profilePayload("ns")
	f := testSource()
	f.snapshot.Synced[model.SecurityProfileType], f.snapshot.Synced[model.SandboxType] = true, true
	f.snapshot.Resources[model.SecurityProfileType] = map[string]*xdsclient.Resource{}
	for name, wire := range map[string]*securityv1.SecurityProfile{"global/policy": global, "namespaced/ns/policy": local} {
		value, err := securityprofile.FromXDS(wire, "", regs)
		if err != nil {
			t.Fatal(err)
		}
		f.snapshot.Resources[model.SecurityProfileType][name] = &xdsclient.Resource{Value: value}
	}
	s := New(f)
	subj := subject.Subject{
		Workload: subject.Workload{
			UID:                       "host",
			SecurityProfileReferences: []string{"namespaced/ns/policy", "global/policy"},
		},
	}
	profiles, err := profileReferences(t, s, subj)
	if err != nil || len(profiles) != 2 || profiles[0].Namespace != "ns" || profiles[1].Namespace != "" {
		t.Fatalf("ordered body lookup: %v %v", profiles, err)
	}
	replacement := *f.snapshot.Resources[model.SecurityProfileType]["namespaced/ns/policy"].Value.(*securityprofile.Profile)
	replacement.Meta.SourceIdentity.UID = "replacement"
	f.snapshot.Resources[model.SecurityProfileType]["namespaced/ns/policy"] = &xdsclient.Resource{Value: &replacement}
	profiles, err = profileReferences(t, s, subj)
	if err != nil || len(profiles) != 2 || profiles[0].SourceIdentity.UID != "replacement" {
		t.Fatal("name binding did not resolve the replacement profile", err)
	}
	subj.Workload.SecurityProfileReferences = []string{"missing"}
	if _, err := profileReferences(t, s, subj); err == nil {
		t.Fatal("missing profile accepted")
	}
	subj.Workload.SecurityProfileReferences = []string{}
	if got, err := profileReferences(t, s, subj); err != nil || len(got) != 0 {
		t.Fatal("empty binding used local selectors", err)
	}
	for _, raw := range []string{
		`{`,
		`null`,
		`{"metadata":{"name":"policy"}}`,
		`{"selector":{}}`,
		`{"priority":100}`,
		`{"rules":[{"actions":{"newAction":{}}}]}`,
		`{"rules":[{"match":[{"domains":["*"],"paths":[{"type":"Regex","value":"["}]}]}]}`,
		`{"rules":[{"match":[{"domains":["*"],"paths":[{"type":"FutureMatch","value":"/"}]}]}]}`,
		`{"rules":[{"match":[{"domains":["*"]}],"actions":{"headerManipulation":{"set":[{"name":"x-test","value":"{{"}]}}}]}`,
		string(local.PolicyJson) + ` {}`,
	} {
		bad := proto.Clone(local).(*securityv1.SecurityProfile)
		bad.PolicyJson = []byte(raw)
		if _, err := securityprofile.FromXDS(bad, "", regs); err == nil {
			t.Fatalf("invalid config accepted: %s", raw)
		}
	}
	wrongName := proto.Clone(local).(*securityv1.SecurityProfile)
	wrongName.Name = "different-source"
	mismatched, err := securityprofile.FromXDS(wrongName, "", regs)
	if err != nil {
		t.Fatal(err)
	}
	f.snapshot.Resources[model.SecurityProfileType]["namespaced/ns/policy"] = &xdsclient.Resource{Value: mismatched}
	subj.Workload.SecurityProfileReferences = []string{"namespaced/ns/policy"}
	if _, err := profileReferences(t, s, subj); err == nil {
		t.Fatal("xDS resource name inconsistent with source identity accepted")
	}
	missingHTTP := proto.Clone(local).(*securityv1.SecurityProfile)
	missingHTTP.PolicyJson = nil
	if _, err := securityprofile.FromXDS(missingHTTP, "", regs); err == nil {
		t.Fatal("connection-only profile accepted as an empty HTTP policy")
	}
}

func TestSandboxProfilesAreAtomicAndHostBound(t *testing.T) {
	regs, err := wiring.BuildValidationFilters()
	if err != nil {
		t.Fatal(err)
	}
	body := profilePayload("ns")
	manifest := &sandboxv1.Sandbox{
		Uid:      "kruise:one",
		Attester: &sandboxv1.Sandbox_Attester{WorkloadUid: "host"},
		Extensions: []*anypb.Any{
			packed(body),
		},
	}
	source := NewProfileSource(profilestore.NewXDSStore().ObserveAdmission, t.Context().Done())
	watches := source.Watches(regs)
	shared, err := watches[0].Transform(packed(profilePayload("ns")))
	if err != nil {
		t.Fatal(err)
	}
	inline, err := watches[1].Transform(packed(manifest))
	if err != nil {
		t.Fatal(err)
	}
	decoded := inline.(*sandboxProfiles)
	if revision := shared.(*securityprofile.Profile).Meta.AdmissionRevision; revision == 0 ||
		decoded.profile.Meta.AdmissionRevision <= revision {
		t.Fatal("watches did not assign ordered admission revisions")
	}
	if decoded.profile.RawSandboxRules != "" {
		t.Fatal("xDS retained unused admin rules JSON")
	}
	f := testSource()
	f.snapshot.Synced[model.SecurityProfileType], f.snapshot.Synced[model.SandboxType] = true, true
	f.snapshot.Resources[model.SandboxType] = map[string]*xdsclient.Resource{
		"kruise:one": {Value: decoded},
		"ns/policy":  {Value: decoded},
	}
	s := New(f)
	subj := subject.Subject{
		Workload: subject.Workload{UID: "host", Namespace: "ns", Name: "policy", SecurityProfileReferences: []string{}},
	}
	got, err := profileReferences(t, s, subj)
	if err != nil || len(got) != 1 || got[0].SandboxUID != "kruise:one" {
		t.Fatalf("implicit Sandbox resolution: %v %v", got, err)
	}
	subj.Sandbox = &subject.Sandbox{UID: "kruise:one"}
	subj.Workload.UID = "other"
	if _, err := profileReferences(t, s, subj); err == nil {
		t.Fatal("other host used Sandbox policy")
	}
	subj.Workload.UID = "host"
	subj.Sandbox = nil
	subj.Workload.Name = "different"
	if got, err := profileReferences(t, s, subj); err != nil || len(got) != 0 {
		t.Fatalf("nonmatching Workload name selected hosted Sandbox: %v %v", got, err)
	}
	subj.Sandbox = &subject.Sandbox{UID: "kruise:missing"}
	if _, err := profileReferences(t, s, subj); err == nil {
		t.Fatal("missing explicit Sandbox accepted")
	}
	subj.Sandbox.UID = "kruise:one"
	manifest.Uid = "kruise:other"
	rebound, err := decodeSandboxProfiles(packed(manifest), regs)
	if err != nil || rebound.profile.Meta.SandboxUID != manifest.Uid {
		t.Fatal("inline profile did not inherit its enclosing Sandbox identity", err)
	}
	manifest.Uid = "kruise:one"
	manifest.Extensions = append(manifest.Extensions, packed(body))
	if _, err := decodeSandboxProfiles(packed(manifest), regs); err == nil {
		t.Fatal("duplicate Sandbox profile accepted")
	}
	manifest.Extensions = []*anypb.Any{packed(body), {TypeUrl: "unsupported"}}
	if _, err := decodeSandboxProfiles(packed(manifest), regs); err == nil {
		t.Fatal("unsupported Sandbox extension accepted")
	}
	manifest.Extensions = nil
	decoded, err = decodeSandboxProfiles(packed(manifest), regs)
	if err != nil || decoded.profile != nil {
		t.Fatalf("Sandbox without inline policy: %v %v", decoded, err)
	}
	f.snapshot.Resources[model.SandboxType][manifest.Uid] = &xdsclient.Resource{Value: decoded}
	if got, err := profileReferences(t, s, subj); err != nil || len(got) != 0 {
		t.Fatalf("removed inline policy retained: %v %v", got, err)
	}
}

func profileReferences(t *testing.T, s *Store, subj subject.Subject) ([]*securityprofile.Meta, error) {
	t.Helper()
	refs, release, err := s.AcquireProfileReferences(context.Background(), subj)
	if release != nil {
		release()
	}
	return refs, err
}
