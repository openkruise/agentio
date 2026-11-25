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
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/types/known/anypb"
	corev1 "k8s.io/api/core/v1"

	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	sandboxv1 "github.com/openkruise/agentio/api/sandbox/v1"
	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/policy/profilestore"
	"github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"
	"github.com/openkruise/agentio/extensions/epe/pkg/store"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
	"github.com/openkruise/agentio/pkg/features"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/xdsclient"
)

type sandboxProfiles struct {
	value   *sandboxv1.Sandbox
	profile *securityprofile.Profile
}

// ProfileSource publishes accepted xDS candidates into the common collection.
// OnChange runs under the client lock; KRT delivers derived updates asynchronously.
type ProfileSource struct {
	revision atomic.Uint64
	profiles krt.StaticCollection[securityprofile.Profile]
	names    map[store.Key]string
	rejected map[store.Key]securityprofile.Meta
	observe  func(securityprofile.Meta, bool, error)
}

// NewProfileSource creates an empty source with an admission status observer.
func NewProfileSource(observe func(securityprofile.Meta, bool, error), stop <-chan struct{}) *ProfileSource {
	return &ProfileSource{
		profiles: krt.NewMutableCollection[securityprofile.Profile](
			nil,
			nil,
			krt.WithName("XDSProfileSources"),
			krt.WithStop(stop),
		),
		names:   map[store.Key]string{},
		observe: observe,
	}
}

// Collection resolves input dependencies for accepted profiles.
func (s *ProfileSource) Collection(
	configMaps krt.Collection[*corev1.ConfigMap],
	opts ...krt.CollectionOption,
) *profilestore.Collection {
	return profilestore.NewSourceCollection(s.profiles.AsCollection(), configMaps, opts...)
}

func (s *ProfileSource) changed(name string, sandbox bool, current *xdsclient.Resource, err error) {
	var profile *securityprofile.Profile
	typ := store.SecurityProfile
	if sandbox {
		typ = store.Sandbox
	}
	if current != nil {
		if sandbox {
			profile = current.Value.(*sandboxProfiles).profile
		} else {
			profile = current.Value.(*securityprofile.Profile)
		}
	}
	key := store.Key{Type: typ, Name: name}
	if err != nil {
		if s.observe != nil {
			meta := securityprofile.Meta{Name: name}
			if profile != nil {
				meta = profile.Meta
			} else if sandbox {
				meta.Match = securityprofile.MatchSandbox
			} else if local, ok := strings.CutPrefix(name, "namespaced/"); ok {
				meta.Namespace, meta.Name, _ = strings.Cut(local, "/")
			} else {
				meta.Name = strings.TrimPrefix(name, "global/")
			}
			s.observe(meta, profile != nil, err)
			if s.rejected == nil {
				s.rejected = make(map[store.Key]securityprofile.Meta)
			}
			s.rejected[key] = meta
		}
		return
	}
	// Healthy updates publish status through the collection without taking the store lock under the client lock.
	if meta, rejected := s.rejected[key]; rejected {
		s.observe(meta, false, nil)
		delete(s.rejected, key)
	}

	previous := s.names[key]
	if previous != "" && (profile == nil || previous != profile.ResourceName()) {
		installed := s.profiles.GetKey(previous)
		if installed != nil && (!sandbox || installed.Meta.SandboxUID == name) {
			s.profiles.DeleteObject(previous)
		}
		delete(s.names, key)
	}
	if profile != nil {
		s.names[key] = profile.ResourceName()
		s.profiles.UpdateObject(*profile)
	}
}

// Watches validates and compiles policies before the xDS client ACKs.
func (s *ProfileSource) Watches(regs []filter.Registration) []xdsclient.Watch {
	watches := []xdsclient.Watch{
		{
			TypeURL:        model.SecurityProfileType,
			ReconnectGrace: 5 * time.Second,
			OnDelete:       func(string) xdsclient.DeleteAction { return xdsclient.ReleaseSubscription },
			Transform: func(value *anypb.Any) (any, error) {
				profile := &securityv1.SecurityProfile{}
				if err := value.UnmarshalTo(profile); err != nil {
					return nil, err
				}
				compiled, err := securityprofile.FromXDS(profile, "", regs)
				if err != nil {
					return nil, err
				}
				compiled.Meta.AdmissionRevision = s.revision.Add(1)
				return compiled, nil
			},
			OnChange: func(name string, current *xdsclient.Resource, err error) { s.changed(name, false, current, err) },
		},
	}
	if features.SandboxMode {
		watches = append(watches, xdsclient.Watch{
			TypeURL:        model.SandboxType,
			ReconnectGrace: 5 * time.Second,
			OnDelete:       func(string) xdsclient.DeleteAction { return xdsclient.KeepSubscription },
			Transform: func(value *anypb.Any) (any, error) {
				compiled, err := decodeSandboxProfiles(value, regs)
				if err != nil {
					return nil, err
				}
				if compiled.profile != nil {
					compiled.profile.Meta.AdmissionRevision = s.revision.Add(1)
				}
				return compiled, nil
			},
			OnChange: func(name string, current *xdsclient.Resource, err error) { s.changed(name, true, current, err) },
		})
	}
	return watches
}

func decodeSandboxProfiles(value *anypb.Any, regs []filter.Registration) (*sandboxProfiles, error) {
	result := &sandboxProfiles{value: &sandboxv1.Sandbox{}}
	if err := value.UnmarshalTo(result.value); err != nil {
		return nil, err
	}
	for _, extension := range result.value.Extensions {
		switch extension.GetTypeUrl() {
		case model.SecurityProfileType:
			payload := &securityv1.SecurityProfile{}
			if err := extension.UnmarshalTo(payload); err != nil {
				return nil, err
			}
			if result.profile != nil {
				return nil, fmt.Errorf("duplicate profile in Sandbox %q", result.value.Uid)
			}
			compiled, err := securityprofile.FromXDS(payload, result.value.Uid, regs)
			if err != nil {
				return nil, err
			}
			if compiled.Meta.Match != securityprofile.MatchSandbox {
				return nil, fmt.Errorf("Sandbox profile identity does not match its Sandbox")
			}
			result.profile = compiled
		case model.SniTrafficPolicyType:
			if err := extension.UnmarshalTo(&extensionsv1.SniTrafficPolicy{}); err != nil {
				return nil, err
			}
		}
	}
	return result, nil
}

// AcquireProfileReferences discovers and pins the ordered sources. It returns
// identity only; the xDS profile store consumes the collection's derived values.
func (s *Store) AcquireProfileReferences(
	ctx context.Context,
	subj subject.Subject,
) (_ []*securityprofile.Meta, release func(), err error) {
	if subj.Workload.SecurityProfileReferences == nil {
		return nil, nil, fmt.Errorf("SecurityProfile binding has not been resolved")
	}
	sandboxName := ""
	if subj.Sandbox != nil {
		if !features.SandboxMode {
			return nil, nil, fmt.Errorf("Sandbox identity requires AGENTIO_SANDBOX_MODE=true")
		}
		sandboxName = subj.Sandbox.UID
		if sandboxName == "" {
			return nil, nil, fmt.Errorf("empty Sandbox identity")
		}
	} else if features.SandboxMode && subj.Workload.Namespace != "" && subj.Workload.Name != "" {
		sandboxName = subj.Workload.Namespace + "/" + subj.Workload.Name
	}
	shared := subj.Workload.SecurityProfileReferences
	if sandboxName == "" && len(shared) == 0 {
		return nil, func() {}, nil
	}
	if s.cache != nil {
		switch {
		case len(shared) == 0 && subj.Sandbox != nil:
			return s.acquireSingleProfile(ctx, store.Key{Type: store.Sandbox, Name: sandboxName}, subj.Workload.UID)
		case len(shared) == 1 && sandboxName == "":
			if shared[0] == "" {
				return nil, nil, fmt.Errorf("invalid SecurityProfile reference %q", shared[0])
			}
			return s.acquireSingleProfile(
				ctx,
				store.Key{Type: store.SecurityProfile, Name: shared[0]},
				subj.Workload.UID,
			)
		}
	}
	keys := make([]store.Key, 0, len(shared)+1)
	seen := map[string]bool{}
	for _, name := range shared {
		if name == "" || seen[name] {
			return nil, nil, fmt.Errorf("invalid SecurityProfile reference %q", name)
		}
		seen[name] = true
		keys = append(keys, store.Key{Type: store.SecurityProfile, Name: name})
	}
	if sandboxName != "" {
		keys = append(keys, store.Key{Type: store.Sandbox, Name: sandboxName})
	}
	releases := make([]func(), 0, len(keys))
	cleanup := func() {
		for _, release := range releases {
			release()
		}
	}
	defer func() {
		if err != nil {
			cleanup()
			release = nil
		}
	}()
	for i, key := range keys {
		resource, release, err := s.acquireValue(ctx, key)
		if release != nil {
			releases = append(releases, release)
		}
		if err != nil {
			return nil, nil, err
		}
		if resource == nil {
			if key.Type == store.Sandbox && subj.Sandbox == nil {
				keys = keys[:i]
				break
			}
			return nil, nil, &store.MissingResource{Key: key}
		}
		if key.Type == store.Sandbox {
			sandbox := resource.Value.(*sandboxProfiles)
			if subj.Sandbox != nil && sandbox.value.Uid != key.Name {
				return nil, nil, fmt.Errorf("Sandbox resource name does not match its body")
			}
			keys[i].Name = sandbox.value.Uid
		}
	}
	if len(keys) == 0 {
		return nil, cleanup, nil
	}
	references, err := s.readProfileReferences(keys, subj.Workload.UID)
	return references, cleanup, err
}

// Resolve a single required source while keeping its lease through admission.
func (s *Store) acquireSingleProfile(
	ctx context.Context,
	key store.Key,
	workloadUID string,
) ([]*securityprofile.Meta, func(), error) {
	value, release, err := s.acquireValue(ctx, key)
	if err != nil {
		return nil, nil, err
	}
	if value != nil {
		// A lease can resolve an alias. A required binding names a canonical resource.
		var status store.Status
		value, status = s.lookup(key)
		if !status.Ready {
			release()
			return nil, nil, fmt.Errorf("SecurityProfile xDS is not synchronized")
		}
	}
	if value == nil {
		if release != nil {
			release()
		}
		return nil, nil, &store.MissingResource{Key: key}
	}
	refs, err := appendProfileReference(nil, key, value, workloadUID)
	if err != nil {
		release()
		return nil, nil, err
	}
	return refs, release, nil
}

func (s *Store) readProfileReferences(keys []store.Key, workloadUID string) ([]*securityprofile.Meta, error) {
	snapshot := s.snapshotFor(keys)
	for _, key := range keys {
		if !snapshot.Usable(wireType(key.Type)) {
			return nil, fmt.Errorf("SecurityProfile xDS is not synchronized")
		}
	}
	references := make([]*securityprofile.Meta, 0, len(keys))
	for _, key := range keys {
		value := snapshot.Resources[wireType(key.Type)][key.Name]
		if value == nil {
			return nil, &store.MissingResource{Key: key}
		}
		var err error
		references, err = appendProfileReference(references, key, value, workloadUID)
		if err != nil {
			return nil, err
		}
	}
	return references, nil
}

func appendProfileReference(
	refs []*securityprofile.Meta,
	key store.Key,
	value *xdsclient.Resource,
	workloadUID string,
) ([]*securityprofile.Meta, error) {
	if key.Type == store.Sandbox {
		sandbox := value.Value.(*sandboxProfiles)
		if sandbox.value.Uid != key.Name {
			return nil, fmt.Errorf("Sandbox resource name does not match its body")
		}
		if workloadUID == "" || sandbox.value.GetAttester().GetWorkloadUid() != workloadUID {
			return nil, fmt.Errorf("Sandbox %q is not hosted by workload %q", key.Name, workloadUID)
		}
		if sandbox.profile != nil {
			refs = append(refs, &sandbox.profile.Meta)
		}
		return refs, nil
	}
	profile := value.Value.(*securityprofile.Profile)
	name := "global/" + profile.Meta.Name
	if profile.Meta.Namespace != "" {
		name = "namespaced/" + profile.Meta.Namespace + "/" + profile.Meta.Name
	}
	if key.Name != name {
		return nil, fmt.Errorf("SecurityProfile resource name does not match its body")
	}
	return append(refs, &profile.Meta), nil
}
