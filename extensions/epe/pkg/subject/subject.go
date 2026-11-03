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

// Package subject defines caller identities and attributes shared by policy backends.
package subject

import "context"

// WorkloadResolver loads metadata and policy references for the captured identity.
type WorkloadResolver func(context.Context, Workload) (Workload, error)

// Subject carries trusted, read-only caller identities and attributes.
// Workload may be empty or partial; Sandbox is an optional execution identity.
// Each policy backend determines which workload fields it needs.
type Subject struct {
	Workload Workload
	Sandbox  *Sandbox
}

// Workload describes the host workload. UID is its discovery resource
// name, not a Kubernetes object UID; metadata supports the local policy backend.
type Workload struct {
	UID       string
	Namespace string
	Name      string
	IP        string
	Labels    map[string]string
	// Nil selects the legacy local matcher; an explicit empty list binds no administrator profiles.
	SecurityProfileReferences []string
}

// Sandbox identifies the request's execution unit by discovery UID.
type Sandbox struct {
	UID string
}

// HasIdentity distinguishes supplied identities from optional request metadata.
func (s Subject) HasIdentity() bool {
	return s.Workload.HasIdentity() || (s.Sandbox != nil && s.Sandbox.UID != "")
}

// HasIdentity accepts either a discovery UID or a complete namespace/name pair.
func (w Workload) HasIdentity() bool {
	return w.UID != "" || (w.Namespace != "" && w.Name != "")
}

// String identifies the workload in diagnostic logs, preferring its discovery UID.
func (w Workload) String() string {
	if w.UID != "" {
		return w.UID
	}
	if w.Namespace == "" && w.Name == "" {
		return ""
	}
	return w.Namespace + "/" + w.Name
}

func (s *Sandbox) String() string {
	if s == nil {
		return ""
	}
	return s.UID
}
