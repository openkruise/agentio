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

// Package store provides transport-independent resource queries for EPE.
package store

import "context"

// Type identifies a resource model, independently of its transport encoding.
type Type string

// Resource types currently consumed by EPE through the aggregate.
const (
	Workload        Type = "Workload"
	SecurityProfile Type = "SecurityProfile"
	Sandbox         Type = "Sandbox"
)

// Key identifies a resource. Name is an opaque, source-independent resource ID.
// Namespaced resources may use namespace/name; Workloads use their UID.
type Key struct {
	Type Type
	Name string
}

// Resource carries a typed resource value. Consumers must treat it as read-only.
// All stores serving a Type must use the same value model and name convention.
type Resource struct {
	Key   Key
	Value any
}

// Store supplies local resources and explicit on-demand retrieval.
// A nil resource with no error means not found. Errors must not be interpreted
// as absence. Types is fixed for the lifetime of a store.
type Store interface {
	Types() []Type
	// Status observes readiness and a change signal without reading resources.
	Status() Status
	// Read captures one immutable backend batch across its resource types.
	Read() Batch
	// Fetch retrieves a resource and makes it available to subsequent Get/List calls.
	Fetch(context.Context, Key) (*Resource, error)
}

// Status describes one backend publication. On resource or readiness changes,
// the backend closes Changed and replaces it with a new channel. Observers must
// capture readiness and the channel together to avoid missing an update.
// A nil Changed is allowed for a static store.
type Status struct {
	Ready   bool
	Changed <-chan struct{}
}

// Batch is one backend publication. Status, resources and errors are captured together.
// The map and snapshots must be immutable; unchanged types retain their snapshot.
type Batch struct {
	Status
	Snapshots map[Type]TypeSnapshot
}
