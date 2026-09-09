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
package filter

import "slices"

// HeaderOpKind distinguishes the three header operations. HeaderOps is an
// ordered list, not a map, because ordered multi-value headers
// (set-cookie) cannot be expressed by map[string]string.
type HeaderOpKind uint8

const (
	// HeaderSet overwrites all existing values of the header.
	HeaderSet HeaderOpKind = iota
	// HeaderAdd adds one value without replacing existing values.
	HeaderAdd
	// HeaderRemove deletes the header. Envoy rejects REMOVE of
	// pseudo-headers and host unconditionally.
	HeaderRemove
)

// HeaderOp is one ordered header operation.
type HeaderOp struct {
	Kind  HeaderOpKind
	Name  string
	Value string
}

// Mutation is the plain, proto-free change set a filter returns. A filter
// must not modify a Mutation after returning it; the engine folds without
// deep-copying.
type Mutation struct {
	HeaderOps []HeaderOp
	// Body: nil = unchanged; non-nil (including empty) = replace.
	Body []byte
	// StatusCode is a response-only status replacement. nil leaves the
	// upstream status unchanged.
	StatusCode *int
	// Route is request-only. nil leaves routing unchanged.
	Route *RouteMutation
}

func (m Mutation) equal(o Mutation) bool {
	return m.Route.equal(o.Route) &&
		equalIntPointer(m.StatusCode, o.StatusCode) &&
		slices.Equal(m.Body, o.Body) &&
		slices.Equal(m.HeaderOps, o.HeaderOps)
}

func equalIntPointer(a, b *int) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// SetHeader builds a single-op mutation overwriting name with value.
func SetHeader(name, value string) Mutation {
	return Mutation{HeaderOps: []HeaderOp{{Kind: HeaderSet, Name: name, Value: value}}}
}

// AddHeader builds a single-op mutation adding one value.
func AddHeader(name, value string) Mutation {
	return Mutation{HeaderOps: []HeaderOp{{Kind: HeaderAdd, Name: name, Value: value}}}
}

// RemoveHeader builds a single-op mutation removing the header.
func RemoveHeader(name string) Mutation {
	return Mutation{HeaderOps: []HeaderOp{{Kind: HeaderRemove, Name: name}}}
}

// SetPath rewrites :path. The caller explicitly chooses whether Envoy should
// re-evaluate the route; changing the path alone does not clear its cache.
func SetPath(path string, clearCache bool) Mutation {
	return Mutation{
		HeaderOps: []HeaderOp{{Kind: HeaderSet, Name: ":path", Value: path}},
		Route:     &RouteMutation{ClearCache: clearCache},
	}
}

// Reply is a blocking local response, translated to an ext_proc
// ImmediateResponse by the adapter.
type Reply struct {
	Status int
	// HeaderOps are applied to the response Envoy synthesizes. Ordered ops
	// rather than map[string]string for the reason given above: a map cannot
	// express two values of one header, nor set versus append.
	//
	// HeaderRemove is inert here. Envoy applies these mutations while the local
	// reply holds only :status, which is unremovable, and adds content-type and
	// content-length afterwards, so a removal has nothing to hit. Whoever
	// validates untrusted ops should reject a removal rather than let it look
	// effective.
	HeaderOps []HeaderOp
	Body      []byte
	// Details feeds RESPONSE_CODE_DETAILS; the framework may synthesize it.
	Details string
}

func (r Reply) equal(o Reply) bool {
	return r.Status == o.Status && r.Details == o.Details &&
		slices.Equal(r.Body, o.Body) && slices.Equal(r.HeaderOps, o.HeaderOps)
}
