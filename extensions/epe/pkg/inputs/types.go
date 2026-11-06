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
package inputs

import (
	"strings"

	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
)

// Workload is the source Workload's expression view. Exposed to templates as
// {{ .Pod.* }} and projected into CEL activations as the `pod` variable.
type Workload struct {
	Name      string
	Namespace string
	IP        string
	Labels    map[string]string
}

// WorkloadFromSubject preserves the expression vocabulary independently of policy identity.
func WorkloadFromSubject(subject subject.Subject) Workload {
	w := subject.Workload
	return Workload{Name: w.Name, Namespace: w.Namespace, IP: w.IP, Labels: w.Labels}
}

// Label returns the named workload label value, or empty string when absent.
func (p Workload) Label(key string) string {
	if p.Labels == nil {
		return ""
	}
	return p.Labels[key]
}

// Request exposes the matched HTTP request to templates and CEL.
type Request struct {
	DNSCandidates []string
	Host          string
	Port          int32
	Path          string
	Scheme        string
	Method        string
	Query         map[string][]string
	headers       map[string]string // lowercase keys (Envoy convention)
}

// RequestFrom projects the transport tuple into the expression-visible
// Request view. All fields are forwarded deliberately; a future HTTPRequest
// field carrying sensitive data must be excluded here — this function is
// the exposure choke point. Maps are shared, not copied; Headers is
// lowercase-keyed by httpreq's contract.
func RequestFrom(r httpreq.HTTPRequest) Request {
	return Request{
		DNSCandidates: r.DNSCandidates,
		Host:          r.Host,
		Port:          r.Port,
		Path:          r.Path,
		Scheme:        r.Scheme,
		Method:        r.Method,
		Query:         r.Query,
		headers:       r.Headers,
	}
}

// Header returns the named header value, case-insensitive. Missing headers
// render as the empty string (no error).
func (r Request) Header(name string) string {
	if r.headers == nil {
		return ""
	}
	return r.headers[strings.ToLower(name)]
}

// QueryParam returns the first value of the named query parameter, or empty
// string when absent.
func (r Request) QueryParam(name string) string {
	if vals, ok := r.Query[name]; ok && len(vals) > 0 {
		return vals[0]
	}
	return ""
}

// Rule describes the matched SecurityRule.
type Rule struct {
	Name string
}

// Profile describes the matched SecurityProfile.
type Profile struct {
	Name      string
	Namespace string
}
