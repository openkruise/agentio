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
// profile.go is the compiled SecurityProfile: the Meta identity subset
// distilled from a SecurityProfile / GlobalSecurityProfile CRD together
// with its pre-parsed label selector and pre-compiled rule matchers, so the
// request hot path skips selector and regex re-parsing on every match. The
// original CRD object is intentionally not retained.
//
// Matching stays CRD-typed on purpose: only the actions half of a rule is
// pluggable, so there is no neutral matching vocabulary to factor out —
// matching belongs to the API, action configuration belongs to the filters.
package securityprofile

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/utils/ptr"

	"istio.io/istio/extensions/epe/pkg/audit"
	"istio.io/istio/extensions/epe/pkg/httpreq"
)

// pathMatcher is a pre-compiled path matcher for a single PathMatch entry.
type pathMatcher struct {
	Type  v1alpha1.PathMatchType
	Value string
	Re    *regexp.Regexp // non-nil only when Type == Regex
}

// stringMatcher is a pre-compiled string matcher for HeaderMatch / QueryParamMatch.
type stringMatcher struct {
	Name  string
	Type  v1alpha1.StringMatchType
	Value string
	Re    *regexp.Regexp // non-nil only when Type == Regex
}

// Match holds pre-compiled matching information for a single v1alpha1.RuleMatch.
// It encapsulates domain, path, method, port, header, and query-param matching
// with regexps compiled once at profile load time.
type Match struct {
	Domains     []string
	Paths       []pathMatcher
	Methods     []string
	Ports       []int32
	Schemes     []string
	Headers     []stringMatcher
	QueryParams []stringMatcher
}

// compileRuleMatch compiles a v1alpha1.RuleMatch into a Match with
// pre-compiled regexps. An uncompilable pattern is returned as an error: it is
// a static authoring error, and the alternative — a nil matcher that never
// matches — silently stops a block rule from firing.
func compileRuleMatch(raw v1alpha1.RuleMatch) (Match, error) {
	rm := Match{
		Domains: raw.Domains,
		Methods: raw.Methods,
		Ports:   raw.Ports,
		Schemes: raw.Schemes,
	}

	for _, p := range raw.Paths {
		pm := pathMatcher{Type: p.Type, Value: p.Value}
		if p.Type == v1alpha1.PathMatchTypeRegex {
			re, err := regexp.Compile(p.Value)
			if err != nil {
				return Match{}, fmt.Errorf("path regex %q: %w", p.Value, err)
			}
			pm.Re = re
		}
		rm.Paths = append(rm.Paths, pm)
	}

	for _, h := range raw.Headers {
		sm := stringMatcher{Name: strings.ToLower(h.Name), Type: h.Type, Value: h.Value}
		if h.Type == v1alpha1.StringMatchTypeRegex {
			re, err := regexp.Compile(h.Value)
			if err != nil {
				return Match{}, fmt.Errorf("header %q regex %q: %w", h.Name, h.Value, err)
			}
			sm.Re = re
		}
		rm.Headers = append(rm.Headers, sm)
	}

	for _, q := range raw.QueryParams {
		sm := stringMatcher{Name: q.Name, Type: q.Type, Value: q.Value}
		if q.Type == v1alpha1.StringMatchTypeRegex {
			re, err := regexp.Compile(q.Value)
			if err != nil {
				return Match{}, fmt.Errorf("queryParam %q regex %q: %w", q.Name, q.Value, err)
			}
			sm.Re = re
		}
		rm.QueryParams = append(rm.QueryParams, sm)
	}

	return rm, nil
}

// Matches checks if the request matches this compiled Match condition.
// All specified sub-conditions must be satisfied (AND semantics).
func (rm *Match) Matches(req *httpreq.HTTPRequest) bool {
	if !rm.matchDomain(req.Host) {
		return false
	}
	if len(rm.Paths) > 0 && !rm.matchPath(req.Path) {
		return false
	}
	if len(rm.Methods) > 0 && !rm.matchMethod(req.Method) {
		return false
	}
	if len(rm.Ports) > 0 && !rm.matchPort(req.Port) {
		return false
	}
	if len(rm.Schemes) > 0 && !rm.matchScheme(req.Scheme) {
		return false
	}
	if len(rm.Headers) > 0 && !rm.matchHeaders(req.Headers) {
		return false
	}
	if len(rm.QueryParams) > 0 && !rm.matchQueryParams(req.Query) {
		return false
	}
	return true
}

func (rm *Match) matchDomain(host string) bool {
	if len(rm.Domains) == 0 {
		return false
	}
	for _, domain := range rm.Domains {
		if domain == "*" {
			return true
		}
		if strings.HasPrefix(domain, "*.") {
			suffix := domain[1:]
			if len(host) > len(suffix) && strings.EqualFold(host[len(host)-len(suffix):], suffix) {
				return true
			}
			continue
		}
		if strings.EqualFold(host, domain) {
			return true
		}
	}
	return false
}

func (rm *Match) matchPath(path string) bool {
	for i := range rm.Paths {
		pm := &rm.Paths[i]
		switch pm.Type {
		case v1alpha1.PathMatchTypeExact:
			if path == pm.Value {
				return true
			}
		// An empty type means the value never went through API-server
		// defaulting; follow the CRD's own default (Prefix) instead of
		// falling off the switch and never matching. The string matchers
		// below do the same with their Exact default.
		case "", v1alpha1.PathMatchTypePrefix:
			if strings.HasPrefix(path, pm.Value) {
				return true
			}
		case v1alpha1.PathMatchTypeRegex:
			// Re is non-nil by construction: compileRuleMatch rejects a
			// pattern it cannot compile, so there is no nil case to fall
			// through to.
			if pm.Re.MatchString(path) {
				return true
			}
		}
	}
	return false
}

func (rm *Match) matchMethod(method string) bool {
	for _, m := range rm.Methods {
		if strings.EqualFold(method, m) {
			return true
		}
	}
	return false
}

func (rm *Match) matchPort(port int32) bool {
	if port == 0 {
		return false
	}
	for _, p := range rm.Ports {
		if p == port {
			return true
		}
	}
	return false
}

func (rm *Match) matchScheme(scheme string) bool {
	for _, s := range rm.Schemes {
		if strings.EqualFold(s, scheme) {
			return true
		}
	}
	return false
}

func (rm *Match) matchHeaders(reqHeaders map[string]string) bool {
	for i := range rm.Headers {
		h := &rm.Headers[i]
		val, ok := reqHeaders[h.Name]
		if !ok {
			return false
		}
		if !h.matchValue(val) {
			return false
		}
	}
	return true
}

func (sm *stringMatcher) matchValue(val string) bool {
	switch sm.Type {
	case "", v1alpha1.StringMatchTypeExact:
		return val == sm.Value
	case v1alpha1.StringMatchTypePrefix:
		return strings.HasPrefix(val, sm.Value)
	case v1alpha1.StringMatchTypeRegex:
		// Non-nil by construction — see matchPath.
		return sm.Re.MatchString(val)
	default:
		return false
	}
}

func (rm *Match) matchQueryParams(query url.Values) bool {
	for i := range rm.QueryParams {
		q := &rm.QueryParams[i]
		vals, ok := query[q.Name]
		if !ok || len(vals) == 0 {
			return false
		}
		if !q.matchValue(vals[0]) {
			return false
		}
	}
	return true
}

// Rule holds pre-compiled match conditions for a single CRD rule.
// Audits holds the rule-level audit entries compiled once at write time so the
// request hot path reuses them without recompiling.
type Rule struct {
	Name    string
	Actions v1alpha1.SecurityRuleActions
	Matches []Match
	Audits  []*audit.Audit
}

// MatchesRequest returns true if the request matches ANY of this rule's conditions.
func (cr *Rule) MatchesRequest(req *httpreq.HTTPRequest) bool {
	for i := range cr.Matches {
		if cr.Matches[i].Matches(req) {
			return true
		}
	}
	return false
}

// MatchingIndex returns the zero-based index of the first match clause that
// satisfies req, or -1 when no entry matches. Equivalent in trigger
// semantics to MatchesRequest but exposes which match fired so callers
// can attribute the decision (used by the audit stream logger to rebuild
// MatchedCriteria without re-running the matcher).
func (cr *Rule) MatchingIndex(req *httpreq.HTTPRequest) int {
	for i := range cr.Matches {
		if cr.Matches[i].Matches(req) {
			return i
		}
	}
	return -1
}

// compileRules compiles all rules from a Profile spec into Rules. The first
// matcher that fails to compile rejects the whole profile: a partially
// compiled profile would apply some of its author's intent and silently drop
// the rest.
func compileRules(rules []v1alpha1.SecurityRule) ([]Rule, error) {
	compiled := make([]Rule, len(rules))
	for i, rule := range rules {
		cr := Rule{
			Name:    rule.Name,
			Actions: rule.Actions,
		}
		for j, m := range rule.Match {
			cm, err := compileRuleMatch(m)
			if err != nil {
				return nil, fmt.Errorf("rule %q match %d: %w", rule.Name, j, err)
			}
			cr.Matches = append(cr.Matches, cm)
		}
		compiled[i] = cr
	}
	return compiled, nil
}

// Meta holds the subset of a v1alpha1.SecurityProfile /
// v1alpha1.GlobalSecurityProfile object retained after compilation:
// identity (for logging, audit context, metrics) and ordering keys (for
// deterministic evaluation order). The raw typed CRD object is
// intentionally not kept, so both the namespace-scoped and cluster-scoped
// variants collapse to the same in-memory representation.
type Meta struct {
	Name string
	// Namespace is empty for cluster-scoped GlobalSecurityProfile objects.
	Namespace         string
	CreationTimestamp metav1.Time
	Priority          int32
	// Version is the source object's resourceVersion, captured so
	// downstream projection caches can key on (identity, version).
	Version string
	// Source identifies the object kind the profile was compiled from:
	// empty for SecurityProfile/GlobalSecurityProfile, SourceInline for
	// per-Sandbox annotation chains. A Sandbox and a SecurityProfile in one
	// namespace may share a name and even a resourceVersion, so caches keyed
	// on namespace/name must include the source to stay collision-free.
	Source string
}

// SourceInline marks profiles compiled from the per-Sandbox inline security
// rules annotation rather than from a SecurityProfile CR.
const SourceInline = "inline"

// Profile is the in-memory representation of a Profile or
// GlobalSecurityProfile with its label selector, rule regexps, and audit
// entries compiled once at write time.
type Profile struct {
	Meta     Meta
	Selector labels.Selector
	Rules    []Rule         // parallel to the source Spec.Rules
	Audits   []*audit.Audit // spec-level compiled audit entries
	// Inputs is the immutable, profile-scoped snapshot resolved while the
	// profile's krt collection item is compiled. Each value is a
	// map[string]string sourced from either inline data or a ConfigMap.
	Inputs map[string]any
	// CompileError is populated only on identity-bearing invalid collection
	// items. The profile store uses such items to retain the prior effective
	// profile instead of treating an invalid update as a deletion.
	CompileError string
}

// ResourceName implements krt.ResourceNamer so compiled profiles can be held
// in krt collections. Cluster-scoped GlobalSecurityProfiles (empty namespace)
// key by bare name and namespaced SecurityProfiles key by namespace/name, so
// the two scopes can never collide inside a joined collection. Inline
// profiles carry a source prefix on top: a Sandbox and a SecurityProfile in
// the same namespace can share a name, and without the prefix one would
// silently replace the other in a joined collection.
func (sp Profile) ResourceName() string {
	name := sp.Meta.Name
	if sp.Meta.Namespace != "" {
		name = sp.Meta.Namespace + "/" + sp.Meta.Name
	}
	if sp.Meta.Source != "" {
		return sp.Meta.Source + "/" + name
	}
	return name
}

// NewProfile converts a SecurityProfile / GlobalSecurityProfile into
// a *Profile with a pre-parsed label selector and pre-compiled
// rule regexps and audit entries. The scope difference between the two CRD
// variants is erased here: obj supplies identity via metav1.Object and spec
// supplies the shared SecurityProfileSpec, so the rest of the pipeline treats
// both uniformly.
//
// Returns an error if the selector is invalid, any matcher regex fails to
// compile, or any audit entry fails to compile. The caller rejects that
// candidate; the profile store may continue serving LKG.
func NewProfile(obj metav1.Object, spec *v1alpha1.SecurityProfileSpec) (*Profile, error) {
	selector, err := metav1.LabelSelectorAsSelector(&spec.Selector)
	if err != nil {
		return nil, err
	}
	meta := Meta{
		Name:              obj.GetName(),
		Namespace:         obj.GetNamespace(),
		CreationTimestamp: obj.GetCreationTimestamp(),
		Priority:          ptr.Deref(spec.Priority, v1alpha1.DefaultSecurityProfilePriority),
		Version:           obj.GetResourceVersion(),
	}
	rules, err := compileRules(spec.Rules)
	if err != nil {
		return nil, err
	}
	sp := &Profile{
		Meta:     meta,
		Selector: selector,
		Rules:    rules,
	}
	if err := sp.compileAudits(spec); err != nil {
		return nil, err
	}
	return sp, nil
}

// InvalidProfile returns an identity-bearing collection item for a source
// object that failed compilation. It is never eligible for matching; the
// profile store recognizes CompileError and retains any last-known-good
// profile under the same identity.
func InvalidProfile(obj metav1.Object, spec *v1alpha1.SecurityProfileSpec, err error) *Profile {
	message := "invalid profile"
	if err != nil {
		message = err.Error()
	}
	return &Profile{
		Meta: Meta{
			Name:              obj.GetName(),
			Namespace:         obj.GetNamespace(),
			CreationTimestamp: obj.GetCreationTimestamp(),
			Priority:          ptr.Deref(spec.Priority, v1alpha1.DefaultSecurityProfilePriority),
			Version:           obj.GetResourceVersion(),
		},
		CompileError: message,
	}
}

// compileAudits pre-compiles every audit entry on the profile — both the
// spec-level Audit list and any rule-level overrides — attaching the results
// to the Profile and its Rules. It returns the first
// compilation error so the caller can drop the whole profile.
func (sp *Profile) compileAudits(spec *v1alpha1.SecurityProfileSpec) error {
	if len(spec.Audit) > 0 {
		specCompiled, err := compileAuditList(spec.Audit)
		if err != nil {
			return fmt.Errorf("spec: %w", err)
		}
		sp.Audits = specCompiled
	}
	for i := range sp.Rules {
		cr := &sp.Rules[i]
		if len(cr.Actions.Audit) == 0 {
			continue
		}
		ruleCompiled, err := compileAuditList(cr.Actions.Audit)
		if err != nil {
			return fmt.Errorf("rule %q: %w", cr.Name, err)
		}
		cr.Audits = ruleCompiled
	}
	return nil
}

// SortProfiles sorts a slice of Profile pointers in evaluation order:
// lower priority first, then earlier creationTimestamp, then name ascending,
// then namespace ascending. This is the canonical ordering used throughout the
// EPE pipeline (profile store snapshot build, admin debug output,
// ext-proc request evaluation).
//
// Namespace is the final tie-break so the comparator is a total order: a
// cluster-scoped GlobalSecurityProfile (empty namespace) and a namespaced
// Profile can share the same name, priority (default 1000), and
// second-precision creationTimestamp. Without this key sort.Slice (unstable)
// would leave their relative order — and thus which action wins — undefined.
// Empty namespace sorts first, so an exact-tie global profile is evaluated
// before its namespaced namesake.
func SortProfiles(profiles []*Profile) {
	sort.Slice(profiles, func(i, j int) bool {
		pi, pj := profiles[i].Meta.Priority, profiles[j].Meta.Priority
		if pi != pj {
			return pi < pj
		}
		ci, cj := profiles[i].Meta.CreationTimestamp, profiles[j].Meta.CreationTimestamp
		if !ci.Equal(&cj) {
			return ci.Before(&cj)
		}
		if profiles[i].Meta.Name != profiles[j].Meta.Name {
			return profiles[i].Meta.Name < profiles[j].Meta.Name
		}
		return profiles[i].Meta.Namespace < profiles[j].Meta.Namespace
	})
}
