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
package engine

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
)

// Disposition aliases the filter-level type; the engine derives it from
// which Action constructor won.
type Disposition = filter.Disposition

const (
	DispositionPassthrough = filter.DispositionPassthrough
	DispositionMutated     = filter.DispositionMutated
	DispositionBlocked     = filter.DispositionBlocked
	DispositionBypassed    = filter.DispositionBypassed
	DispositionError       = filter.DispositionError
)

// Unit is the engine-facing view of one matched policy unit: identity,
// evaluation scope, and the per-registration projected configs. A policy
// resolver may carry richer attribution alongside it; the engine never sees
// the policy model. Units and their configs remain read-only through body
// processing in both directions.
type Unit struct {
	ID    filter.UnitID
	Scope *inputs.Scope
	// Cfgs[i] is the projected config for registration i; nil when the
	// unit does not carry that filter's config.
	Cfgs []any
}

// Engine evaluates rules in policy order and actions in registration order.
// It records every invocation and unit action into Stream.Info when the
// caller attached one.
type Engine struct {
	regs   []filter.Registration
	budget time.Duration
	// metrics is parallel to regs: metrics[i] holds registration i's
	// pre-resolved Prometheus children for every dispatched phase.
	metrics []regMetrics
}

// NewEngine builds an engine. budget bounds each evaluation phase (one
// ext_proc message); zero disables the bound.
func NewEngine(regs []filter.Registration, budget time.Duration) *Engine {
	frozen := append([]filter.Registration(nil), regs...)
	return &Engine{regs: frozen, budget: budget, metrics: buildMetrics(frozen)}
}

// Registrations exposes the within-rule action order for contract tests.
func (e *Engine) Registrations() []filter.Registration {
	return append([]filter.Registration(nil), e.regs...)
}

// withBudget bounds one evaluation phase. The budget is per ext_proc
// message, not per filter invocation: the flag's contract is that the
// extension answers (or is cancelled) before Envoy's message_timeout,
// which only a phase-wide bound can honor — per-invocation budgets sum
// past it. It also prices to one context per phase instead of one per
// filter call.
func (e *Engine) withBudget(ctx context.Context) (context.Context, context.CancelFunc) {
	if e.budget <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, e.budget)
}

type bodyInvocation struct {
	requirement filter.BodyRequirement
	// f is the live instance that already ran the direction's header callback;
	// the body callback MUST reuse it, not rebuild via reg.New, or header-phase
	// instance state is lost.
	f filter.Filter
	// at identifies the rule and filter for execution records and control flow.
	at evalCursor
}

// evalCursor is a (unit, registration) coordinate. regIdx indexes both
// Engine.regs and Unit.Cfgs, which are parallel by construction — it is an
// index, not the pair.reg Registration value it selects.
type evalCursor struct {
	unit   int
	regIdx int
}

// pair is one (unit, registration) coordinate plus everything dispatch needs.
type pair struct {
	at   evalCursor
	reg  filter.Registration
	unit Unit
	cfg  any
}

// pairs yields every (unit, registration) pair that carries a config for any
// phase in phases, in policy order, starting at start. phases is a mask:
// ValidateSubscriptions passes several at once.
func (e *Engine) pairs(units []Unit, start evalCursor, phases filter.Phase) func(func(pair) bool) {
	return func(yield func(pair) bool) {
		for u := start.unit; u < len(units); u++ {
			regStart := 0
			if u == start.unit {
				regStart = start.regIdx
			}
			for regIdx := regStart; regIdx < len(e.regs); regIdx++ {
				reg := e.regs[regIdx]
				cfg := units[u].Cfgs[regIdx]
				if cfg == nil || reg.Phases&phases == 0 {
					continue
				}
				if !yield(pair{at: evalCursor{unit: u, regIdx: regIdx}, reg: reg, unit: units[u], cfg: cfg}) {
					return
				}
			}
		}
	}
}

// pairAt builds the pair at one cursor, for callers that already know the
// coordinate (the registered body invocation).
func (e *Engine) pairAt(units []Unit, at evalCursor) pair {
	return pair{at: at, reg: e.regs[at.regIdx], unit: units[at.unit], cfg: units[at.unit].Cfgs[at.regIdx]}
}

// bodyState retains callbacks registered during headers and their pending mutations.
type bodyState struct {
	units       []Unit
	bodyFilters []bodyInvocation
	pending     []filter.Mutation
	stream      *bodyStream
}

func (b *bodyState) mode(needed bool) filter.BodyMode {
	if !needed {
		return filter.BodyNone
	}
	if b.stream != nil {
		return filter.BodyStreamed
	}
	return filter.BodyBuffered
}

// SubscribablePhases contains phases that configs may request from Envoy.
// Request bodies are requested dynamically through NeedBody.
const SubscribablePhases = filter.PhaseResponseHeaders

// ResponseScope bounds response-header dispatch after a request-phase bypass.
// The zero value is unbounded; last includes the bypassing pair.
type ResponseScope struct {
	bounded bool
	last    evalCursor
}

// excludes reports whether the pair at (unit, regIdx) lies strictly after the
// bypass point and is therefore suppressed.
func (s ResponseScope) excludes(unit, regIdx int) bool {
	if !s.bounded {
		return false
	}
	return unit > s.last.unit || (unit == s.last.unit && regIdx > s.last.regIdx)
}

// ValidateSubscriptions validates config-requested phases and returns their
// union. It does not invoke filters.
func (e *Engine) ValidateSubscriptions(units []Unit) (filter.Phase, error) {
	if err := e.validateUnits(units); err != nil {
		return 0, err
	}
	var subscriptions filter.Phase
	for p := range e.pairs(units, evalCursor{}, filter.DispatchedPhases) {
		if p.reg.Subscribes == nil {
			continue
		}
		subscribes := p.reg.Subscribes(p.cfg)
		if surplus := subscribes &^ SubscribablePhases; surplus != 0 {
			return 0, fmt.Errorf("filter %q subscribes to phases %08b the engine cannot open; "+
				"widen engine.SubscribablePhases when it learns to", p.reg.Name, surplus)
		}
		subscriptions |= subscribes
	}
	return subscriptions, nil
}

// RequestHeadersResult is the outcome of the headers phase.
type RequestHeadersResult struct {
	Disposition Disposition
	// Reply is valid when Disposition is Blocked. Bypassed preserves mutations
	// produced by earlier actions and skips later header callbacks, while
	// retaining body callbacks already registered.
	Reply filter.Reply
	// HeaderOps is the net-effect folded mutation set, ready for a single
	// proto translation.
	HeaderOps []filter.HeaderOp
	// Route is the folded request routing change. The result owns its nested
	// values; modifying it cannot change filter data or a continuation.
	Route *filter.RouteMutation
	// Body: nil = unchanged; non-nil (including empty) = replace, the same
	// sentinel as filter.Mutation.Body. The last executed action to set one
	// wins.
	Body []byte
	// ResponseScope bounds response-phase dispatch when this walk bypassed;
	// the zero value is unbounded. The adapter carries it to EvalResponseHeaders.
	ResponseScope ResponseScope
	bodyState
}

// NeedsBody reports whether registered request-body callbacks remain to run.
func (r *RequestHeadersResult) NeedsBody() bool {
	return r.Disposition != DispositionBlocked && len(r.bodyFilters) > 0
}

// BodyMode reports the required delivery, or BodyNone when no body is needed.
func (r *RequestHeadersResult) BodyMode() filter.BodyMode {
	return r.mode(r.NeedsBody())
}

// RequestBodyResult is the outcome of the body phase.
type RequestBodyResult struct {
	Disposition Disposition
	Reply       filter.Reply
	HeaderOps   []filter.HeaderOp
	Route       *filter.RouteMutation
	// Body: nil = unchanged; non-nil (including empty) = replace.
	Body []byte
	// ResponseScope retains the headers bypass boundary, narrowed if a body
	// callback bypasses earlier; the zero value is unbounded.
	ResponseScope ResponseScope
}

// ResponseHeadersResult is the outcome of the response-headers phase.
type ResponseHeadersResult struct {
	Disposition Disposition
	// Reply is valid when Disposition is Blocked. The adapter turns it into an
	// ImmediateResponse; Envoy holds the upstream response headers while
	// awaiting our reply, so the local reply replaces them.
	Reply filter.Reply
	// HeaderOps is the net-effect folded mutation set for the response
	// headers, ready for a single proto translation. Empty when blocked.
	HeaderOps []filter.HeaderOp
	// Body: nil = unchanged; non-nil (including empty) = replace. The adapter
	// emits CONTINUE_AND_REPLACE so Envoy applies it from the headers phase.
	Body []byte
	// StatusCode is the last response status replacement; nil leaves the
	// upstream status unchanged.
	StatusCode *int
	bodyState
}

// NeedsBody reports whether registered response-body callbacks remain to run.
func (r *ResponseHeadersResult) NeedsBody() bool {
	return r.Disposition != DispositionBlocked && len(r.bodyFilters) > 0
}

// BodyMode reports the required delivery, or BodyNone when no body is needed.
func (r *ResponseHeadersResult) BodyMode() filter.BodyMode {
	return r.mode(r.NeedsBody())
}

// ResponseBodyResult is the outcome of registered response-body callbacks.
type ResponseBodyResult struct {
	Disposition Disposition
	Reply       filter.Reply
	HeaderOps   []filter.HeaderOp
	// Body: nil = unchanged; non-nil (including empty) = replace.
	Body       []byte
	StatusCode *int
}

// RequestOption configures one request-headers evaluation.
type RequestOption func(*requestOptions)

type requestOptions struct {
	body      *filter.Body
	streaming bool
}

// ResponseOption configures one response-headers evaluation.
type ResponseOption func(*responseOptions)

type responseOptions struct {
	body      *filter.Body
	streaming bool
}

// WithRequestStreaming prefers incremental execution when the remaining chain
// supports it. Incremental capability alone does not request streaming.
func WithRequestStreaming() RequestOption {
	return func(o *requestOptions) { o.streaming = true }
}

// WithResponseStreaming is the response counterpart of WithRequestStreaming.
func WithResponseStreaming() ResponseOption {
	return func(o *responseOptions) { o.streaming = true }
}

// WithAvailableRequestBody runs registered body callbacks after all headers
// callbacks, using the body already in hand. Pass
// it when Envoy set end_of_stream on the headers message: no body will follow,
// so the empty body is final rather than merely not-yet-arrived.
func WithAvailableRequestBody(b filter.Body) RequestOption {
	return func(o *requestOptions) {
		o.body = &b
	}
}

// WithAvailableResponseBody runs registered body callbacks after all response
// headers callbacks, using the complete body already in hand.
// The end_of_stream contract is the same as WithAvailableRequestBody's: an
// end-of-stream response-headers message is the complete bodyless response.
func WithAvailableResponseBody(b filter.Body) ResponseOption {
	return func(o *responseOptions) {
		o.body = &b
	}
}

// EvalRequestHeaders runs header callbacks in rule order. NeedBody registers
// the live filter for the body phase without delaying later header callbacks.
func (e *Engine) EvalRequestHeaders(
	ctx context.Context,
	st *filter.Stream,
	units []Unit,
	opts ...RequestOption,
) (*RequestHeadersResult, error) {
	if err := e.validateUnits(units); err != nil {
		return &RequestHeadersResult{}, err
	}
	var o requestOptions
	for _, opt := range opts {
		opt(&o)
	}
	ctx, cancel := e.withBudget(ctx)
	defer cancel()
	walk, err := e.walkHeaders(ctx, st, units, ResponseScope{}, filter.PhaseRequestHeaders)
	reduced, routeErr := walk.result()
	if err == nil {
		err = routeErr
	}
	res := &RequestHeadersResult{
		Disposition:   reduced.disposition,
		Reply:         reduced.reply,
		HeaderOps:     reduced.headerOps,
		Route:         reduced.route,
		Body:          reduced.body,
		ResponseScope: walk.scope,
		bodyState:     bodyState{units: units, bodyFilters: walk.bodyFilters, pending: walk.pending},
	}
	if err == nil && o.body != nil && res.NeedsBody() {
		br, bodyErr := e.EvalRequestBody(ctx, st, res, *o.body)
		return br.HeadersResult(), bodyErr
	}
	if err == nil && res.NeedsBody() {
		res.prepareStream(e, st, filter.PhaseRequestBody, res.ResponseScope, o.streaming)
	}
	return res, err
}

// HeadersResult renders a completed body phase in a headers response when the
// complete body was already available (including an empty end-of-stream body).
func (r *RequestBodyResult) HeadersResult() *RequestHeadersResult {
	return &RequestHeadersResult{
		Disposition:   r.Disposition,
		Reply:         r.Reply,
		HeaderOps:     r.HeaderOps,
		Route:         r.Route,
		Body:          r.Body,
		ResponseScope: r.ResponseScope,
	}
}

type actionResult struct {
	disposition Disposition
	reply       filter.Reply
	headerOps   []filter.HeaderOp
	route       *filter.RouteMutation
	body        []byte
	statusCode  *int
}

// actionWalk reduces phase-independent Action semantics. Phase walkers select
// pairs, validate capabilities, and handle continuation around it.
type actionWalk struct {
	st          *filter.Stream
	disposition Disposition
	reply       filter.Reply
	pending     []filter.Mutation
}

// newActionWalk starts a walk over st, which must be non-nil: the walk records
// unit actions through it unconditionally. A nil st.Info is fine — StreamInfo's
// mutators tolerate a nil receiver — so callers that want no accounting pass
// &filter.Stream{} rather than nil.
func newActionWalk(st *filter.Stream) actionWalk {
	return actionWalk{st: st, disposition: DispositionPassthrough}
}

type phaseWalk struct {
	actionWalk
	phase       filter.Phase
	scope       ResponseScope
	bodyFilters []bodyInvocation
	view        *filter.Stream
	viewed      int
	route       *filter.RouteMutation
}

// record keeps phase walkers from restating the unit and filter already
// carried by a pair. StreamInfo's mutators tolerate a nil receiver.
func (w *actionWalk) record(p pair, kind filter.UnitActionKind) {
	w.st.Info.RecordUnitAction(p.unit.ID, p.reg.Name, kind)
}

// resolved reports the disposition a finished walk settles on: a walk that
// accumulated mutations but reached no verdict is Mutated.
func (w *actionWalk) resolved() Disposition {
	if w.disposition == DispositionPassthrough && len(w.pending) > 0 {
		return DispositionMutated
	}
	return w.disposition
}

func (w *actionWalk) result() (actionResult, error) {
	headerOps, route, body, statusCode, err := foldPending(w.pending)
	if err != nil {
		return actionResult{disposition: DispositionError}, err
	}
	return actionResult{
		disposition: w.resolved(),
		reply:       w.reply,
		headerOps:   headerOps,
		route:       route,
		body:        body,
		statusCode:  statusCode,
	}, nil
}

// halted reports whether the walk stopped. These three dispositions are the
// complete set that ends a walk; nothing else may.
func (w *actionWalk) halted() bool {
	switch w.disposition {
	case DispositionBlocked, DispositionBypassed, DispositionError:
		return true
	}
	return false
}

// invokeBody runs one filter's body callback and folds the result into w. It is
// the whole body ladder — invoke, resolve a failure through the registration's
// policy, validate, fold — shared by both directions and by both the inline and
// deferred body delivery.
//
// halted reports that the walk must stop; err is a contract violation that
// aborts evaluation. A failure the policy opened over returns (false, nil), so
// the caller proceeds to the next registered body callback.
func (e *Engine) invokeBody(
	ctx context.Context,
	st *filter.Stream,
	w *phaseWalk,
	p pair,
	phase filter.Phase,
	requirement filter.BodyRequirement,
	m *filterMetrics,
	call func(context.Context) (filter.Action, error),
) (halted bool, err error) {
	act, invokeErr := e.invoke(ctx, st, m, call)
	if invokeErr != nil {
		w.filterFailed(p, phase, invokeErr)
		return w.halted(), nil
	}
	if err := validateAction(p.reg, phase, act); err != nil {
		return false, err
	}
	if requirement == filter.IncrementalBody {
		if err := validateIncrementalAction(p.reg, act); err != nil {
			return false, err
		}
	}
	if err := w.apply(p, act); err != nil {
		return false, err
	}
	return w.halted(), nil
}

// walkHeaders registers body callbacks without delaying later headers in either direction.
func (e *Engine) walkHeaders(
	ctx context.Context,
	st *filter.Stream,
	units []Unit,
	scope ResponseScope,
	phase filter.Phase,
) (phaseWalk, error) {
	walk := phaseWalk{actionWalk: newActionWalk(st), scope: scope, phase: phase}
	for p := range e.pairs(units, evalCursor{}, phase) {
		if phase == filter.PhaseResponseHeaders && (scope.excludes(p.at.unit, p.at.regIdx) ||
			p.reg.Subscribes == nil || p.reg.Subscribes(p.cfg)&phase == 0) {
			continue
		}
		view := st
		if phase == filter.PhaseRequestHeaders {
			var err error
			view, err = walk.streamView()
			if err != nil {
				return walk, err
			}
		}
		f := p.reg.New(filter.ErasedRuleConfig{ID: p.unit.ID, Cfg: p.cfg, Scope: p.unit.Scope})
		m, call := e.metrics[p.at.regIdx].requestHeaders, f.OnRequestHeaders
		if phase == filter.PhaseResponseHeaders {
			m, call = e.metrics[p.at.regIdx].responseHeaders, f.OnResponseHeaders
		}
		act, invokeErr := e.invoke(ctx, st, m,
			func(ctx context.Context) (filter.Action, error) { return call(ctx, view) })
		if invokeErr != nil {
			walk.filterFailed(p, phase, invokeErr)
			if walk.halted() {
				return walk, nil
			}
			continue
		}
		if err := validateAction(p.reg, phase, act); err != nil {
			return walk, err
		}
		if act.Kind() == filter.KindNeedBody {
			walk.pending = append(walk.pending, act.Mutations()...)
			walk.bodyFilters = append(walk.bodyFilters, bodyInvocation{
				at:          p.at,
				f:           f,
				requirement: act.BodyRequirement(),
			})
			walk.record(p, filter.ActionNeedBody)
			continue
		}
		if err := walk.apply(p, act); err != nil {
			return walk, err
		}
		if walk.halted() {
			return walk, nil
		}
	}
	return walk, nil
}

// streamView exposes the accumulated target without changing the original
// request tuple. Filters borrow read-only views; only a routing mutation needs
// a new view. Scan each pending mutation once as the header walk advances.
func (w *phaseWalk) streamView() (*filter.Stream, error) {
	route, err := foldRouteFrom(w.route, w.pending[w.viewed:])
	if err != nil {
		return nil, err
	}
	w.viewed = len(w.pending)
	if w.view == nil || route != w.route {
		w.view = w.st
		if route != nil || w.st.Upstream != nil {
			view := *w.st
			view.Upstream = nil
			if route != nil {
				view.Upstream = route.Upstream
			}
			w.view = &view
		}
		w.route = route
	}
	return w.view, nil
}

// apply folds the Action kinds shared by request and response phases. Only
// Stop, Bypass and Continue can arrive here: validateAction runs first and
// rejects NeedBody outside the two header phases, and the header phases
// intercept it before folding. The default arm therefore reports an engine
// bug, not a filter one.
func (w *actionWalk) apply(p pair, act filter.Action) error {
	switch act.Kind() {
	case filter.KindStop:
		w.reply, _ = act.Reply()
		w.disposition = DispositionBlocked
		w.pending = nil
		w.record(p, filter.ActionBlock)
		return nil
	case filter.KindBypass:
		w.disposition = DispositionBypassed
		w.record(p, filter.ActionBypass)
		return nil
	case filter.KindContinue:
		if len(act.Mutations()) > 0 {
			w.pending = append(w.pending, act.Mutations()...)
			w.record(p, filter.ActionMutate)
		}
		return nil
	default:
		return fmt.Errorf("filter %q returned action kind %d the walk cannot fold; "+
			"validateAction should have rejected it first", p.reg.Name, act.Kind())
	}
}

// apply adds the request direction's cross-phase Bypass scope to the common
// Action reduction. Request-header NeedBody is handled before this method.
func (w *phaseWalk) apply(p pair, act filter.Action) error {
	if err := w.actionWalk.apply(p, act); err != nil {
		return err
	}
	if act.Kind() == filter.KindBypass &&
		(w.phase == filter.PhaseRequestHeaders || w.phase == filter.PhaseRequestBody) {
		// The pairs after this one are skipped in this walk AND in the
		// response phase; the scope is how the suppression reaches there.
		w.scope = ResponseScope{bounded: true, last: p.at}
	}
	return nil
}

// EvalRequestBody runs only the body callbacks registered during headers, in
// registration order. All callbacks see the original request and body. Header
// mutations remain pending until this phase completes, then body mutations win.
func (e *Engine) EvalRequestBody(
	ctx context.Context,
	st *filter.Stream,
	prior *RequestHeadersResult,
	body filter.Body,
) (*RequestBodyResult, error) {
	if prior != nil && prior.BodyMode() == filter.BodyStreamed {
		return nil, fmt.Errorf("streamed request body requires EvalRequestBodyChunk")
	}
	ctx, cancel := e.withBudget(ctx)
	defer cancel()
	res := &RequestBodyResult{Disposition: DispositionPassthrough}
	if prior == nil || !prior.NeedsBody() {
		return res, nil
	}
	walk := phaseWalk{actionWalk: newActionWalk(st), scope: prior.ResponseScope, phase: filter.PhaseRequestBody}
	walk.pending = append([]filter.Mutation(nil), prior.pending...)
	view := *st
	if prior.Route != nil {
		view.Upstream = prior.Route.Upstream
	}
	err := e.walkBody(ctx, st, &view, &walk, &prior.bodyState, body)
	if !walk.halted() && prior.Disposition == DispositionBypassed {
		walk.disposition = DispositionBypassed
	}
	reduced, routeErr := walk.result()
	if err == nil {
		err = routeErr
	}
	res.Disposition = reduced.disposition
	res.Reply = reduced.reply
	res.HeaderOps = reduced.headerOps
	res.Route = reduced.route
	if res.Disposition != DispositionBlocked && prior.Route != nil {
		// Preserve the target pinned after headers; body cannot select a new one.
		res.Route = prior.Route
	}
	res.Body = reduced.body
	res.ResponseScope = walk.scope
	return res, err
}

// walkBody executes only registered callbacks, preserving their original input view.
func (e *Engine) walkBody(
	ctx context.Context,
	st, view *filter.Stream,
	walk *phaseWalk,
	state *bodyState,
	body filter.Body,
) error {
	for _, invocation := range state.bodyFilters {
		p := e.pairAt(state.units, invocation.at)
		m, call := e.metrics[p.at.regIdx].requestBody, invocation.f.OnRequestBody
		if walk.phase == filter.PhaseResponseBody {
			m, call = e.metrics[p.at.regIdx].responseBody, invocation.f.OnResponseBody
		}
		halted, err := e.invokeBody(ctx, st, walk, p, walk.phase, invocation.requirement, m,
			func(ctx context.Context) (filter.Action, error) { return call(ctx, view, body) })
		if err != nil || halted {
			return err
		}
	}
	return nil
}

// FailClosed uses 500 rather than 403 because a filter invocation failure is
// a server-side fault, not a policy deny.
const failClosedStatus = 500

// EvalResponseHeaders runs subscribed headers within scope, then selects body delivery.
func (e *Engine) EvalResponseHeaders(
	ctx context.Context,
	st *filter.Stream,
	units []Unit,
	scope ResponseScope,
	opts ...ResponseOption,
) (*ResponseHeadersResult, error) {
	res := &ResponseHeadersResult{Disposition: DispositionPassthrough}
	subscriptions, err := e.ValidateSubscriptions(units)
	if err != nil {
		return res, err
	}
	if subscriptions&filter.PhaseResponseHeaders == 0 {
		return res, nil
	}
	var o responseOptions
	for _, opt := range opts {
		opt(&o)
	}
	ctx, cancel := e.withBudget(ctx)
	defer cancel()
	walk, err := e.walkHeaders(ctx, st, units, scope, filter.PhaseResponseHeaders)
	reduced, foldErr := walk.result()
	if err == nil {
		err = foldErr
	}
	res.Disposition, res.Reply = reduced.disposition, reduced.reply
	res.HeaderOps, res.Body, res.StatusCode = reduced.headerOps, reduced.body, reduced.statusCode
	res.bodyState = bodyState{units: units, bodyFilters: walk.bodyFilters, pending: walk.pending}
	if err == nil && o.body != nil && res.NeedsBody() {
		br, bodyErr := e.EvalResponseBody(ctx, st, res, *o.body)
		return &ResponseHeadersResult{
			Disposition: br.Disposition,
			Reply:       br.Reply,
			HeaderOps:   br.HeaderOps,
			Body:        br.Body,
			StatusCode:  br.StatusCode,
		}, bodyErr
	}
	if err == nil && res.NeedsBody() {
		res.prepareStream(e, st, filter.PhaseResponseBody, scope, o.streaming)
	}
	return res, err
}

// EvalResponseBody runs registered body callbacks after all response headers.
func (e *Engine) EvalResponseBody(
	ctx context.Context,
	st *filter.Stream,
	prior *ResponseHeadersResult,
	body filter.Body,
) (*ResponseBodyResult, error) {
	if prior != nil && prior.BodyMode() == filter.BodyStreamed {
		return nil, fmt.Errorf("streamed response body requires EvalResponseBodyChunk")
	}
	ctx, cancel := e.withBudget(ctx)
	defer cancel()
	res := &ResponseBodyResult{Disposition: DispositionPassthrough}
	if prior == nil || !prior.NeedsBody() {
		return res, nil
	}
	walk := phaseWalk{actionWalk: newActionWalk(st), phase: filter.PhaseResponseBody}
	walk.pending = append([]filter.Mutation(nil), prior.pending...)
	err := e.walkBody(ctx, st, st, &walk, &prior.bodyState, body)
	if !walk.halted() && prior.Disposition == DispositionBypassed {
		walk.disposition = DispositionBypassed
	}
	reduced, foldErr := walk.result()
	if err == nil {
		err = foldErr
	}
	res.Disposition, res.Reply = reduced.disposition, reduced.reply
	res.HeaderOps, res.Body, res.StatusCode = reduced.headerOps, reduced.body, reduced.statusCode
	return res, err
}

// filterFailed resolves an invocation error through the registration's policy.
// The original error was already retained by invoke in StreamInfo.Filters.
func (w *actionWalk) filterFailed(p pair, phase filter.Phase, err error) {
	if failurePolicy(p.reg, p.cfg) == filter.FailOpen {
		w.record(p, filter.ActionErrorOpen)
		return
	}
	w.pending = nil
	w.disposition = DispositionBlocked
	w.reply = filter.Reply{Status: failClosedStatus, Details: failClosedDetails(phase)}
	// Info is a plain field write, so unlike record it cannot lean on
	// StreamInfo's nil-receiver tolerance. No first-writer guard is needed: a
	// block halts the walk (see the halted() check in the pair loop) and
	// finalizes the stream, so this runs at most once per stream.
	if w.st.Info != nil {
		w.st.Info.Error = err.Error()
	}
	// Not ActionBlock: the filter did not choose this block, its failure policy
	// did. Recording them alike made a broken enforcement path read as a working
	// one.
	w.record(p, filter.ActionErrorClosed)
}

func failClosedDetails(phase filter.Phase) string {
	switch phase {
	case filter.PhaseRequestHeaders:
		return "epe_request_headers_failed_closed"
	case filter.PhaseRequestBody:
		return "epe_request_body_failed_closed"
	case filter.PhaseResponseHeaders:
		return "epe_response_headers_failed_closed"
	case filter.PhaseResponseBody:
		return "epe_response_body_failed_closed"
	default:
		return "epe_filter_failed_closed"
	}
}

// validateAction rejects phase-incompatible actions and mutations before they
// enter the pending fold.
func validateAction(reg filter.Registration, phase filter.Phase, act filter.Action) error {
	switch act.Kind() {
	case filter.KindContinue, filter.KindStop, filter.KindBypass:
	case filter.KindNeedBody:
		if act.BodyRequirement() != filter.CompleteBody && act.BodyRequirement() != filter.IncrementalBody {
			return fmt.Errorf("filter %q returned unknown body requirement %d", reg.Name, act.BodyRequirement())
		}
		switch phase {
		case filter.PhaseRequestHeaders:
			if reg.Phases&filter.PhaseRequestBody == 0 {
				return fmt.Errorf("filter %q returned NeedBody without declaring request-body support", reg.Name)
			}
		case filter.PhaseResponseHeaders:
			if reg.Phases&filter.PhaseResponseBody == 0 {
				return fmt.Errorf("filter %q returned NeedBody without declaring response-body support", reg.Name)
			}
		default:
			return fmt.Errorf("filter %q returned NeedBody from a body phase", reg.Name)
		}
	default:
		return fmt.Errorf("filter %q returned unknown action kind %d", reg.Name, act.Kind())
	}
	for _, m := range act.Mutations() {
		if err := m.Route.Validate(); err != nil {
			return fmt.Errorf("filter %q returned invalid route mutation: %w", reg.Name, err)
		}
		// Target selection belongs to request headers, before forwarding.
		if m.Route != nil && m.Route.Upstream != nil && phase != filter.PhaseRequestHeaders {
			return fmt.Errorf("filter %q returned an upstream target outside request headers", reg.Name)
		}
		if phase == filter.PhaseRequestBody && m.Route != nil && m.Route.ClearCache {
			return fmt.Errorf("filter %q cannot clear the route cache after request headers", reg.Name)
		}
		for _, op := range m.HeaderOps {
			if phase == filter.PhaseRequestBody {
				switch strings.ToLower(op.Name) {
				case "host", ":authority", ":scheme", ":method":
					return fmt.Errorf("filter %q cannot modify %s after request headers", reg.Name, op.Name)
				}
			}
			if strings.EqualFold(op.Name, ":status") {
				return fmt.Errorf("filter %q returned :status as a header mutation; use Mutation.StatusCode", reg.Name)
			}
		}
		switch phase {
		case filter.PhaseRequestHeaders, filter.PhaseRequestBody:
			if m.StatusCode != nil {
				return fmt.Errorf("filter %q returned a response status mutation from a request phase", reg.Name)
			}
		case filter.PhaseResponseHeaders, filter.PhaseResponseBody:
			if m.Route != nil && m.Route.ClearCache {
				return fmt.Errorf(
					"filter %q asked to clear the route cache from a response phase; routing is already resolved",
					reg.Name,
				)
			}
			if m.StatusCode != nil && (*m.StatusCode < 200 || *m.StatusCode > 599) {
				return fmt.Errorf("filter %q returned response status %d outside 200..599", reg.Name, *m.StatusCode)
			}
		}
	}
	return nil
}

func (e *Engine) validateUnits(units []Unit) error {
	for i := range units {
		if len(units[i].Cfgs) != len(e.regs) {
			return fmt.Errorf("unit %q config count %d does not match registration count %d",
				units[i].ID.String(), len(units[i].Cfgs), len(e.regs))
		}
	}
	return nil
}

// foldPending computes the net effect of one walk's accumulated mutations.
func foldPending(
	pending []filter.Mutation,
) (ops []filter.HeaderOp, route *filter.RouteMutation, body []byte, statusCode *int, err error) {
	route, err = foldRoute(pending)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return fold(pending), route, lastBodyMutation(pending), lastStatusMutation(pending), nil
}

// lastBodyMutation returns the last non-nil body replacement in execution
// order; nil means unchanged, non-nil (including empty) means replace.
func lastBodyMutation(muts []filter.Mutation) []byte {
	var body []byte
	for _, m := range muts {
		if m.Body != nil {
			body = m.Body
		}
	}
	return body
}

// lastStatusMutation returns a copy of the last non-nil response status in
// execution order. The copy does not retain a filter-owned pointer.
func lastStatusMutation(muts []filter.Mutation) *int {
	var statusCode *int
	for _, m := range muts {
		if m.StatusCode != nil {
			v := *m.StatusCode
			statusCode = &v
		}
	}
	return statusCode
}

// failurePolicy applies the registration's error policy. A nil OnError defaults
// to FailClosed.
func failurePolicy(reg filter.Registration, cfg any) filter.FailurePolicy {
	if reg.OnError == nil {
		return filter.FailClosed
	}
	return reg.OnError(cfg)
}
