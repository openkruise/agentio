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
package eval

import (
	"bytes"
	"fmt"
	"reflect"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/google/cel-go/ext"
)

var (
	whenEnvOnce  sync.Once
	whenEnv      *cel.Env
	whenEnvErr   error
	valueEnvOnce sync.Once
	valueEnv     *cel.Env
	valueEnvErr  error
)

// RestrictedRequestCELCostLimit bounds request-time mutation work in cel-go
// runtime cost units. Consumers share the same budget and add only the
// declarations required by their own expression contract.
const RestrictedRequestCELCostLimit uint64 = 10_000

// requestVariableOptions declares the request-time scope shared by every CEL
// environment. It returns a fresh slice so consumer declarations cannot leak
// between independently constructed environments.
func requestVariableOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Variable("request", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("pod", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("profile", cel.MapType(cel.StringType, cel.StringType)),
		cel.Variable("rule", cel.MapType(cel.StringType, cel.StringType)),
		cel.Variable("inputs", cel.MapType(cel.StringType, cel.DynType)),
	}
}

// commonEnvOptions declares the request-time variables and extensions shared
// by audit conditions and credential-provider parameter values.
func commonEnvOptions() []cel.EnvOption {
	options := requestVariableOptions()
	return append(options,
		ext.Bindings(),
		ext.Strings(),
		ext.Sets(),
		ext.Lists(),
	)
}

// NewRequestEnv returns the standard request-time CEL environment plus
// consumer-specific declarations. Callers constrain their own result type.
func NewRequestEnv(extra ...cel.EnvOption) (*cel.Env, error) {
	options := append([]cel.EnvOption{}, commonEnvOptions()...)
	options = append(options, extra...)
	return cel.NewEnv(options...)
}

// NewRestrictedRequestEnv returns the request-time variables and safe
// extension subset used by mutation expressions. lists.range is deliberately
// omitted so request data cannot control an unbounded collection constructor.
func NewRestrictedRequestEnv(extra ...cel.EnvOption) (*cel.Env, error) {
	options := append(requestVariableOptions(),
		ext.Bindings(),
		ext.Strings(),
		ext.Sets(),
		ext.Lists(ext.ListsVersion(1)),
	)
	options = append(options, extra...)
	return cel.NewEnv(options...)
}

// WhenEnv returns the shared CEL environment for audit `when` expressions.
// It adds audit-only result to the request-time variables shared with provider
// parameter values.
func WhenEnv() (*cel.Env, error) {
	whenEnvOnce.Do(func() {
		options := append([]cel.EnvOption{cel.Variable("result", cel.StringType)}, commonEnvOptions()...)
		whenEnv, whenEnvErr = cel.NewEnv(options...)
	})
	return whenEnv, whenEnvErr
}

// providerValueEnv omits audit-only variables so invalid provider parameter
// references fail during compilation instead of at request evaluation.
func providerValueEnv() (*cel.Env, error) {
	valueEnvOnce.Do(func() {
		valueEnv, valueEnvErr = NewRequestEnv()
	})
	return valueEnv, valueEnvErr
}

// CompileValue parses and type-checks a CEL expression without constraining
// its result type. CredentialProvider extraMetadata values may be strings,
// lists, or any other JSON-compatible value.
func CompileValue(expr string) (cel.Program, error) {
	env, err := providerValueEnv()
	if err != nil {
		return nil, fmt.Errorf("init CEL env: %w", err)
	}
	ast, issues := env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("compile value: %w", issues.Err())
	}
	prog, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	if err != nil {
		return nil, fmt.Errorf("program value: %w", err)
	}
	return prog, nil
}

// CompileBool parses and type-checks a CEL expression that must return bool.
// An empty expression compiles to a nil program (the "always fire" path).
func CompileBool(expr string) (cel.Program, error) {
	if expr == "" {
		return nil, nil
	}
	env, err := WhenEnv()
	if err != nil {
		return nil, fmt.Errorf("init CEL env: %w", err)
	}
	ast, issues := env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("compile when: %w", issues.Err())
	}
	if ast.OutputType() != cel.BoolType {
		return nil, fmt.Errorf("compile when: expression must return bool, got %s", ast.OutputType().String())
	}
	prog, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	if err != nil {
		return nil, fmt.Errorf("program when: %w", err)
	}
	return prog, nil
}

// EvalBool evaluates a compiled program against activation. A nil program
// returns true (the empty-expression "always fire" path).
func EvalBool(prog cel.Program, act cel.Activation) (bool, error) {
	if prog == nil {
		return true, nil
	}
	val, _, err := prog.Eval(act)
	if err != nil {
		return false, fmt.Errorf("eval when: %w", err)
	}
	b, ok := val.(types.Bool)
	if !ok {
		return false, fmt.Errorf("eval when: result is %T not bool", val)
	}
	return bool(b), nil
}

// EvalValue evaluates a CEL program and converts the result into an owned,
// JSON-native Go value: maps become map[string]any, lists become []any, and
// nothing in the result shares storage with the activation. A null result is
// reported as an untyped nil.
func EvalValue(prog cel.Program, act cel.Activation) (any, error) {
	val, _, err := prog.Eval(act)
	if err != nil {
		return nil, fmt.Errorf("eval value: %w", err)
	}
	native, err := ownedNative(val)
	if err != nil {
		return nil, fmt.Errorf("convert value: %w", err)
	}
	return native, nil
}

// anyType is the reflect.Type of the empty interface, the conversion target
// for CEL scalars.
var anyType = reflect.TypeOf((*any)(nil)).Elem()

// ownedNative walks a CEL result into a plain Go value. It exists because
// ref.Val.ConvertToNative is unfit for either of this package's two duties:
//
// Ownership. ConvertToNative hands back the underlying container whenever it is
// already assignable to the requested type — for a value read out of an
// activation that container belongs to the Scope that built it, or to the
// caller's own inputs map. Those are immutable for the stream's life, so the
// alias is stable today; copying keeps the guarantee a property of this
// function rather than of every producer of a Scope.
//
// JSON shape. cel-go converts a map result to map[any]any, which
// encoding/json rejects outright, so every map-valued expression would fail
// the caller's marshalling step. Rebuilding maps as map[string]any keys them
// the way JSON requires.
//
// Scalars are immutable and pass through ConvertToNative unchanged.
func ownedNative(val ref.Val) (any, error) {
	switch v := val.(type) {
	case types.Null:
		return nil, nil
	case types.Bytes:
		return bytes.Clone(v), nil
	case traits.Mapper:
		out := make(map[string]any, sizeOf(v))
		for it := v.Iterator(); it.HasNext() == types.True; {
			k := it.Next()
			key, err := jsonKey(k)
			if err != nil {
				return nil, err
			}
			elem, found := v.Find(k)
			if !found {
				return nil, fmt.Errorf("map key %q disappeared during iteration", key)
			}
			if out[key], err = ownedNative(elem); err != nil {
				return nil, err
			}
		}
		return out, nil
	case traits.Lister:
		out := make([]any, 0, sizeOf(v))
		for it := v.Iterator(); it.HasNext() == types.True; {
			elem, err := ownedNative(it.Next())
			if err != nil {
				return nil, err
			}
			out = append(out, elem)
		}
		return out, nil
	default:
		return val.ConvertToNative(anyType)
	}
}

// jsonKey renders a CEL map key as a JSON object key. CEL permits int, uint
// and bool keys; JSON objects are string-keyed, so those are stringified the
// same way encoding/json stringifies an integer-keyed Go map.
func jsonKey(k ref.Val) (string, error) {
	if s, ok := k.(types.String); ok {
		return string(s), nil
	}
	s, ok := k.ConvertToType(types.StringType).(types.String)
	if !ok {
		return "", fmt.Errorf("map key of type %s is not JSON-compatible", k.Type().TypeName())
	}
	return string(s), nil
}

// sizeOf reports a container's length as an allocation hint, falling back to
// zero for an implementation that does not report a plain int size.
func sizeOf(v traits.Sizer) int {
	if n, ok := v.Size().(types.Int); ok {
		return int(n)
	}
	return 0
}
