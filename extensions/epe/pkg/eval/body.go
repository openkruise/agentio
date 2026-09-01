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
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

var (
	requestMutationEnvOnce sync.Once
	requestMutationEnv     *cel.Env
	requestMutationEnvErr  error
)

// RequestMutationEnv returns the single CEL environment used by token header
// and body mutations. Context-specific activations bind every declared
// variable, using empty token/value/header fields when that context has no
// credential or target header yet.
func RequestMutationEnv() (*cel.Env, error) {
	requestMutationEnvOnce.Do(func() {
		mapType := cel.MapType(cel.StringType, cel.DynType)
		requestMutationEnv, requestMutationEnvErr = NewRestrictedRequestEnv(
			cel.Variable("token", cel.StringType),
			cel.Variable("value", cel.StringType),
			cel.Variable("header", cel.MapType(cel.StringType, cel.StringType)),
			cel.Function("json",
				cel.Overload("json_bytes", []*cel.Type{cel.BytesType}, cel.DynType,
					cel.UnaryBinding(decodeJSON)),
				cel.Overload("json_string", []*cel.Type{cel.StringType}, cel.DynType,
					cel.UnaryBinding(decodeJSON))),
			cel.Function("merge",
				cel.MemberOverload("map_merge", []*cel.Type{mapType, mapType}, mapType,
					cel.BinaryBinding(mergeJSONMaps))),
		)
	})
	return requestMutationEnv, requestMutationEnvErr
}

// CompileBodyMutation compiles a body expression once per projected filter
// config. Its result type is intentionally dynamic: bytes and strings are raw
// replacements, while every other JSON-compatible value is encoded as JSON.
func CompileBodyMutation(expr string) (cel.Program, error) {
	env, err := RequestMutationEnv()
	if err != nil {
		return nil, fmt.Errorf("init body CEL env: %w", err)
	}
	ast, issues := env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("compile body mutation: %w", issues.Err())
	}
	prog, err := env.Program(ast,
		cel.EvalOptions(cel.OptOptimize),
		cel.CostLimit(RestrictedRequestCELCostLimit),
	)
	if err != nil {
		return nil, fmt.Errorf("program body mutation: %w", err)
	}
	return prog, nil
}

// EvalBodyMutation evaluates a compiled expression and returns an owned body.
// Activation values are deliberately absent from every error path: callers
// layer credentials and request bodies into the activation.
func EvalBodyMutation(prog cel.Program, act cel.Activation) ([]byte, error) {
	result, _, err := prog.Eval(act)
	if err != nil {
		// CEL helper errors can contain values from the activation. Body and
		// credential values are both sensitive, so the runtime detail must not
		// escape into failStrategy logging.
		return nil, fmt.Errorf("evaluate body mutation: CEL evaluation failed")
	}
	value, err := ownedNative(result)
	if err != nil {
		return nil, fmt.Errorf("evaluate body mutation: result is not JSON-compatible")
	}
	switch v := value.(type) {
	case []byte:
		return bytes.Clone(v), nil
	case string:
		return []byte(v), nil
	default:
		out, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("encode body mutation result: result is not JSON-compatible")
		}
		return out, nil
	}
}

func decodeJSON(arg ref.Val) ref.Val {
	var raw []byte
	switch v := arg.(type) {
	case types.Bytes:
		raw = v
	case types.String:
		raw = []byte(v)
	default:
		return types.MaybeNoSuchOverloadErr(arg)
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return types.NewErr("decode JSON body: %v", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return types.NewErr("decode JSON body: multiple JSON values")
		}
		return types.NewErr("decode JSON body: %v", err)
	}
	normalized, err := normalizeJSONNumbers(decoded)
	if err != nil {
		return types.NewErr("decode JSON body: %v", err)
	}
	return types.DefaultTypeAdapter.NativeToValue(normalized)
}

// normalizeJSONNumbers converts encoding/json's exact json.Number tokens into
// CEL-native numeric types. Values outside CEL's numeric range fail instead of
// being rounded, and the error intentionally omits the source token.
func normalizeJSONNumbers(value any) (any, error) {
	switch v := value.(type) {
	case json.Number:
		text := string(v)
		if strings.ContainsAny(text, ".eE") {
			f, err := strconv.ParseFloat(text, 64)
			if err != nil {
				return nil, fmt.Errorf("number is outside CEL's numeric range")
			}
			return f, nil
		}
		if i, err := strconv.ParseInt(text, 10, 64); err == nil {
			return i, nil
		}
		if u, err := strconv.ParseUint(text, 10, 64); err == nil {
			return u, nil
		}
		return nil, fmt.Errorf("number is outside CEL's numeric range")
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			normalized, err := normalizeJSONNumbers(item)
			if err != nil {
				return nil, err
			}
			out[key] = normalized
		}
		return out, nil
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			normalized, err := normalizeJSONNumbers(item)
			if err != nil {
				return nil, err
			}
			out[i] = normalized
		}
		return out, nil
	default:
		return value, nil
	}
}

func mergeJSONMaps(left, right ref.Val) ref.Val {
	leftNative, err := ownedNative(left)
	if err != nil {
		return types.NewErr("merge JSON maps: invalid left map")
	}
	rightNative, err := ownedNative(right)
	if err != nil {
		return types.NewErr("merge JSON maps: invalid right map")
	}
	leftMap, leftOK := leftNative.(map[string]any)
	rightMap, rightOK := rightNative.(map[string]any)
	if !leftOK || !rightOK {
		return types.NewErr("merge JSON maps: operands must be string-keyed maps")
	}
	out := make(map[string]any, len(leftMap)+len(rightMap))
	for key, value := range leftMap {
		out[key] = value
	}
	for key, value := range rightMap {
		out[key] = value
	}
	return types.DefaultTypeAdapter.NativeToValue(out)
}
