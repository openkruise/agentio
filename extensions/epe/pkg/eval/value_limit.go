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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
)

// ErrResultTooLarge means the projected JSON exceeds its byte or nesting budget.
var ErrResultTooLarge = errors.New("CEL result exceeds recording budget")

// ValueBounded checks the CEL result before making the owned JSON-native copy.
// maxBytes bounds its JSON representation, not allocations inside CEL evaluation.
func ValueBounded(prog cel.Program, act cel.Activation, maxBytes int) (any, error) {
	if maxBytes <= 0 {
		return nil, ErrResultTooLarge
	}
	val, _, err := prog.Eval(act)
	if err != nil {
		return nil, fmt.Errorf("eval value: %w", err)
	}
	remaining := maxBytes
	if err := checkValueSize(val, &remaining, 0); err != nil {
		return nil, err
	}
	return ownedNative(val)
}

// CheckValueSize checks a native value against the same byte and nesting budgets
// as ValueBounded without evaluating a program or copying the value.
func CheckValueSize(value any, maxBytes int) error {
	if maxBytes <= 0 {
		return ErrResultTooLarge
	}
	return checkValueSize(types.DefaultTypeAdapter.NativeToValue(value), &maxBytes, 0)
}

func spend(remaining *int, n int) error {
	if n > *remaining {
		return ErrResultTooLarge
	}
	*remaining -= n
	return nil
}

func checkValueSize(val ref.Val, remaining *int, depth int) error {
	// shortcut: cap output nesting at 128; revisit if deeper audit documents are needed.
	if depth > 128 {
		return ErrResultTooLarge
	}
	switch v := val.(type) {
	case traits.Mapper:
		return checkMapSize(v, remaining, depth)
	case traits.Lister:
		if err := spend(remaining, 2); err != nil {
			return err
		}
		first := true
		for it := v.Iterator(); it.HasNext() == types.True; {
			if !first {
				if err := spend(remaining, 1); err != nil {
					return err
				}
			}
			first = false
			if err := checkValueSize(it.Next(), remaining, depth+1); err != nil {
				return err
			}
		}
		return nil
	case types.Bytes:
		if v == nil {
			return spend(remaining, 4)
		}
		if len(v) > *remaining {
			return ErrResultTooLarge
		}
		return spend(remaining, base64.StdEncoding.EncodedLen(len(v))+2)
	case types.Null:
		return spend(remaining, 4)
	case types.String, types.Bool, types.Int, types.Uint, types.Double, types.Timestamp, types.Duration:
		native, err := val.ConvertToNative(anyType)
		if err != nil {
			return err
		}
		return checkScalarSize(native, remaining)
	default:
		return fmt.Errorf("unsupported audit result type %s", val.Type())
	}
}

func checkScalarSize(value any, remaining *int) error {
	if s, ok := value.(string); ok && len(s)+2 > *remaining {
		return ErrResultTooLarge
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return spend(remaining, len(encoded))
}

func checkMapSize(v traits.Mapper, remaining *int, depth int) error {
	if err := spend(remaining, 2); err != nil {
		return err
	}
	first := true
	for it := v.Iterator(); it.HasNext() == types.True; {
		if !first {
			if err := spend(remaining, 1); err != nil {
				return err
			}
		}
		first = false
		key := it.Next()
		name, err := jsonKey(key)
		if err != nil {
			return err
		}
		if err := checkScalarSize(name, remaining); err != nil {
			return err
		}
		if err := spend(remaining, 1); err != nil {
			return err
		}
		child, found := v.Find(key)
		if !found {
			return fmt.Errorf("map key %q disappeared during iteration", name)
		}
		if err := checkValueSize(child, remaining, depth+1); err != nil {
			return err
		}
	}
	return nil
}
