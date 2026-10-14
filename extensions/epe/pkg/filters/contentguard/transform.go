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
package contentguard

import (
	"encoding/json"
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/interpreter"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"

	"github.com/openkruise/agentio/extensions/epe/pkg/content/protocol"
	"github.com/openkruise/agentio/extensions/epe/pkg/eval"
)

func compileTransformation(expression string) (cel.Program, protocol.CaptureFields, error) {
	if expression == "" {
		return nil, protocol.CaptureFields{InputMessages: true, OutputMessages: true, Tools: true}, nil
	}
	env, err := eval.NewRequestEnv(cel.Variable("content", cel.DynType))
	if err != nil {
		return nil, protocol.CaptureFields{}, err
	}
	ast, issues := env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return nil, protocol.CaptureFields{}, fmt.Errorf("content transform: %w", issues.Err())
	}
	program, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize), cel.CostLimit(10000))
	return program, transformationFields(ast.Expr()), err
}

// Bare/dynamic content access conservatively captures everything. Static field
// access can avoid retaining messages that a metadata-only transformation never uses.
// Retention-dependent flags use all fields so this optimization cannot mask truncation.
func transformationFields(root *exprpb.Expr) protocol.CaptureFields {
	var fields protocol.CaptureFields
	all := func() { fields = protocol.CaptureFields{InputMessages: true, OutputMessages: true, Tools: true} }

	var visit func(*exprpb.Expr)
	visit = func(e *exprpb.Expr) {
		if e == nil {
			return
		}
		switch v := e.ExprKind.(type) {
		case *exprpb.Expr_IdentExpr:
			if v.IdentExpr.Name == "content" {
				all()
			}
		case *exprpb.Expr_SelectExpr:
			if v.SelectExpr.Operand.GetIdentExpr().GetName() == "content" {
				selectCaptureField(&fields, v.SelectExpr.Field)
			} else {
				visit(v.SelectExpr.Operand)
			}
		case *exprpb.Expr_CallExpr:
			c := v.CallExpr
			if c.Function == "_[_]" && len(c.Args) == 2 && c.Args[0].GetIdentExpr().GetName() == "content" {
				if key, ok := c.Args[1].GetConstExpr().GetConstantKind().(*exprpb.Constant_StringValue); ok {
					selectCaptureField(&fields, key.StringValue)
					return
				}
			}
			visit(c.Target)
			for _, arg := range c.Args {
				visit(arg)
			}
		case *exprpb.Expr_ListExpr:
			for _, item := range v.ListExpr.Elements {
				visit(item)
			}
		case *exprpb.Expr_StructExpr:
			for _, entry := range v.StructExpr.Entries {
				visit(entry.GetMapKey())
				visit(entry.Value)
			}
		case *exprpb.Expr_ComprehensionExpr:
			c := v.ComprehensionExpr
			visit(c.IterRange)
			visit(c.AccuInit)
			visit(c.LoopCondition)
			visit(c.LoopStep)
			visit(c.Result)
		}
	}
	visit(root)
	return fields
}

func selectCaptureField(fields *protocol.CaptureFields, name string) {
	switch name {
	case "inputMessages":
		fields.InputMessages = true
	case "outputMessages":
		fields.OutputMessages = true
	case "tools":
		fields.Tools = true
	case "format", "model", "usage", "error", "status", "incompleteReason":
	default:
		*fields = protocol.CaptureFields{InputMessages: true, OutputMessages: true, Tools: true}
	}
}

func transformContent(program cel.Program, content any, parent cel.Activation, maxBytes int) (any, error) {
	if view, ok := content.(*protocol.LLMView); ok {
		encoded, err := json.Marshal(view)
		if err != nil {
			return nil, err
		}
		content = nil
		if err := json.Unmarshal(encoded, &content); err != nil {
			return nil, err
		}
	}
	if program == nil {
		if err := eval.CheckValueSize(content, maxBytes); err != nil {
			return nil, err
		}
		return content, nil
	}
	act, err := cel.NewActivation(map[string]any{"content": content})
	if err != nil {
		panic(err)
	} // A map activation is always valid.
	if parent != nil {
		act = interpreter.NewHierarchicalActivation(parent, act)
	}
	return eval.ValueBounded(program, act, maxBytes)
}
