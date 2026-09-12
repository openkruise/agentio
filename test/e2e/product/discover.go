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

package product

import (
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/openkruise/agentio/test/e2e/command"
)

// Discover uses go list's build-selected files without compiling or executing
// TestMain. Planning needs neither image inputs nor a Kubernetes environment.
func Discover(ctx context.Context, root string, runner command.Interface) (map[string][]string, error) {
	result, err := runner.Run(ctx, command.Request{Name: "go", Args: []string{"list", "-json", "./suites/..."}, Dir: root})
	if err != nil {
		return nil, fmt.Errorf("discover product suites: %w; %s", err, result.Stderr)
	}
	decoder := json.NewDecoder(strings.NewReader(result.Stdout))
	inventory := map[string][]string{}
	for {
		var pkg struct {
			Dir, ImportPath           string
			TestGoFiles, XTestGoFiles []string
		}
		if err := decoder.Decode(&pkg); err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("decode package inventory: %w", err)
		}
		name, found := strings.CutPrefix(pkg.ImportPath, "github.com/openkruise/agentio/test/e2e/suites/")
		// Framework smoke and internal helper packages are not product suites.
		if !found || name == "framework" || strings.Contains(name, "/") {
			continue
		}
		inventory[name] = nil
		for _, file := range append(pkg.TestGoFiles, pkg.XTestGoFiles...) {
			names, err := testNames(filepath.Join(pkg.Dir, file))
			if err != nil {
				return nil, err
			}
			inventory[name] = append(inventory[name], names...)
		}
	}
	return inventory, nil
}

func testNames(path string) ([]string, error) {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		return nil, err
	}
	testingAlias, err := testingImportAlias(file)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, declaration := range file.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Name.Name == "TestMain" || !strings.HasPrefix(fn.Name.Name, "Test") {
			continue
		}
		if suffix := strings.TrimPrefix(fn.Name.Name, "Test"); suffix != "" {
			first, _ := utf8.DecodeRuneInString(suffix)
			if unicode.IsLower(first) {
				continue
			}
		}
		if err := validateTestSignature(fn, testingAlias); err != nil {
			return nil, fmt.Errorf("%s: %s: %w", path, fn.Name.Name, err)
		}
		names = append(names, fn.Name.Name)
	}
	return names, nil
}

func testingImportAlias(file *ast.File) (string, error) {
	for _, imported := range file.Imports {
		name, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			return "", err
		}
		if name == "testing" {
			if imported.Name != nil {
				return imported.Name.Name, nil
			}
			return "testing", nil
		}
	}
	return "", nil
}

func validateTestSignature(fn *ast.FuncDecl, alias string) error {
	if fn.Type.Results != nil || fn.Type.TypeParams != nil || len(fn.Type.Params.List) != 1 || len(fn.Type.Params.List[0].Names) > 1 {
		return fmt.Errorf("invalid Go test signature")
	}
	pointer, ok := fn.Type.Params.List[0].Type.(*ast.StarExpr)
	if !ok {
		return fmt.Errorf("must accept *testing.T")
	}
	if selector, ok := pointer.X.(*ast.SelectorExpr); ok {
		qualifier, ok := selector.X.(*ast.Ident)
		if ok && qualifier.Name == alias && selector.Sel.Name == "T" {
			return nil
		}
	} else if identifier, ok := pointer.X.(*ast.Ident); ok && alias == "." && identifier.Name == "T" {
		return nil
	}
	return fmt.Errorf("must accept *testing.T")
}
