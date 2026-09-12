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
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDiscoveryRecognizesGoTests(t *testing.T) {
	path := filepath.Join(t.TempDir(), "names_test.go")
	source := `package sample
import tt "testing"
func TestMain(m *tt.M) {}
func TestFirst(t *tt.T) {}
func TestSecond(*tt.T) {}
func Testhelper(t *tt.T) {}
type helper struct{}
func (helper) TestMethod(t *tt.T) {}
`
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := testNames(path)
	if err != nil || !reflect.DeepEqual(got, []string{"TestFirst", "TestSecond"}) {
		t.Fatalf("names=%v error=%v", got, err)
	}
	if err := os.WriteFile(path, []byte("package sample; func TestBroken() {}"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := testNames(path); err == nil {
		t.Fatal("invalid Go test signature accepted")
	}
}
