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

// public-ca-package converts a dated curl CA Extract snapshot to Agentiod's package format.
package main

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/openkruise/agentio/pkg/clienttrust"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: public-ca-package <cacert-YYYY-MM-DD.pem>")
		os.Exit(2)
	}
	file, err := buildPackage(os.Args[1])
	if err == nil {
		err = json.NewEncoder(os.Stdout).Encode(file)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func buildPackage(path string) (clienttrust.Package, error) {
	name := filepath.Base(path)
	version := strings.TrimSuffix(strings.TrimPrefix(name, "cacert-"), ".pem")
	if _, err := time.Parse(time.DateOnly, version); err != nil || name != "cacert-"+version+".pem" {
		return clienttrust.Package{}, fmt.Errorf("expected a dated curl CA snapshot, got %q", name)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return clienttrust.Package{}, err
	}

	// curl adds subject headings and fingerprints between PEM blocks.
	var certs [][]byte
	for rest := data; len(rest) > 0; {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		certs = append(certs, pem.EncodeToMemory(block))
		rest = remaining
	}
	if len(certs) != bytes.Count(data, []byte("-----BEGIN ")) {
		return clienttrust.Package{}, fmt.Errorf("malformed PEM block in %s", name)
	}
	bundle, _, err := clienttrust.Merge(certs, time.Now())
	if err != nil {
		return clienttrust.Package{}, fmt.Errorf("validate %s: %w", name, err)
	}
	return clienttrust.Package{Name: "mozilla", Version: version, Bundle: string(bundle)}, nil
}
