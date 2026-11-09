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

package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/pflag"

	"github.com/openkruise/agentio/pkg/proxyinit"
)

func main() {
	if err := proxyinit.Command(
		context.Background(),
		os.Args[1:],
		os.Stdout,
		os.Stderr,
	); err != nil &&
		!errors.Is(err, pflag.ErrHelp) {
		fmt.Fprintln(os.Stderr, err)
		code := 1
		if errors.Is(err, proxyinit.ErrValidation) {
			code = 126 // Pinned CNI repair protocol.
		}
		os.Exit(code)
	}
}
