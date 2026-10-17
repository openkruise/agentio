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
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if err := command(os.Args[1:]); err != nil && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func command(args []string) error {
	if len(args) == 2 && args[0] == "analyze" {
		return analyze(args[1])
	}
	if len(args) == 0 || args[0] != "run" {
		return fmt.Errorf("usage: porter-bench run [flags] | analyze OUTPUT")
	}
	cfg, err := parseConfig(args[1:], os.Stderr)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	r, err := newRunner(cfg)
	if err != nil {
		return err
	}
	return r.execute(ctx)
}
