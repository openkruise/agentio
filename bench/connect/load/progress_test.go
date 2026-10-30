// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"
	"time"
)

func TestProgressIncludesSilentStartEndAndStarvedStreams(t *testing.T) {
	start := time.Now()
	p := newProgressWindow([]uint64{10, 20, 0}, start)
	p.observe([]uint64{11, 20, 0}, start.Add(time.Second))
	p.observe([]uint64{12, 21, 0}, start.Add(3*time.Second))
	gaps := p.finish(start.Add(7 * time.Second))
	if gaps[0] != 4000 || gaps[1] != 4000 || gaps[2] != 7000 {
		t.Fatal(gaps)
	}
}
