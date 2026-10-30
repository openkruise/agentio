// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

package main

import "time"

// Progress is sampled at the receiver: local pipe writes can run ahead of TCP.
// Include the initial and terminal silent periods, including streams that never advance.
type progressWindow struct {
	counts []uint64
	last   []time.Time
	gaps   []time.Duration
}

func newProgressWindow(counts []uint64, now time.Time) *progressWindow {
	p := &progressWindow{
		counts: append([]uint64(nil), counts...),
		last:   make([]time.Time, len(counts)),
		gaps:   make([]time.Duration, len(counts)),
	}
	for i := range p.last {
		p.last[i] = now
	}
	return p
}
func (p *progressWindow) observe(counts []uint64, now time.Time) {
	for i, count := range counts {
		if count != p.counts[i] {
			p.gaps[i] = max(p.gaps[i], now.Sub(p.last[i]))
			p.last[i] = now
			p.counts[i] = count
		}
	}
}
func (p *progressWindow) finish(now time.Time) []float64 {
	gaps := make([]float64, len(p.counts))
	for i := range gaps {
		gaps[i] = float64(max(p.gaps[i], now.Sub(p.last[i]))) / float64(time.Millisecond)
	}
	return gaps
}
