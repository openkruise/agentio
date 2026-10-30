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
