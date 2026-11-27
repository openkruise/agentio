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
	"errors"

	"github.com/openkruise/agentio/extensions/epe/pkg/eval"

	capturestatus "github.com/openkruise/agentio/extensions/epe/pkg/content/status"

	"github.com/google/cel-go/cel"

	"github.com/openkruise/agentio/extensions/epe/pkg/content/protocol"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
)

const (
	statusTransformError = "transform_error"
	statusRecordTooLarge = "record_too_large"
)

// capture owns one direction's parse state and immutable audit snapshots.
type capture struct {
	cfg     captureConfig
	adapter *protocol.Adapter
	record  filter.ContentRecord
	done    bool
}

func newCapture(cfg captureConfig, headers map[string]string) *capture {
	adapter, status := protocol.New(
		protocol.Config{
			Format:          cfg.format,
			Response:        cfg.response,
			MaxCaptureBytes: cfg.captureBytes,
			MaxContentBytes: cfg.recordBytes,
			Fields:          &cfg.fields,
		},
		headers,
	)
	return &capture{
		cfg:     cfg,
		adapter: adapter,
		record:  filter.ContentRecord{Status: string(status)},
	}
}

func (c *capture) observe(chunk []byte, complete bool, scope *inputs.Scope) {
	if c.done {
		return
	}
	c.record.BytesSeen += int64(len(chunk))
	if c.adapter != nil {
		progress := c.adapter.Feed(chunk, complete, func(obs protocol.Observation) {
			var parent cel.Activation
			if c.cfg.transform != nil && scope != nil {
				parent = scope.Activation()
			}
			c.recordObservation(obs, parent)
		})
		c.record.CapturedBytes = progress.CapturedBytes
		if progress.Status != capturestatus.Complete {
			c.record.Status = string(progress.Status)
		}
		if progress.Status != capturestatus.Incomplete {
			c.adapter = nil
		}
	}
	c.done = complete
}

// Protocol adapters publish one completed document or aggregated stream view.
func (c *capture) recordObservation(obs protocol.Observation, parent cel.Activation) {
	value, err := transformContent(c.cfg.transform, obs.Content, parent, c.cfg.recordBytes)
	if errors.Is(err, eval.ErrResultTooLarge) {
		c.record.Status = statusRecordTooLarge
		return
	}
	if err != nil {
		c.record.Status = statusTransformError
		return
	}
	encoded, err := json.Marshal(struct {
		Content any `json:"content"`
	}{Content: value})
	if err != nil {
		c.record.Status = statusTransformError
		return
	}
	if len(encoded) > c.cfg.recordBytes {
		c.record.Status = statusRecordTooLarge
		return
	}
	c.record.Status = string(capturestatus.Complete)
	if obs.Truncated {
		c.record.Status = string(capturestatus.Truncated)
	}
	if obs.Partial {
		c.record.Status = string(capturestatus.Partial)
	}
	c.record.Content = value
}
