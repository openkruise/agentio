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
package auditlog

import (
	"github.com/go-logr/logr"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

// ContentEntry is one rule's observation of a request or response body.
type ContentEntry struct {
	RequestID string
	Unit      string
	Direction string
	Method    string
	Host      string
	Path      string
	Record    filter.ContentRecord
}

func (e ContentEntry) emit(logger logr.Logger) {
	logger.Info("content captured", "type", "content", "requestID", e.RequestID, "unit", e.Unit,
		"direction", e.Direction, "method", e.Method, "host", e.Host, "path", e.Path,
		"status", e.Record.Status, "bytesSeen", e.Record.BytesSeen,
		"capturedBytes", e.Record.CapturedBytes, "content", e.Record.Content)
}
