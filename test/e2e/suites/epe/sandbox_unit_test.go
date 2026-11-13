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

package epe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"

	"golang.org/x/net/http2"
)

func TestSandboxTLSRejectionEvidence(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"EOF", fmt.Errorf("inner TLS handshake: %w", io.EOF), true},
		{"truncated handshake", io.ErrUnexpectedEOF, true},
		{"stream canceled by gateway", http2.StreamError{StreamID: 1, Code: http2.ErrCodeCancel}, true},
		{"TLS alert", errors.New("remote error: tls: access denied"), true},
		{"success", nil, false},
		{"deadline", fmt.Errorf("inner TLS handshake: %w", context.DeadlineExceeded), false},
		{"dial timeout", &net.OpError{Op: "dial", Net: "tcp", Err: context.DeadlineExceeded}, false},
		{"DNS failure", &net.DNSError{Err: "not found", Name: "server"}, false},
		{"unrelated reset", http2.StreamError{StreamID: 1, Code: http2.ErrCodeProtocol}, false},
		{"transport failure", errors.New("connection refused"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sandboxTLSRejected(tc.err); got != tc.want {
				t.Fatalf("policy rejection=%t, want %t for %v", got, tc.want, tc.err)
			}
		})
	}
}
