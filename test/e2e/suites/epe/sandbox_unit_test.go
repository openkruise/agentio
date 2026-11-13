// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

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
