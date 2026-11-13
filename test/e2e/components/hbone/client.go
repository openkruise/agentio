// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

// Package hbone sends real HTTP/2 CONNECT requests with explicit identity headers.
package hbone

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"

	"golang.org/x/net/http2"
)

// Dial opens one fresh tunnel. A non-200 CONNECT returns its status and no stream.
// The supplied TLS configuration authenticates the outer gateway connection.
func Dial(ctx context.Context, address, target string, config *tls.Config, headers http.Header) (net.Conn, int, error) {
	outer, err := (&tls.Dialer{Config: config}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, 0, err
	}
	stop := context.AfterFunc(ctx, func() { outer.Close() })
	reader, writer := io.Pipe()
	closeTunnel := func() error {
		stop()
		return errors.Join(reader.Close(), writer.Close(), outer.Close())
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := outer.SetDeadline(deadline); err != nil {
			return nil, 0, errors.Join(err, closeTunnel())
		}
	}
	transport := &http2.Transport{}
	client, err := transport.NewClientConn(outer)
	if err != nil {
		return nil, 0, errors.Join(err, closeTunnel())
	}
	response, err := client.RoundTrip((&http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Scheme: "https", Host: target},
		Host:   target,
		Header: headers,
		Body:   reader,
	}).WithContext(ctx))
	if err != nil {
		return nil, 0, errors.Join(err, closeTunnel())
	}
	if response.StatusCode != http.StatusOK {
		return nil, response.StatusCode, errors.Join(response.Body.Close(), closeTunnel())
	}
	return &tunnel{Conn: outer, reader: response.Body, writer: writer, closeTunnel: closeTunnel}, response.StatusCode, nil
}

type tunnel struct {
	net.Conn
	reader      io.ReadCloser
	writer      io.Writer
	closeTunnel func() error
}

func (t *tunnel) Read(p []byte) (int, error)  { return t.reader.Read(p) }
func (t *tunnel) Write(p []byte) (int, error) { return t.writer.Write(p) }
func (t *tunnel) Close() error                { return errors.Join(t.reader.Close(), t.closeTunnel()) }
