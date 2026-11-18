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
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const socketTimeout = 8 * time.Second

var uploadBody = bytes.Repeat([]byte("x"), 1<<20)

type request struct {
	Host        string `json:"host"`
	Scheme      string `json:"scheme"`
	Port        int    `json:"port"`
	Path        string `json:"path"`
	clientID    string
	policyGroup string
	deny        bool
}

func (r request) validate() error {
	if r.Host == "" || strings.ContainsAny(r.Host, "/?#@ \t\r\n") || !strings.HasPrefix(r.Path, "/") {
		return errors.New("provide a host and an absolute request path")
	}
	if (r.Scheme != "http" && r.Scheme != "https") || r.Port < 1 || r.Port > 65535 {
		return errors.New("scheme must be http or https and port must be between 1 and 65535")
	}
	return nil
}

func (r request) authority() string {
	return net.JoinHostPort(r.Host, strconv.Itoa(r.Port))
}

func (c *client) nextRequest(worker, sequence int) (request, string, bool) {
	c.mu.Lock()
	cfg := c.config
	cold := sequence*37%100 < int(math.RoundToEven(cfg.ColdFraction*100))
	host := fmt.Sprintf("hot-%02d.load.test", worker)
	if cold {
		ordinal := (c.coldSequence*cfg.Clients + cfg.ClientIndex) % cfg.DomainCount
		c.coldSequence++
		host = fmt.Sprintf("host-%06d.load.test", ordinal)
	}
	_, seen := c.seen[host]
	c.seen[host] = struct{}{}
	c.mu.Unlock()

	group := "hot"
	switch {
	case !seen:
		group = "domain-first"
	case cold:
		group = "long-tail"
	}
	req := request{
		Host:        host,
		Scheme:      cfg.Scheme,
		Port:        cfg.Port,
		Path:        "/allow",
		clientID:    strconv.Itoa(cfg.ClientIndex),
		policyGroup: cfg.Group,
		deny:        cfg.Deny,
	}
	if sequence%10 == 7 {
		req.Path = "/deny"
	}
	if cfg.Mixed {
		switch sequence % 50 {
		case 20:
			req.Path, group = "/stream", "stream"
		case 30:
			req.Path, group = "/download", "download"
		case 40:
			req.Path, group = "/upload", "upload"
		}
	}
	if cfg.Fault && sequence%10 == 1 {
		req.Path, group = "/fault", "fault"
	}
	return req, group, cold
}

type connection struct {
	net.Conn
	reader *bufio.Reader
	key    string
	opened time.Time
}

// Bound idle I/O rather than the whole request so a healthy SSE stream can run longer.
type idleConn struct {
	net.Conn
}

func (c idleConn) Read(p []byte) (int, error) {
	if err := c.SetReadDeadline(time.Now().Add(socketTimeout)); err != nil {
		return 0, err
	}
	return c.Conn.Read(p)
}

func (c idleConn) Write(p []byte) (int, error) {
	if err := c.SetWriteDeadline(time.Now().Add(socketTimeout)); err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}

func closeConnection(slot **connection) {
	if conn := *slot; conn != nil {
		if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Error("close upstream connection", "error", err)
		}
		*slot = nil
	}
}

type handshakeError struct {
	error
}

func (e *handshakeError) Unwrap() error { return e.error }

func dial(ctx context.Context, req request, roots *x509.CertPool, key string) (*connection, *certificate, error) {
	ctx, cancel := context.WithTimeout(ctx, socketTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", req.authority())
	if err != nil {
		return nil, nil, err
	}
	var peer *certificate
	if req.Scheme == "https" {
		secured := tls.Client(conn, &tls.Config{
			RootCAs:    roots,
			ServerName: req.Host,
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"http/1.1"},
		})
		if err := secured.HandshakeContext(ctx); err != nil {
			if closeErr := conn.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
				log.Error("close failed TLS handshake", "error", closeErr)
			}
			return nil, nil, &handshakeError{err}
		}
		info := certificateInfo(secured.ConnectionState().PeerCertificates[0])
		peer = &info
		conn = secured
	}
	socket := idleConn{conn}
	return &connection{Conn: socket, reader: bufio.NewReader(socket), key: key, opened: time.Now()}, peer, nil
}

type observation struct {
	status    int
	body      []byte
	cert      *certificate
	err       error
	errorType string
	stage     string
}

func exchange(ctx context.Context, req request, roots *x509.CertPool, slot **connection) (result observation) {
	key := req.Scheme + "://" + req.authority()
	if conn := *slot; conn != nil && (conn.key != key || time.Since(conn.opened) >= time.Minute) {
		closeConnection(slot)
	}
	result.stage = "connect"
	defer func() {
		if result.err != nil {
			result.errorType = failureType(result.err, result.stage)
			closeConnection(slot)
		}
	}()
	if *slot == nil {
		*slot, result.cert, result.err = dial(ctx, req, roots, key)
		if result.err != nil {
			return result
		}
	}
	conn := *slot

	method := http.MethodGet
	var body io.Reader
	if req.clientID != "" && req.Path == "/upload" {
		method = http.MethodPost
		body = bytes.NewReader(uploadBody)
	}
	result.stage = "send"
	outgoing, err := http.NewRequestWithContext(ctx, method, key+req.Path, body)
	if err != nil {
		result.err = err
		return result
	}
	outgoing.Header.Set("Accept-Encoding", "identity")
	outgoing.Header.Set("User-Agent", "")
	if req.clientID != "" {
		outgoing.Header.Set("X-Stability-Client", req.clientID)
	}
	// Write exactly once per request, including on a stale keepalive connection.
	if err := outgoing.Write(conn); err != nil {
		result.err = err
		return result
	}

	result.stage = "headers"
	response, err := http.ReadResponse(conn.reader, outgoing)
	if err != nil {
		result.err = err
		return result
	}
	result.stage = "body"
	result.status = response.StatusCode
	result.body, result.err = io.ReadAll(response.Body)
	if result.err == nil {
		result.err = response.Body.Close()
	}
	if response.Close {
		closeConnection(slot)
	}
	return result
}

func (o *observation) check(req request) {
	expected := http.StatusOK
	if req.Path == "/deny" && req.deny {
		expected = http.StatusUnavailableForLegalReasons
	}
	if o.status != expected {
		o.errorType = "AssertionError"
		if o.status == http.StatusOK && expected == http.StatusUnavailableForLegalReasons {
			o.errorType = "PolicyViolation"
		}
		o.err = fmt.Errorf("status %d expected %d, %s%s: %.200q", o.status, expected, req.authority(), req.Path, o.body)
		return
	}
	switch req.Path {
	case "/stream":
		if bytes.Count(o.body, []byte("data:")) != 20 {
			o.errorType, o.err = "AssertionError", errors.New("stream truncated")
		}
	case "/download":
		if len(o.body) != 1<<20 {
			o.errorType, o.err = "AssertionError", errors.New("download truncated")
		}
	case "/upload":
		if string(o.body) != "uploaded:1048576" {
			o.errorType, o.err = "AssertionError", errors.New("upload differs")
		}
	case "/allow":
		o.checkIdentity(req)
	}
}

func (o *observation) checkIdentity(req request) {
	var data struct {
		Marker  string      `json:"marker"`
		Host    string      `json:"host"`
		SNI     string      `json:"tls_sni"`
		Headers http.Header `json:"headers"`
	}
	if err := json.Unmarshal(o.body, &data); err != nil {
		o.errorType, o.err = "JSONDecodeError", err
		return
	}
	switch {
	case data.Marker != "STABILITY-UPSTREAM" || data.Host != req.authority():
		o.errorType, o.err = "AssertionError", errors.New("upstream host or marker mismatch")
	case req.Scheme == "https" && data.SNI != req.Host:
		o.errorType, o.err = "AssertionError", errors.New("upstream SNI mismatch")
	case !slices.Equal(data.Headers.Values("X-Stability-Client"), []string{req.clientID}):
		o.errorType, o.err = "PolicyViolation", errors.New("identity header changed")
	case req.policyGroup != "" && !slices.Equal(data.Headers.Values("X-Policy-Group"), []string{req.policyGroup}):
		o.errorType, o.err = "PolicyViolation", errors.New("policy identity group crossed")
	}
}

func failureType(err error, stage string) string {
	if e, ok := errors.AsType[net.Error](err); ok && e.Timeout() {
		return "TimeoutError"
	}
	if verification, _ := errors.AsType[*tls.CertificateVerificationError](err); verification != nil {
		return "SSLCertVerificationError"
	}
	if dns, _ := errors.AsType[*net.DNSError](err); dns != nil {
		return "gaierror"
	}
	switch {
	case errors.Is(err, syscall.ECONNRESET):
		return "ConnectionResetError"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "ConnectionRefusedError"
	case errors.Is(err, syscall.EPIPE):
		return "BrokenPipeError"
	case stage == "headers" && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)):
		return "RemoteDisconnected"
	case stage == "body" && errors.Is(err, io.ErrUnexpectedEOF):
		return "IncompleteRead"
	}
	if handshake, _ := errors.AsType[*handshakeError](err); handshake != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return "SSLEOFError"
		}
		return "SSLError"
	}
	return "OSError"
}

func certificateInfo(leaf *x509.Certificate) certificate {
	// Match ssl.getpeercert field names and the OpenSSL serial/time formatting.
	serial := strings.ToUpper(hex.EncodeToString(leaf.SerialNumber.Bytes()))
	if serial == "" {
		serial = "00"
	}
	const date = "Jan _2 15:04:05 2006 GMT"
	names := map[string]string{
		"2.5.4.3":  "commonName",
		"2.5.4.6":  "countryName",
		"2.5.4.7":  "localityName",
		"2.5.4.8":  "stateOrProvinceName",
		"2.5.4.10": "organizationName",
		"2.5.4.11": "organizationalUnitName",
	}
	issuer := make([][][2]string, 0, len(leaf.Issuer.Names))
	for _, name := range leaf.Issuer.Names {
		oid := name.Type.String()
		label := names[oid]
		if label == "" {
			label = oid
		}
		issuer = append(issuer, [][2]string{{label, fmt.Sprint(name.Value)}})
	}
	return certificate{
		Serial:    serial,
		NotBefore: leaf.NotBefore.UTC().Format(date),
		NotAfter:  leaf.NotAfter.UTC().Format(date),
		Issuer:    issuer,
	}
}
