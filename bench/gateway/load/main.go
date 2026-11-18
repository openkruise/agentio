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
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/openkruise/agentio/bench/load"
)

type options struct {
	mode             string
	endpoint         string
	authority        string
	targetMode       string
	tcpHost          string
	caFile           string
	tlsServerName    string
	certFile         string
	keyFile          string
	listen           string
	tlsListen        string
	tcpListen        string
	tcpTLSListen     string
	seconds          int
	rate             int
	concurrency      int
	targets          int
	body             int
	profiles         int
	slot             int
	h2               bool
	closeConnections bool
	stream           bool
	tlsTCP           bool
	expectPolicy     bool
}

func flags(fs *flag.FlagSet) *options {
	o := &options{}
	fs.StringVar(&o.mode, "mode", "http", "http, tcp, or serve")
	fs.StringVar(&o.endpoint, "endpoint", "http://127.0.0.1:18000/", "gateway URL for HTTP, host:port for TCP")
	fs.StringVar(
		&o.authority,
		"authority",
		"bench.test:19201",
		"HTTP authority / CONNECT target; port only for rotating HTTP targets",
	)
	fs.IntVar(&o.seconds, "seconds", 60, "measurement duration in seconds")
	fs.IntVar(&o.rate, "rate", 5000, "positive offered requests per second")
	fs.IntVar(&o.concurrency, "concurrency", 128, "concurrent workers")
	fs.IntVar(&o.targets, "targets", 1, "logical targets")
	fs.StringVar(&o.targetMode, "targets-mode", "fixed", "fixed, names, cold, ips, or ttl")
	fs.BoolVar(&o.h2, "h2", false, "HTTP/2 downstream")
	fs.IntVar(&o.body, "body", 0, "request body bytes")
	fs.BoolVar(&o.closeConnections, "close", false, "disable downstream HTTP keepalive")
	fs.BoolVar(&o.stream, "stream", false, "reuse TCP tunnels")
	fs.BoolVar(&o.tlsTCP, "tls-tcp", false, "TLS inside CONNECT")
	fs.IntVar(&o.profiles, "profiles", 0, "TCP profile count")
	fs.IntVar(&o.slot, "slot", 0, "TCP policy slot")
	fs.StringVar(&o.tcpHost, "tcp-host", "bench.test", "TCP DNS/SNI test target")
	fs.StringVar(&o.caFile, "ca-file", "", "trusted CA PEM for HTTPS or TLS inside CONNECT")
	fs.StringVar(&o.tlsServerName, "tls-server-name", "bench.test", "verified TLS server name")
	fs.BoolVar(&o.expectPolicy, "expect-policy", false, "require origin response X-Policy: applied")
	fs.StringVar(&o.certFile, "cert-file", "", "serve: TLS certificate PEM")
	fs.StringVar(&o.keyFile, "key-file", "", "serve: TLS private key PEM")
	fs.StringVar(&o.listen, "listen", ":19201", "serve: HTTP listen address")
	fs.StringVar(&o.tlsListen, "tls-listen", ":19443", "serve: HTTPS listen address")
	fs.StringVar(&o.tcpListen, "tcp-listen", ":18080", "serve: TCP echo listen address")
	fs.StringVar(&o.tcpTLSListen, "tcp-tls-listen", ":19444", "serve: TLS echo listen address")
	return o
}

func (o *options) validate() error {
	if o.mode == "serve" {
		return o.validateServe()
	}
	if o.mode != "http" && o.mode != "tcp" {
		return fmt.Errorf("unsupported mode %q", o.mode)
	}
	if o.seconds <= 0 || o.rate <= 0 || o.concurrency <= 0 || o.targets <= 0 || o.body < 0 || o.profiles < 0 ||
		o.slot < 0 {
		return errors.New(
			"seconds, rate, concurrency and targets must be positive; body, profiles and slot must be nonnegative",
		)
	}
	switch o.targetMode {
	case "fixed", "names", "cold", "ips", "ttl":
	default:
		return fmt.Errorf("unsupported targets-mode %q", o.targetMode)
	}
	if o.targetMode == "ips" && o.targets > 2*65536 {
		return errors.New("IP target count exceeds the 10.200.0.0/15 test range")
	}
	if (strings.HasPrefix(o.endpoint, "https://") || o.tlsTCP) && (o.caFile == "" || o.tlsServerName == "") {
		return errors.New("TLS requires -ca-file and a nonempty -tls-server-name")
	}
	if o.mode == "http" {
		return o.validateHTTP()
	}
	return o.validateTCP()
}

func (o *options) validateServe() error {
	if o.certFile == "" || o.keyFile == "" {
		return errors.New("serve requires -cert-file and -key-file")
	}
	for _, address := range []string{o.listen, o.tlsListen, o.tcpListen, o.tcpTLSListen} {
		if _, _, err := net.SplitHostPort(address); err != nil {
			return fmt.Errorf("invalid listen address %q: %w", address, err)
		}
	}
	return nil
}

func (o *options) validateHTTP() error {
	endpoint, err := url.Parse(o.endpoint)
	if err != nil || endpoint.Host == "" || (endpoint.Scheme != "http" && endpoint.Scheme != "https") {
		return errors.New("HTTP endpoint must be an http:// or https:// URL")
	}
	if o.targetMode != "fixed" {
		port, err := strconv.Atoi(o.authority)
		if err != nil || port < 1 || port > 65535 {
			return errors.New("rotating HTTP targets require -authority to be a port")
		}
	}
	return nil
}

func (o *options) validateTCP() error {
	if _, _, err := net.SplitHostPort(o.endpoint); err != nil {
		return fmt.Errorf("invalid TCP endpoint: %w", err)
	}
	if _, _, err := net.SplitHostPort(o.authority); err != nil {
		return fmt.Errorf("invalid CONNECT authority: %w", err)
	}
	if o.targetMode != "fixed" && o.targetMode != "names" && o.targetMode != "cold" {
		return errors.New("TCP supports fixed, names and cold target modes")
	}
	return nil
}

func (o *options) tlsConfig() (*tls.Config, error) {
	config := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: o.tlsServerName}
	if o.caFile != "" {
		pem, err := os.ReadFile(o.caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA: %w", err)
		}
		config.RootCAs = x509.NewCertPool()
		if !config.RootCAs.AppendCertsFromPEM(pem) {
			return nil, errors.New("CA file contains no certificates")
		}
	}
	return config, nil
}

func (o *options) httpOperation() (func(context.Context, int) error, func(), error) {
	config, err := o.tlsConfig()
	if err != nil {
		return nil, nil, err
	}
	t := &http.Transport{
		MaxIdleConns:        o.concurrency,
		MaxIdleConnsPerHost: o.concurrency,
		MaxConnsPerHost:     o.concurrency,
		DisableKeepAlives:   o.closeConnections,
		TLSClientConfig:     config,
	}
	var transport http.RoundTripper = t
	if o.h2 {
		if strings.HasPrefix(o.endpoint, "https://") {
			if err := http2.ConfigureTransport(t); err != nil {
				return nil, nil, err
			}
		} else {
			transport = &http2.Transport{
				AllowHTTP:          true,
				DisableCompression: true,
				DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, addr)
				},
			}
		}
	} else {
		t.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	client := &http.Client{
		Transport:     transport,
		Timeout:       6 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	payload := bytes.Repeat([]byte("x"), o.body)
	var sequence atomic.Uint64
	prefix := strconv.FormatInt(time.Now().UnixNano(), 10)
	operation := func(ctx context.Context, i int) error {
		authority := o.authority
		switch o.targetMode {
		case "names":
			authority = fmt.Sprintf("pool-%d.test:%s", i, o.authority)
		case "cold":
			authority = fmt.Sprintf("cold-%s-%d.test:%s", prefix, sequence.Add(1), o.authority)
		case "ttl":
			authority = fmt.Sprintf("ttl.pool-%d.test:%s", i, o.authority)
		case "ips":
			authority = fmt.Sprintf("10.%d.%d.%d:%s", 200+i/65536, (i/256)%256, i%256, o.authority)
		}
		method := http.MethodGet
		if o.body > 0 {
			method = http.MethodPost
		}
		req, err := http.NewRequestWithContext(ctx, method, o.endpoint, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Host = authority
		req.Header.Set("x-test-sni", o.tlsServerName)
		res, err := client.Do(req)
		if err != nil {
			return err
		}
		data, readErr := io.ReadAll(io.LimitReader(res.Body, 4096))
		closeErr := res.Body.Close()
		if res.StatusCode != http.StatusOK {
			return fmt.Errorf("HTTP status %d", res.StatusCode)
		}
		if err := errors.Join(readErr, closeErr); err != nil {
			return err
		}
		if o.h2 && res.ProtoMajor != 2 {
			return fmt.Errorf("expected HTTP/2, got %s", res.Proto)
		}
		if string(data) != "ok\n" {
			return fmt.Errorf("origin response mismatch: %q", data)
		}
		if o.expectPolicy && res.Header.Get("X-Policy") != "applied" {
			return fmt.Errorf("origin policy mutation missing: %q", res.Header.Get("X-Policy"))
		}
		return nil
	}
	return operation, client.CloseIdleConnections, nil
}

func (o *options) tcpOperation() (func(context.Context, int) error, func(), error) {
	config, err := o.tlsConfig()
	if err != nil {
		return nil, nil, err
	}
	type channel struct {
		sync.Mutex
		c net.Conn
	}
	channels := make([]channel, o.targets)
	cleanup := func() {
		for i := range channels {
			if channels[i].c != nil {
				closeResource(channels[i].c)
				channels[i].c = nil
			}
		}
	}
	profiles := make([]any, 0, o.profiles)
	for i := 0; i < o.profiles; i++ {
		profiles = append(
			profiles,
			map[string]any{
				"uid": fmt.Sprint(i),
				"tcpPolicy": map[string]any{
					"rules": []any{
						map[string]any{
							"name":   "miss",
							"match":  []any{map[string]any{"cidrs": []string{fmt.Sprintf("198.18.%d.0/24", i%256)}}},
							"action": "TCP_ACTION_DENY",
						},
					},
				},
			},
		)
	}
	policy, err := json.Marshal(map[string]any{"profiles": profiles})
	if err != nil {
		return nil, nil, err
	}
	payload := bytes.Repeat([]byte("x"), o.body)
	if len(payload) == 0 {
		payload = []byte("ping\n")
	}
	var sequence atomic.Uint64
	prefix := strconv.FormatInt(time.Now().UnixNano(), 10)
	operation := func(ctx context.Context, i int) (err error) {
		var c net.Conn
		if o.stream {
			ch := &channels[i]
			ch.Lock()
			defer ch.Unlock()
			if err := ctx.Err(); err != nil {
				return err
			}
			c = ch.c
			defer func() {
				if err != nil && ch.c != nil {
					err = errors.Join(err, ch.c.Close())
					ch.c = nil
				}
			}()
		}
		deadline := time.Now().Add(6 * time.Second)
		if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
			deadline = contextDeadline
		}
		if c == nil {
			host := o.tcpHost
			switch o.targetMode {
			case "names":
				host = fmt.Sprintf("pool-%d.test", i)
			case "cold":
				host = fmt.Sprintf("cold-%s-%d.test", prefix, sequence.Add(1))
			}
			c, err = o.dialTunnel(ctx, deadline, config, host, policy)
			if err != nil {
				return err
			}
			if o.stream {
				channels[i].c = c
			}
		}
		if !o.stream {
			defer closeResource(c)
		}
		if err := c.SetDeadline(deadline); err != nil {
			return err
		}
		return checkEcho(c, payload)
	}
	return operation, cleanup, nil
}

func checkEcho(c net.Conn, payload []byte) error {
	if _, err := c.Write(payload); err != nil {
		return err
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(c, response); err != nil {
		return err
	}
	if !bytes.Equal(response, payload) {
		return errors.New("echo mismatch")
	}
	return nil
}

func (o *options) dialTunnel(
	ctx context.Context,
	deadline time.Time,
	config *tls.Config,
	host string,
	policy []byte,
) (net.Conn, error) {
	c, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", o.endpoint)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (net.Conn, error) { return nil, errors.Join(err, c.Close()) }
	if err := c.SetDeadline(deadline); err != nil {
		return fail(err)
	}
	if _, err := fmt.Fprintf(
		c,
		"CONNECT %s HTTP/1.1\r\nHost: %s\r\nx-test-host: %s\r\nx-test-slot: %d\r\nx-test-connection-policy: %s\r\n\r\n",
		o.authority,
		o.authority,
		host,
		o.slot,
		policy,
	); err != nil {
		return fail(err)
	}
	res, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodConnect})
	if err != nil {
		return fail(err)
	}
	if res.StatusCode != http.StatusOK {
		return fail(fmt.Errorf("CONNECT status %d", res.StatusCode))
	}
	// The echo origin sends nothing before the first client payload.
	if o.tlsTCP {
		tlsConn := tls.Client(c, config)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return fail(err)
		}
		return tlsConn, nil
	}
	return c, nil
}

func (o *options) serve() error {
	cert, err := tls.LoadX509KeyPair(o.certFile, o.keyFile)
	if err != nil {
		return err
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("X-Policy", r.Header.Get("X-Policy"))
		if _, err := io.WriteString(w, "ok\n"); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	})
	var listeners []net.Listener
	defer func() {
		for _, listener := range listeners {
			closeResource(listener)
		}
	}()
	failures := make(chan error, 4)
	for i, address := range []string{o.listen, o.tlsListen, o.tcpListen, o.tcpTLSListen} {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			return err
		}
		listeners = append(listeners, listener)
		if i == 0 || i == 1 {
			server := &http.Server{
				Handler:           h2c.NewHandler(handler, &http2.Server{}),
				ReadHeaderTimeout: 5 * time.Second,
				TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}},
			}
			go func() {
				if i == 1 {
					failures <- server.ServeTLS(listener, "", "")
				} else {
					failures <- server.Serve(listener)
				}
			}()
		} else {
			if i == 3 {
				listener = tls.NewListener(
					listener,
					&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}},
				)
			}
			go func() {
				for {
					c, err := listener.Accept()
					if err != nil {
						failures <- err
						return
					}
					go func() {
						defer closeResource(c)
						if _, err := io.Copy(c, c); err != nil && !errors.Is(err, net.ErrClosed) {
							fmt.Fprintln(os.Stderr, err)
						}
					}()
				}
			}()
		}
	}
	return <-failures
}

func run(o *options) error {
	if err := o.validate(); err != nil {
		return err
	}
	if o.mode == "serve" {
		return o.serve()
	}
	var operation func(context.Context, int) error
	var cleanup func()
	var err error
	if o.mode == "http" {
		operation, cleanup, err = o.httpOperation()
	} else {
		operation, cleanup, err = o.tcpOperation()
	}
	if err != nil {
		return err
	}
	defer cleanup()
	count := o.rate * o.seconds
	result, runErr := load.Run(
		context.Background(),
		load.Config{
			Requests:    count,
			Identities:  o.targets,
			Concurrency: o.concurrency,
			Rate:        o.rate,
			Duration:    time.Duration(o.seconds)*time.Second + 10*time.Second,
		},
		operation,
	)
	result.BatchMeans = nil
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		return err
	}
	if runErr != nil {
		return runErr
	}
	if result.Errors > 0 {
		return fmt.Errorf("%d failed operations: %s", result.Errors, result.FirstError)
	}
	if result.Operations != count {
		return fmt.Errorf("completed %d/%d operations", result.Operations, count)
	}
	return nil
}

func closeResource(c io.Closer) {
	if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		fmt.Fprintln(os.Stderr, "close resource:", err)
	}
}

func main() {
	o := flags(flag.CommandLine)
	flag.Parse()
	if err := run(o); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
