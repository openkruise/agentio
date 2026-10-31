// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

package gatewayagent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"google.golang.org/protobuf/encoding/protojson"
)

//go:embed testdata/internal-connect.json
var internalConnectFixture []byte

type internalConnectConn struct {
	net.Conn
	reader io.Reader
	writer io.Writer
}

func (c internalConnectConn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c internalConnectConn) Write(p []byte) (int, error) { return c.writer.Write(p) }

// Exercise server-first HTTP closure and cancellation over TLS and both internal
// hops while the downstream HTTP/2 CONNECT request remains open.
func TestCommunityEnvoyInternalConnect(t *testing.T) {
	binary := os.Getenv("AGENTIO_TEST_ENVOY_BINARY")
	if binary == "" {
		t.Skip("set AGENTIO_TEST_ENVOY_BINARY")
	}
	certificateServer := httptest.NewTLSServer(http.NotFoundHandler())
	defer certificateServer.Close()
	key, err := x509.MarshalPKCS8PrivateKey(certificateServer.TLS.Certificates[0].PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.Repeat([]byte("x"), 256*1024)
	arrived, released := make(chan struct{}), make(chan struct{})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/cancel" {
			close(arrived)
			<-r.Context().Done()
			close(released)
			return
		}
		data := []byte("hello")
		if r.URL.Path == "/large" {
			data = body
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		if _, err := w.Write(data); err != nil {
			t.Errorf("origin response: %v", err)
		}
	}))
	defer origin.Close()
	bootstrap, err := bootstrapConfig(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	data, err := protojson.Marshal(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	var config, resources map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(internalConnectFixture, &resources); err != nil {
		t.Fatal(err)
	}
	delete(config, "dynamicResources")
	delete(config, "admin")
	config["staticResources"] = resources
	ports, releasePorts := reservePorts(t, 1)
	listeners := resources["listeners"].([]any)
	listeners[0].(map[string]any)["address"].(map[string]any)["socket_address"].(map[string]any)["port_value"] = ports[0]
	chain := listeners[1].(map[string]any)["filter_chains"].([]any)[0].(map[string]any)
	cert := chain["transport_socket"].(map[string]any)["typed_config"].(map[string]any)["common_tls_context"].(map[string]any)["tls_certificates"].([]any)[0].(map[string]any)
	cert["certificate_chain"].(map[string]any)["inline_string"] = string(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateServer.Certificate().Raw}),
	)
	cert["private_key"].(map[string]any)["inline_string"] = string(
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}),
	)
	cluster := resources["clusters"].([]any)[2].(map[string]any)
	endpoint := cluster["load_assignment"].(map[string]any)["endpoints"].([]any)[0].(map[string]any)["lb_endpoints"].([]any)[0].(map[string]any)["endpoint"].(map[string]any)
	endpoint["address"].(map[string]any)["socket_address"].(map[string]any)["port_value"] = origin.Listener.Addr().(*net.TCPAddr).Port
	data, err = json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "envoy.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	var logs bytes.Buffer
	cmd := exec.CommandContext(ctx, binary, "-c", path, "--concurrency", "1", "--disable-hot-restart", "-l", "warning")
	cmd.Stdout, cmd.Stderr = &logs, &logs
	releasePorts()
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	defer func() {
		cancel()
		var exit *exec.ExitError
		if err := cmd.Wait(); err != nil && !errors.As(err, &exit) {
			t.Errorf("wait for Envoy: %v", err)
		}
		if t.Failed() {
			t.Log(logs.String())
		}
	}()
	var connection net.Conn
	deadline := time.Now().Add(5 * time.Second)
	for {
		connection, err = net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", ports[0]))
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	defer closeResource(connection)
	client, err := (&http2.Transport{}).NewClientConn(connection)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificateServer.Certificate())
	for _, path := range []string{"small", "large", "cancel"} {
		t.Run(path, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			reader, writer := io.Pipe()
			defer closeResource(writer)
			request, err := http.NewRequestWithContext(ctx, http.MethodConnect, "http://internal:443", reader)
			if err != nil {
				t.Fatal(err)
			}
			response, err := client.RoundTrip(request)
			if err != nil {
				t.Fatal(err)
			}
			defer closeResource(response.Body)
			tunnel := tls.Client(
				internalConnectConn{Conn: connection, reader: response.Body, writer: writer},
				&tls.Config{
					RootCAs:    roots,
					ServerName: certificateServer.Certificate().DNSNames[0],
					MinVersion: tls.VersionTLS12,
				},
			)
			if err := tunnel.HandshakeContext(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := fmt.Fprintf(
				tunnel,
				"GET /%s HTTP/1.1\r\nHost: origin\r\nConnection: close\r\n\r\n",
				path,
			); err != nil {
				t.Fatal(err)
			}
			if path == "cancel" {
				select {
				case <-arrived:
				case <-ctx.Done():
					t.Fatal("request did not reach origin")
				}
				cancel()
				// Closing the response explicitly sends the HTTP/2 cancellation.
				if err := response.Body.Close(); err != nil {
					t.Fatal(err)
				}
				select {
				case <-released:
				case <-time.After(2 * time.Second):
					t.Fatal("cancelled CONNECT retained its upstream request")
				}
				return
			}
			inner, err := http.ReadResponse(bufio.NewReader(tunnel), &http.Request{Method: http.MethodGet})
			if err != nil {
				t.Fatal(err)
			}
			defer closeResource(inner.Body)
			actual, err := io.ReadAll(inner.Body)
			if err != nil {
				t.Fatal(err)
			}
			want := []byte("hello")
			if path == "large" {
				want = body
			}
			if inner.StatusCode != http.StatusOK || !bytes.Equal(actual, want) {
				t.Fatalf(
					"HTTP response status=%d bytes=%d, want 200 and %d bytes",
					inner.StatusCode,
					len(actual),
					len(want),
				)
			}
		})
	}
}
