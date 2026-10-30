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

package networklimits

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
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
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/openkruise/agentio/bench/connect/fixture"
)

const rate = 128 * 1024
const size = 512 * 1024

type object = map[string]any

func obj(v any) object { return v.(map[string]any) }
func nested(v any, keys ...string) object {
	for _, key := range keys {
		v = obj(v)[key]
	}
	return obj(v)
}
func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func closeTest(t *testing.T, c io.Closer) {
	t.Helper()
	if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Error(err)
	}
}
func payload(n int) []byte { return bytes.Repeat([]byte("x"), n) }
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	must(t, l.Close())
	return port
}
func eventually(t *testing.T, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatal("condition did not become true within 10s")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

type origin struct {
	listener net.Listener
	release  chan struct{}
	produced atomic.Int64
	conns    sync.Map
	workers  sync.WaitGroup
}

func startOrigin(t *testing.T, encrypted bool) *origin {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	if encrypted {
		// Reuse the standard library's local test certificate.
		server := httptest.NewTLSServer(http.NotFoundHandler())
		l = tls.NewListener(l, server.TLS.Clone())
		server.Close()
	}
	o := &origin{listener: l, release: make(chan struct{})}
	o.workers.Go(func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			o.conns.Store(c, true)
			o.workers.Go(func() {
				defer o.conns.Delete(c)
				defer closeTest(t, c)
				o.serve(c)
			})
		}
	})
	t.Cleanup(func() {
		must(t, l.Close())
		select {
		case <-o.release:
		default:
			close(o.release)
		}
		o.conns.Range(func(c, _ any) bool {
			closeTest(t, c.(net.Conn))
			return true
		})
		o.workers.Wait()
	})
	return o
}
func (o *origin) port() int { return o.listener.Addr().(*net.TCPAddr).Port }

// Client resets and closed tunnels deliberately interrupt origin writes.
//
//nolint:errcheck // Origin write failures are observed by the client or caused by deliberate cancellation.
func (o *origin) serve(c net.Conn) {
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	r := bufio.NewReader(c)
	line, err := r.ReadString('\n')
	if err != nil {
		return
	}
	if strings.HasPrefix(line, "GET ") {
		for {
			line, err = r.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		_, _ = fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", size)
		_, _ = c.Write(payload(size))
		return
	}
	if line == "hold\n" {
		<-o.release
		_, _ = c.Write([]byte("done"))
		return
	}
	if line == "done\n" {
		_, _ = c.Write([]byte("done"))
		return
	}
	var direction string
	var n int
	if _, err = fmt.Sscanf(line, "%s %d", &direction, &n); err != nil {
		return
	}
	switch direction {
	case "U":
		data := make([]byte, n)
		if _, err = io.ReadFull(r, data); err == nil && bytes.Equal(data, payload(n)) {
			_, _ = c.Write([]byte("OK"))
		}
	case "P":
		for n > 0 {
			buf := make([]byte, min(n, 16384))
			if _, err = io.ReadFull(r, buf); err != nil || !bytes.Equal(buf, payload(len(buf))) {
				return
			}
			if _, err = c.Write([]byte("p")); err != nil {
				return
			}
			n -= len(buf)
		}
		_, _ = c.Write([]byte("OK"))
	case "D":
		_, _ = c.Write(payload(n))
	case "E":
		for n > 0 {
			data := make([]byte, min(n, 16384))
			if _, err = io.ReadFull(r, data); err != nil {
				return
			}
			if _, err = c.Write(data); err != nil {
				return
			}
			n -= len(data)
		}
	case "B":
		if tcp, ok := c.(*net.TCPConn); ok {
			_ = tcp.SetWriteBuffer(65536)
		}
		data := payload(65536)
		for n > 0 {
			written, err := c.Write(data[:min(n, len(data))])
			o.produced.Add(int64(written))
			if err != nil {
				return
			}
			n -= written
		}
	}
}

type runtime struct {
	port       int
	admin      int
	cmd        *exec.Cmd
	listener   object
	lds        string
	extensions map[string]object
}

func filters(listener object) []any {
	chain := obj(listener["filter_chains"].([]any)[0])
	return nested(chain["filters"].([]any)[0], "typed_config")["http_filters"].([]any)
}
func setFilters(listener object, fs []any) {
	chain := obj(listener["filter_chains"].([]any)[0])
	nested(chain["filters"].([]any)[0], "typed_config")["http_filters"] = fs
}
func policy(filter any) object {
	return nested(filter, "typed_config", "value", "filter_config", "value")
}
func clone(t *testing.T, v object) object {
	t.Helper()
	b, err := json.Marshal(v)
	must(t, err)
	var result object
	must(t, json.Unmarshal(b, &result))
	return result
}
func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	must(t, err)
	must(t, os.WriteFile(path+".new", b, 0600))
	must(t, os.Rename(path+".new", path))
}
func (r *runtime) writeLDS(t *testing.T, listener object) {
	v := clone(t, listener)
	if r.extensions != nil {
		for _, f := range filters(v) {
			name := obj(f)["name"].(string)
			if _, ok := r.extensions[name]; ok {
				delete(obj(f), "typed_config")
				obj(f)["config_discovery"] = object{
					"config_source": object{
						"resource_api_version": "V3",
						"path_config_source":   object{"path": filepath.Join(filepath.Dir(r.lds), name+".json")},
					},
					"type_urls": []any{
						"type.googleapis.com/envoy.extensions.filters.http.dynamic_modules.v3.DynamicModuleFilter",
					},
				}
			}
		}
	}
	v["@type"] = "type.googleapis.com/envoy.config.listener.v3.Listener"
	writeJSON(t, r.lds, object{"version_info": strconv.FormatInt(time.Now().UnixNano(), 10), "resources": []any{v}})
}
func startEnvoy(t *testing.T, plain, tlsPort int, edit func(object)) *runtime {
	return startEnvoyConfig(t, plain, tlsPort, edit, false)
}
func startEnvoyConfig(t *testing.T, plain, tlsPort int, edit func(object), ecds bool) *runtime {
	t.Helper()
	binary := os.Getenv("AGENTIO_TEST_ENVOY_BINARY")
	if binary == "" {
		t.Skip("set AGENTIO_TEST_ENVOY_BINARY to run against real Envoy")
	}
	module := os.Getenv("AGENTIO_TEST_NETWORK_LIMITS_MODULE")
	if module == "" {
		module = "/usr/local/lib/libenvoy_agentio_network_limits.so"
	}
	var b object
	must(t, json.Unmarshal(fixture.Bootstrap, &b))
	r := &runtime{port: freePort(t), admin: freePort(t), lds: filepath.Join(t.TempDir(), "lds.json")}
	nested(b, "admin", "address", "socket_address")["port_value"] = r.admin
	resources := obj(b["static_resources"])
	r.listener = obj(resources["listeners"].([]any)[0])
	nested(r.listener, "address", "socket_address")["port_value"] = r.port
	r.listener["connection_balance_config"] = object{"exact_balance": object{}}
	for _, v := range resources["clusters"].([]any) {
		cluster := obj(v)
		// Keep the upstream pool from imposing a separate ceiling on scale tests.
		cluster["circuit_breakers"] = object{"thresholds": []any{
			object{"max_connections": 100000, "max_requests": 100000},
		}}
		// Allow a TCP SYN retransmission when this fixture runs under external netem.
		cluster["connect_timeout"] = "5s"
		port := plain
		if cluster["name"] == "tls" {
			port = tlsPort
		}
		endpoint := nested(cluster, "load_assignment")["endpoints"].([]any)[0]
		lb := obj(endpoint)["lb_endpoints"].([]any)[0]
		nested(lb, "endpoint", "address", "socket_address")["port_value"] = port
	}
	moduleConfig := nested(filters(r.listener)[1], "typed_config", "value", "dynamic_module_config", "module", "local")
	moduleConfig["filename"] = module
	if edit != nil {
		edit(r.listener)
	}
	if ecds {
		r.extensions = make(map[string]object)
		for _, f := range filters(r.listener) {
			name := obj(f)["name"].(string)
			if name == "agentio.bandwidth" || name == "agentio.connect_concurrency" {
				r.extensions[name] = clone(t, obj(f))
				r.writeECDS(t, name, r.extensions[name])
			}
		}
	}
	delete(resources, "listeners")
	b["node"] = object{"id": "network-limits-test", "cluster": "network-limits-test"}
	b["dynamic_resources"] = object{
		"lds_config": object{"resource_api_version": "V3", "path_config_source": object{"path": r.lds}},
	}
	r.writeLDS(t, r.listener)
	path := filepath.Join(filepath.Dir(r.lds), "envoy.json")
	writeJSON(t, path, b)
	logPath := filepath.Join(filepath.Dir(r.lds), "envoy.log")
	log, err := os.Create(logPath)
	must(t, err)
	r.cmd = exec.Command(binary, "-c", path, "--concurrency", "2", "--disable-hot-restart", "--log-level", "error")
	r.cmd.Stdout = log
	r.cmd.Stderr = log
	must(t, r.cmd.Start())
	exited := make(chan error, 1)
	go func() { exited <- r.cmd.Wait() }()
	t.Cleanup(func() {
		if err := r.cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
			t.Error(err)
		}
		select {
		case err := <-exited:
			if err != nil {
				t.Errorf("Envoy shutdown: %v", err)
			}
		case <-time.After(10 * time.Second):
			must(t, r.cmd.Process.Kill())
			<-exited
			t.Error("Envoy shutdown timed out")
		}
		must(t, log.Close())
		if t.Failed() {
			data, err := os.ReadFile(logPath)
			must(t, err)
			t.Log(string(data))
		}
	})
	eventually(t, func() bool {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", r.port), 100*time.Millisecond)
		if err != nil {
			return false
		}
		must(t, c.Close())
		return true
	})
	return r
}
func (r *runtime) counter(t *testing.T, name string) int {
	return r.stat(t, "listener_manager.lds."+name)
}
func (r *runtime) stat(t *testing.T, name string) int {
	t.Helper()
	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(
		fmt.Sprintf("http://127.0.0.1:%d/stats?format=json&filter=%s", r.admin, name),
	)
	must(t, err)
	defer closeTest(t, resp.Body)
	var result struct{ Stats []struct{ Value int } }
	must(t, json.NewDecoder(resp.Body).Decode(&result))
	n := 0
	for _, s := range result.Stats {
		n += s.Value
	}
	return n
}
func (r *runtime) reload(t *testing.T, edit func(object), reject bool) {
	t.Helper()
	listener := clone(t, r.listener)
	edit(listener)
	if reject {
		fs := filters(listener)
		var invalid object
		for _, f := range fs {
			if obj(f)["name"] == "agentio.bandwidth" || obj(f)["name"] == "agentio.connect_concurrency" {
				invalid = clone(t, obj(f))
				break
			}
		}
		invalid["name"] = "reject-candidate"
		nested(invalid, "typed_config", "value")["filter_name"] = "unknown-filter"
		setFilters(listener, append(fs[:len(fs)-1], invalid, fs[len(fs)-1]))
	}
	name := "update_success"
	if reject {
		name = "update_rejected"
	}
	before := r.counter(t, name)
	r.writeLDS(t, listener)
	eventually(t, func() bool { return r.counter(t, name) > before })
}

type stream struct {
	t        *testing.T
	response *http.Response
	writer   *io.PipeWriter
	cancel   context.CancelFunc
}

func (s *stream) close() {
	s.cancel()
	closeTest(s.t, s.writer)
	closeTest(s.t, s.response.Body)
}

type h2client struct{ conn *http2.ClientConn }

func newClient(t *testing.T, port int) *h2client {
	t.Helper()
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	must(t, err)
	transport := &http2.Transport{AllowHTTP: true}
	cc, err := transport.NewClientConn(c)
	must(t, err)
	t.Cleanup(func() { closeTest(t, cc) })
	return &h2client{cc}
}
func (c *h2client) open(t *testing.T, tenant, sandbox, target string, expected int) *stream {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	reader, writer := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, "CONNECT", "http://"+target, reader)
	must(t, err)
	req.Header.Set("x-tenant", tenant)
	if sandbox != "" {
		req.Header.Set("x-sandbox", sandbox)
	}
	resp, err := c.conn.RoundTrip(req)
	if err != nil {
		cancel()
		closeTest(t, writer)
		t.Fatal(err)
	}
	s := &stream{t, resp, writer, cancel}
	t.Cleanup(s.close)
	if expected != 0 && resp.StatusCode != expected {
		t.Fatalf("CONNECT %s: got %d, want %d", sandbox, resp.StatusCode, expected)
	}
	return s
}
func (c *h2client) eventuallyOpen(t *testing.T, sandbox string) *stream {
	t.Helper()
	var s *stream
	eventually(t, func() bool {
		s = c.open(t, "test", sandbox, "plain:80", 0)
		if s.response.StatusCode == 200 {
			return true
		}
		if s.response.StatusCode != 429 {
			t.Fatalf("unexpected admission status: %d", s.response.StatusCode)
		}
		s.close()
		return false
	})
	return s
}
func finish(t *testing.T, s *stream) {
	t.Helper()
	_, err := io.WriteString(s.writer, "done\n")
	must(t, err)
	must(t, s.writer.Close())
	b, err := io.ReadAll(s.response.Body)
	must(t, err)
	if string(b) != "done" {
		t.Fatalf("response: %q", b)
	}
	s.close()
}
func tunnel(t *testing.T, port int, sandbox string, encrypted bool) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	must(t, err)
	t.Cleanup(func() { closeTest(t, c) })
	must(t, c.SetDeadline(time.Now().Add(30*time.Second)))
	target := "plain:80"
	if encrypted {
		target = "tls:443"
	}
	_, err = fmt.Fprintf(
		c,
		"CONNECT %s HTTP/1.1\r\nHost: %s\r\nx-tenant: http\r\nx-sandbox: %s\r\n\r\n",
		target,
		target,
		sandbox,
	)
	must(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "CONNECT"})
	must(t, err)
	if resp.StatusCode != 200 {
		t.Fatalf("CONNECT: %s", resp.Status)
	}
	if encrypted {
		c = tls.Client(c, &tls.Config{InsecureSkipVerify: true})
	} // Test-only local certificate.
	return c
}

func (r *runtime) writeECDS(t *testing.T, name string, filter object) {
	resource := object{
		"@type":        "type.googleapis.com/envoy.config.core.v3.TypedExtensionConfig",
		"name":         name,
		"typed_config": filter["typed_config"],
	}
	writeJSON(
		t,
		filepath.Join(filepath.Dir(r.lds), name+".json"),
		object{"version_info": strconv.FormatInt(time.Now().UnixNano(), 10), "resources": []any{resource}},
	)
}
func (r *runtime) reloadECDS(t *testing.T, name string, edit func(object), reject bool) {
	t.Helper()
	filter := clone(t, r.extensions[name])
	edit(policy(filter))
	if reject {
		nested(filter, "typed_config", "value")["filter_name"] = "unknown-filter"
	}
	stat := "extension_config_discovery.*update_success"
	if reject {
		stat = "extension_config_discovery.*config_fail"
	}
	before := r.stat(t, stat)
	r.writeECDS(t, name, filter)
	eventually(t, func() bool { return r.stat(t, stat) > before })
	if !reject {
		r.extensions[name] = filter
	}
}
