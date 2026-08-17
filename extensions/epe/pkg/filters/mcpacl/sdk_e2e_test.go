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

//go:build mcp_e2e

// End-to-end tests that drive the MCP ACL filter with a real MCP SDK client.
// Run with: go test -tags mcp_e2e -run TestSDKE2E -v -timeout 120s ./extensions/epe/pkg/filters/mcpacl/
//
// Requires Node.js and npm on PATH. The test installs
// @modelcontextprotocol/sdk into a temp directory at runtime.

package mcpacl

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/httpreq"
)

// sdkServerConfig is the filter config used by the E2E test server.
func sdkServerConfig() Config {
	return Config{
		DefaultAction: "deny",
		DenyStatus:    403,
		DenyBody:      "MCP tool is not permitted",
		Rules: []RuleEntry{
			{Method: "tools/call", ToolNames: []string{"allowed-tool", "read_file"}, Action: "allow"},
		},
	}
}

// startFilterServer starts an HTTP server that wraps the MCP ACL filter and
// implements a minimal MCP server backend. Every request is processed through
// the filter first; if the filter denies, the deny response is returned. If
// the filter allows, a minimal MCP JSON-RPC response is returned.
// protocolVersion controls the version advertised in initialize/discover
// responses — use "2025-11-25" for the stable TypeScript SDK or "2026-07-28"
// for the Go SDK (GA fast path with Mcp-Method/Mcp-Name headers).
func startFilterServer(t *testing.T, cfg Config, protocolVersion string) *httptest.Server {
	f := New(filter.RuleConfig[Config]{
		ID:  filter.UnitID{Scope: "ns/p", Name: "mcp-whitelist"},
		Cfg: cfg,
	})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract headers (lowercased, matching the filter's expectations).
		headers := make(map[string]string)
		for k, v := range r.Header {
			if len(v) > 0 {
				headers[strings.ToLower(k)] = v[0]
			}
		}

		// Read the request body.
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(400)
			return
		}

		st := &filter.Stream{Request: httpreq.HTTPRequest{Headers: headers}}

		// Headers phase.
		hdrAct, hErr := f.OnRequestHeaders(context.Background(), st)
		if hErr != nil {
			w.WriteHeader(500)
			return
		}
		if hdrAct.Kind() == filter.KindStop {
			reply, _ := hdrAct.Reply()
			w.WriteHeader(int(reply.Status))
			w.Write(reply.Body)
			return
		}

		// Body phase (if the filter requested the body).
		if hdrAct.Kind() == filter.KindNeedBody {
			bodyAct, bErr := f.OnRequestBody(context.Background(), st,
				filter.Body{Bytes: body, Complete: true})
			if bErr != nil {
				w.WriteHeader(500)
				return
			}
			if bodyAct.Kind() == filter.KindStop {
				reply, _ := bodyAct.Reply()
				w.WriteHeader(int(reply.Status))
				w.Write(reply.Body)
				return
			}
		}

		// Filter allowed the request (or passed it through). Return a
		// minimal MCP JSON-RPC response based on the method.
		var req struct {
			JSONRPC string `json:"jsonrpc"`
			ID      any    `json:"id"`
			Method  string `json:"method"`
		}
		// If the body is empty or not JSON, return 202 for notifications.
		if len(bytes.TrimSpace(body)) == 0 {
			w.WriteHeader(202)
			return
		}
		if err := json.Unmarshal(body, &req); err != nil {
			w.WriteHeader(400)
			w.Write([]byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}`))
			return
		}

		// 202 for notifications (no id).
		if req.ID == nil {
			w.WriteHeader(202)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "initialize", "server/discover":
			json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result": map[string]any{
					"protocolVersion": protocolVersion,
					"capabilities": map[string]any{
						"tools": map[string]any{"listChanged": false},
					},
					"serverInfo": map[string]any{"name": "test-server", "version": "1.0"},
				},
			})
		case "tools/list":
			json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result": map[string]any{
					"tools": []map[string]any{
						{"name": "allowed-tool", "description": "An allowed test tool", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{}}},
						{"name": "read_file", "description": "Read a file", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{}}},
					},
				},
			})
		case "tools/call":
			json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result": map[string]any{
					"content": []map[string]any{
						{"type": "text", "text": "tool executed successfully"},
					},
				},
			})
		case "ping":
			json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result":  map[string]any{},
			})
		default:
			json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result":  map[string]any{},
			})
		}
	})

	server := httptest.NewServer(handler)
	return server
}

// tsClientScript is the TypeScript client that uses @modelcontextprotocol/sdk.
const tsClientScript = `import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const url = process.env.MCP_SERVER_URL;
const transport = new StreamableHTTPClientTransport(new URL(url));
const client = new Client({ name: "e2e-test-client", version: "1.0" }, { capabilities: {} });

function result(name, status, detail) {
    console.log("RESULT:" + name + ":" + status + ":" + detail);
}

async function main() {
    await client.connect(transport);
    result("connect", "ok", "connected");

    // Test 1: Call an allowed tool (should succeed).
    try {
        const r = await client.callTool({ name: "allowed-tool", arguments: {} });
        result("allowed-tool", "ok", "call succeeded");
    } catch (e) {
        result("allowed-tool", "fail", e.message || String(e));
    }

    // Test 2: Call another allowed tool (read_file).
    try {
        const r = await client.callTool({ name: "read_file", arguments: {} });
        result("read_file", "ok", "call succeeded");
    } catch (e) {
        result("read_file", "fail", e.message || String(e));
    }

    // Test 3: Call a denied tool (should fail with 403).
    try {
        await client.callTool({ name: "evil", arguments: {} });
        result("evil", "unexpected_ok", "denied tool was not blocked");
    } catch (e) {
        result("evil", "blocked", e.message || String(e));
    }

    // Test 4: Call another unlisted tool (should fail).
    try {
        await client.callTool({ name: "delete_file", arguments: {} });
        result("delete_file", "unexpected_ok", "denied tool was not blocked");
    } catch (e) {
        result("delete_file", "blocked", e.message || String(e));
    }

    // Test 5: List tools (should pass through, not governed by ACL).
    try {
        const r = await client.listTools();
        result("list_tools", "ok", "tools=" + (r.tools || []).map(t => t.name).join(","));
    } catch (e) {
        result("list_tools", "fail", e.message || String(e));
    }

    await client.close();
    result("close", "ok", "closed");
}

main().catch(e => { console.error("FATAL:" + (e.message || String(e))); process.exit(1); });
`

// TestSDKE2E_RealClientRequests verifies the MCP ACL filter against a real
// MCP SDK client (TypeScript @modelcontextprotocol/sdk). The test starts a
// minimal MCP HTTP server that wraps the filter, then drives the real SDK
// client through allowed and denied tool calls.
//
// Requires Node.js and npm on PATH. The test installs the SDK into a temp
// directory at runtime so it does not pollute the project.
func TestSDKE2E_RealClientRequests(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not found on PATH; skipping MCP SDK E2E test")
	}
	if _, err := exec.LookPath("npm"); err != nil {
		t.Skip("npm not found on PATH; skipping MCP SDK E2E test")
	}

	// Start the filter-wrapped MCP server.
	server := startFilterServer(t, sdkServerConfig(), "2025-11-25")
	defer server.Close()

	// Create a temp directory for the TypeScript project.
	tmpDir := t.TempDir()

	// Write package.json.
	pkgJSON := `{
  "name": "mcp-e2e-test",
  "version": "1.0.0",
  "type": "module",
  "dependencies": {
    "@modelcontextprotocol/sdk": "latest"
  }
}`
	if err := os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(pkgJSON), 0644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}

	// Write the TypeScript client script.
	scriptPath := filepath.Join(tmpDir, "client.ts")
	if err := os.WriteFile(scriptPath, []byte(tsClientScript), 0644); err != nil {
		t.Fatalf("write client.ts: %v", err)
	}

	// Install the MCP SDK.
	t.Log("Installing @modelcontextprotocol/sdk...")
	install := exec.Command("npm", "install", "--silent", "--no-progress")
	install.Dir = tmpDir
	install.Stdout = io.Discard
	install.Stderr = &strings.Builder{}
	if err := install.Run(); err != nil {
		t.Skipf("npm install failed (%v); cannot run E2E test without the SDK", err)
	}

	// Run the TypeScript client.
	t.Log("Running MCP SDK client against filter server at", server.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	run := exec.CommandContext(ctx, "npx", "--yes", "tsx", scriptPath)
	run.Dir = tmpDir
	run.Env = append(os.Environ(), "MCP_SERVER_URL="+server.URL+"/mcp")
	var stdout, stderr bytes.Buffer
	run.Stdout = &stdout
	run.Stderr = &stderr
	if err := run.Run(); err != nil {
		t.Fatalf("tsx failed: %v\nstderr: %s", err, stderr.String())
	}

	// Parse the results.
	output := stdout.String()
	t.Log("Client output:\n" + output)

	type outcome struct {
		name   string
		status string
		detail string
	}
	var outcomes []outcome
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "RESULT:") {
			continue
		}
		parts := strings.SplitN(strings.TrimPrefix(line, "RESULT:"), ":", 3)
		if len(parts) != 3 {
			continue
		}
		outcomes = append(outcomes, outcome{parts[0], parts[1], parts[2]})
	}

	if len(outcomes) == 0 {
		t.Fatalf("no RESULT lines in client output:\n%s", output)
	}

	// Verify outcomes.
	expect := map[string]string{
		"connect":      "ok",
		"allowed-tool": "ok",
		"read_file":    "ok",
		"evil":         "blocked",
		"delete_file":  "blocked",
		"list_tools":   "ok",
		"close":        "ok",
	}

	for _, o := range outcomes {
		want, ok := expect[o.name]
		if !ok {
			t.Logf("unexpected result: %s=%s (%s)", o.name, o.status, o.detail)
			continue
		}
		if o.status != want {
			t.Errorf("%-15s status = %q, want %q (detail: %s)", o.name, o.status, want, o.detail)
		} else {
			t.Logf("✓ %-15s %s (%s)", o.name, o.status, o.detail)
		}
	}
}

// goClientSource is the Go MCP SDK client program. It uses
// github.com/modelcontextprotocol/go-sdk (v1.7.0), which defaults to protocol
// version 2026-07-28 (the GA version). This means the client sends the
// mandatory Mcp-Method and Mcp-Name headers on every request, exercising the
// filter's GA fast path (header-based allow/deny before body buffering).
const goClientSource = `package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	url := os.Getenv("MCP_SERVER_URL")
	transport := &mcp.StreamableClientTransport{
		Endpoint:             url,
		DisableStandaloneSSE: true,
	}
	client := mcp.NewClient(
		&mcp.Implementation{Name: "go-e2e-client", Version: "1.0"},
		nil,
	)

	ctx := context.Background()
	cs, err := client.Connect(ctx, transport, nil)
	if err != nil {
		log.Fatalf("RESULT:connect:fail:%v", err)
	}
	fmt.Println("RESULT:connect:ok:connected")

	// Call an allowed tool (should succeed via GA fast path).
	_, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "allowed-tool"})
	if err != nil {
		fmt.Printf("RESULT:allowed-tool:fail:%v\n", err)
	} else {
		fmt.Println("RESULT:allowed-tool:ok:call succeeded")
	}

	// Call another allowed tool.
	_, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "read_file"})
	if err != nil {
		fmt.Printf("RESULT:read_file:fail:%v\n", err)
	} else {
		fmt.Println("RESULT:read_file:ok:call succeeded")
	}

	// Call a denied tool (should be blocked by header fast-path deny).
	_, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "evil"})
	if err != nil {
		fmt.Printf("RESULT:evil:blocked:%v\n", err)
	} else {
		fmt.Println("RESULT:evil:unexpected_ok:denied tool was not blocked")
	}

	// Call another denied tool.
	_, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "delete_file"})
	if err != nil {
		fmt.Printf("RESULT:delete_file:blocked:%v\n", err)
	} else {
		fmt.Println("RESULT:delete_file:unexpected_ok:denied tool was not blocked")
	}

	cs.Close()
	fmt.Println("RESULT:close:ok:closed")
}
`

// TestSDKE2E_GAVersion_GoSDK verifies the filter against the real Go MCP SDK
// (github.com/modelcontextprotocol/go-sdk v1.7.0) using protocol version
// 2026-07-28 (GA). The Go SDK defaults to the GA version and sends the
// mandatory Mcp-Method and Mcp-Name headers, exercising the filter's
// header-based fast path:
//   - Non-governed methods (server/discover) pass without body buffering.
//   - Denied tools/call are blocked from headers alone (Stop).
//   - Allowed tools/call pass after header/body consistency verification.
//
// Requires Go (already available since this is a Go test) and network access
// to download the SDK if not in the module cache.
func TestSDKE2E_GAVersion_GoSDK(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not found on PATH; skipping Go SDK E2E test")
	}

	// Start the filter-wrapped MCP server with GA protocol version.
	server := startFilterServer(t, sdkServerConfig(), "2026-07-28")
	defer server.Close()

	// Create a temp Go module for the client program.
	tmpDir := t.TempDir()

	// Write go.mod.
	goMod := `module mcp-go-e2e

go 1.23.0

require github.com/modelcontextprotocol/go-sdk v1.7.0
`
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goMod), 0644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	// Write the client program.
	if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte(goClientSource), 0644); err != nil {
		t.Fatalf("write main.go: %v", err)
	}

	// Download dependencies.
	t.Log("Running go mod tidy to download Go MCP SDK...")
	tidy := exec.Command("go", "mod", "tidy")
	tidy.Dir = tmpDir
	var tidyStderr bytes.Buffer
	tidy.Stderr = &tidyStderr
	if err := tidy.Run(); err != nil {
		t.Skipf("go mod tidy failed (%v); cannot run Go SDK E2E test.\nstderr: %s", err, tidyStderr.String())
	}

	// Run the Go MCP SDK client.
	t.Log("Running Go MCP SDK client (GA 2026-07-28) against filter server at", server.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	run := exec.CommandContext(ctx, "go", "run", ".")
	run.Dir = tmpDir
	run.Env = append(os.Environ(), "MCP_SERVER_URL="+server.URL+"/mcp")
	var stdout, stderr bytes.Buffer
	run.Stdout = &stdout
	run.Stderr = &stderr
	if err := run.Run(); err != nil {
		t.Fatalf("go run failed: %v\nstderr: %s", err, stderr.String())
	}

	// Parse the results.
	output := stdout.String()
	t.Log("Go SDK client output:\n" + output)

	type outcome struct {
		name   string
		status string
		detail string
	}
	var outcomes []outcome
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "RESULT:") {
			continue
		}
		parts := strings.SplitN(strings.TrimPrefix(line, "RESULT:"), ":", 3)
		if len(parts) != 3 {
			continue
		}
		outcomes = append(outcomes, outcome{parts[0], parts[1], parts[2]})
	}

	if len(outcomes) == 0 {
		t.Fatalf("no RESULT lines in Go SDK client output:\n%s", output)
	}

	// Verify outcomes — same expectations as the TypeScript test.
	expect := map[string]string{
		"connect":      "ok",
		"allowed-tool": "ok",
		"read_file":    "ok",
		"evil":         "blocked",
		"delete_file":  "blocked",
		"close":        "ok",
	}

	for _, o := range outcomes {
		want, ok := expect[o.name]
		if !ok {
			t.Logf("unexpected result: %s=%s (%s)", o.name, o.status, o.detail)
			continue
		}
		if o.status != want {
			t.Errorf("%-15s status = %q, want %q (detail: %s)", o.name, o.status, want, o.detail)
		} else {
			t.Logf("✓ %-15s %s (%s)", o.name, o.status, o.detail)
		}
	}
}
