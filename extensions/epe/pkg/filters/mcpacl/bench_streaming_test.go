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
package mcpacl

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Streaming-mode correctness and performance tests.
//
// In STREAMED mode Envoy delivers the body in multiple HttpBody chunks and
// ext_proc must respond to each chunk. The optimization under test parses
// chunks incrementally and decides as soon as "method" and "params.name" are
// found (typically in the first few hundred bytes), without waiting for the
// entire body. Part 1 checks decision correctness across chunk sizes and
// split points; part 2 measures latency against the buffered path.

// StreamingParser incrementally feeds body chunks and extracts "method" and
// "params.name" from a JSON-RPC request. Once both are found (or the entire
// body is consumed), it reports the decision can be made.
type StreamingParser struct {
	buf      bytes.Buffer
	method   string
	toolName string
	decided  bool
}

// Feed adds a chunk to the parser and attempts to extract method/toolName.
// Returns true when enough information is available to make a decision.
func (sp *StreamingParser) Feed(chunk []byte) bool {
	if sp.decided {
		return true
	}
	sp.buf.Write(chunk)

	data := sp.buf.Bytes()

	if isBatchBody(data) {
		sp.decided = true
		return true
	}

	method, toolName := streamingParsePartial(data)
	if method != "" {
		sp.method = method
		// Non-governed methods can decide immediately
		if !governedMethods[method] {
			sp.decided = true
			return true
		}
		// For governed methods, we need toolName
		if toolName != "" {
			sp.toolName = toolName
			sp.decided = true
			return true
		}
	}
	return false
}

// Result returns the parsed method and toolName.
func (sp *StreamingParser) Result() (method, toolName string) {
	return sp.method, sp.toolName
}

// FeedEOS signals end-of-stream. If we haven't decided yet, force a decision
// with whatever we have.
func (sp *StreamingParser) FeedEOS(chunk []byte) (method, toolName string) {
	if len(chunk) > 0 {
		sp.buf.Write(chunk)
	}
	if !sp.decided {
		data := sp.buf.Bytes()
		sp.method, sp.toolName = parseJSONRPCBody(data)
		sp.decided = true
	}
	return sp.method, sp.toolName
}

// IsBatch reports whether the body is a JSON-RPC batch (array).
func (sp *StreamingParser) IsBatch() bool {
	return isBatchBody(sp.buf.Bytes())
}

func splitIntoChunks(body []byte, chunkSize int) [][]byte {
	var chunks [][]byte
	for i := 0; i < len(body); i += chunkSize {
		end := i + chunkSize
		if end > len(body) {
			end = len(body)
		}
		chunks = append(chunks, body[i:end])
	}
	return chunks
}

func TestStreaming_Correctness_SingleChunk(t *testing.T) {
	tests := []struct {
		name       string
		body       []byte
		wantMethod string
		wantTool   string
	}{
		{"tools/call with tool", jsonRPCBody("tools/call", "read_file"), "tools/call", "read_file"},
		{"tools/list", jsonRPCBody("tools/list", ""), "tools/list", ""},
		{"initialize", jsonRPCBody("initialize", ""), "initialize", ""},
		{"empty body", nil, "", ""},
		{"malformed json", []byte("{bad json"), "", ""},
		{"no method field", []byte(`{"id":1,"jsonrpc":"2.0"}`), "", ""},
		{"large body 100KB", buildLargeToolsCallBody("exec_cmd", 100*1024), "tools/call", "exec_cmd"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sp := &StreamingParser{}
			sp.FeedEOS(tc.body)
			m, tn := sp.Result()
			if m != tc.wantMethod {
				t.Errorf("method mismatch: want %q, got %q", tc.wantMethod, m)
			}
			if tn != tc.wantTool {
				t.Errorf("toolName mismatch: want %q, got %q", tc.wantTool, tn)
			}
		})
	}
}

func TestStreaming_Correctness_MultipleChunks(t *testing.T) {
	// Body with method and tool at the beginning, large arguments at the end
	body := buildLargeToolsCallBody("read_file", 50*1024) // 50KB total

	chunkSizes := []int{1, 10, 50, 100, 256, 512, 1024, 4096, 8192, 16384}

	for _, cs := range chunkSizes {
		t.Run(fmt.Sprintf("chunk_%dB", cs), func(t *testing.T) {
			chunks := splitIntoChunks(body, cs)
			sp := &StreamingParser{}

			var decidedAtChunk int
			for i, chunk := range chunks {
				isLast := i == len(chunks)-1
				if isLast {
					sp.FeedEOS(chunk)
				} else {
					if sp.Feed(chunk) && decidedAtChunk == 0 {
						decidedAtChunk = i + 1
					}
				}
			}

			m, tn := sp.Result()
			if m != "tools/call" {
				t.Errorf("method mismatch with chunk size %d: got %q", cs, m)
			}
			if tn != "read_file" {
				t.Errorf("toolName mismatch with chunk size %d: got %q", cs, tn)
			}

			if decidedAtChunk > 0 {
				bytesRead := decidedAtChunk * cs
				t.Logf("Decided after chunk %d (%d bytes of %d total = %.1f%%)",
					decidedAtChunk, bytesRead, len(body), float64(bytesRead)/float64(len(body))*100)
			}
		})
	}
}

func TestStreaming_Correctness_FieldOrderVariations(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantMethod string
		wantTool   string
	}{
		{
			"standard order: method before params",
			`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"tool_a","arguments":{}}}`,
			"tools/call", "tool_a",
		},
		{
			"params before method",
			`{"jsonrpc":"2.0","id":1,"params":{"name":"tool_b","arguments":{}},"method":"tools/call"}`,
			"tools/call", "tool_b",
		},
		{
			"name after arguments in params",
			`{"jsonrpc":"2.0","method":"tools/call","params":{"arguments":{"x":1},"name":"tool_c"}}`,
			"tools/call", "tool_c",
		},
		{
			"extra fields everywhere",
			`{"extra":"x","jsonrpc":"2.0","more":123,"method":"tools/call","params":{"extra":"y","name":"tool_d","arguments":{"big":"data"}}}`,
			"tools/call", "tool_d",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Test with full body
			sp := &StreamingParser{}
			sp.FeedEOS([]byte(tc.body))
			m, tn := sp.Result()
			if m != tc.wantMethod {
				t.Errorf("method mismatch: want %q, got %q", tc.wantMethod, m)
			}
			if tn != tc.wantTool {
				t.Errorf("toolName mismatch: want %q, got %q", tc.wantTool, tn)
			}

			// Test with tiny chunks (byte-by-byte would be too slow, use 10-byte chunks)
			sp2 := &StreamingParser{}
			chunks := splitIntoChunks([]byte(tc.body), 10)
			for i, chunk := range chunks {
				if i == len(chunks)-1 {
					sp2.FeedEOS(chunk)
				} else {
					sp2.Feed(chunk)
				}
			}
			m2, tn2 := sp2.Result()
			if m2 != tc.wantMethod {
				t.Errorf("chunked method mismatch: want %q, got %q", tc.wantMethod, m2)
			}
			if tn2 != tc.wantTool {
				t.Errorf("chunked toolName mismatch: want %q, got %q", tc.wantTool, tn2)
			}
		})
	}
}

func TestStreaming_Correctness_EarlyTermination(t *testing.T) {
	// Non-governed methods should be decidable from the first chunk
	// even before params arrive
	body := []byte(`{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}`)

	sp := &StreamingParser{}
	// Feed just enough to capture "method":"initialize"
	// The method key starts around byte 15, value ends around byte 35
	decided := sp.Feed(body[:60])
	if !decided {
		t.Fatalf("non-governed method should be decided in first chunk")
	}
	m, _ := sp.Result()
	if m != "initialize" {
		t.Errorf("method: want initialize, got %q", m)
	}
}

func TestStreaming_Correctness_BatchBody(t *testing.T) {
	batch := []byte(`[{"jsonrpc":"2.0","method":"tools/call","params":{"name":"evil"},"id":1}]`)

	// The two sub-cases differ only in how much of the batch is fed: the
	// leading '[' alone must be enough to classify the body as a batch.
	tests := []struct {
		name string
		feed []byte
	}{
		{name: "batch detected in single chunk", feed: batch},
		{name: "batch detected from first byte", feed: batch[:1]}, // just '['
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sp := &StreamingParser{}
			if !sp.Feed(tc.feed) {
				t.Fatalf("batch should be detected immediately")
			}
			if !sp.IsBatch() {
				t.Errorf("IsBatch() = false, want true")
			}
		})
	}
}

// TestStreaming_Correctness_ChunkBoundaryOnKey tests that the parser handles
// JSON keys split across chunk boundaries. This is the hardest case for
// streaming: {"method":"tools... | /call",...}
func TestStreaming_Correctness_ChunkBoundaryOnKey(t *testing.T) {
	body := jsonRPCBody("tools/call", "read_file")

	methodIdx := bytes.Index(body, []byte(`"method"`))
	if methodIdx <= 0 {
		t.Fatalf("body must contain a \"method\" key past offset 0, got index %d", methodIdx)
	}

	splitPoints := []int{
		methodIdx,      // split right before "method" key
		methodIdx + 4,  // split in the middle of "method" key
		methodIdx + 8,  // split between key and colon
		methodIdx + 10, // split between colon and value
		methodIdx + 15, // split in the middle of value "tools/call"
	}

	for _, sp := range splitPoints {
		if sp >= len(body) {
			continue
		}
		t.Run(fmt.Sprintf("split_at_%d", sp), func(t *testing.T) {
			parser := &StreamingParser{}
			parser.Feed(body[:sp])
			parser.FeedEOS(body[sp:])
			m, tn := parser.Result()
			if m != "tools/call" {
				t.Errorf("split at %d: method want tools/call, got %q", sp, m)
			}
			if tn != "read_file" {
				t.Errorf("split at %d: toolName want read_file, got %q", sp, tn)
			}
		})
	}
}

// TestStreaming_Correctness_FullPluginDecision verifies that streaming-parser
// output fed into evaluate() produces identical decisions to the buffered
// path.
func TestStreaming_Correctness_FullPluginDecision(t *testing.T) {
	whitelistPolicy := &Config{
		DefaultAction: "deny",
		Rules: []RuleEntry{
			{Method: "tools/call", ToolNames: []string{"read_file", "write_file"}, Action: "allow"},
		},
	}
	blacklistPolicy := &Config{
		DefaultAction: "allow",
		Rules: []RuleEntry{
			{Method: "tools/call", ToolNames: []string{"exec_command"}, Action: "deny"},
		},
	}
	plugin := newLegacyPlugin()

	tests := []struct {
		name       string
		body       []byte
		policy     *Config
		wantAction legacyAction
	}{
		{"whitelist allow", buildLargeToolsCallBody("read_file", 10*1024), whitelistPolicy, legacyContinue},
		{"whitelist deny", buildLargeToolsCallBody("exec_command", 10*1024), whitelistPolicy, legacyImmediate},
		{"blacklist allow", buildLargeToolsCallBody("read_file", 10*1024), blacklistPolicy, legacyContinue},
		{"blacklist deny", buildLargeToolsCallBody("exec_command", 10*1024), blacklistPolicy, legacyImmediate},
		{"non-governed passthrough", func() []byte {
			b := buildLargeToolsCallBody("", 10*1024)
			return bytes.Replace(b, []byte(`"tools/call"`), []byte(`"initialize"`), 1)
		}(), whitelistPolicy, legacyContinue},
	}

	chunkSizes := []int{64, 256, 1024, 4096}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Reference result from the buffered path.
			rctx := makeRctx("application/json")
			rctx.RequestBody = tc.body
			rule := makeRule(tc.policy)
			refResult, err := plugin.Finalize(context.Background(), rctx, nil, rule)
			if err != nil {
				t.Fatalf("Finalize: %v", err)
			}
			if refResult.Action != tc.wantAction {
				t.Errorf("reference (buffered) result mismatch: want %v, got %v", tc.wantAction, refResult.Action)
			}

			// Verify streaming produces same result at various chunk sizes
			for _, cs := range chunkSizes {
				t.Run(fmt.Sprintf("chunk_%dB", cs), func(t *testing.T) {
					sp := &StreamingParser{}
					chunks := splitIntoChunks(tc.body, cs)
					for i, chunk := range chunks {
						if i == len(chunks)-1 {
							sp.FeedEOS(chunk)
						} else {
							sp.Feed(chunk)
						}
					}
					method, toolName := sp.Result()

					// Reproduce the same decision logic as Finalize
					var streamAction legacyAction
					if sp.IsBatch() {
						if tc.policy.DefaultAction == "deny" {
							streamAction = legacyImmediate
						} else {
							streamAction = legacyContinue
						}
					} else if !governedMethods[method] {
						streamAction = legacyContinue
					} else {
						decision := evaluate(configOf(tc.policy), method, toolName)
						if decision == "deny" {
							streamAction = legacyImmediate
						} else {
							streamAction = legacyContinue
						}
					}

					if streamAction != tc.wantAction {
						t.Errorf("streaming (chunk=%d) decision differs from buffered: want %v, got %v",
							cs, tc.wantAction, streamAction)
					}
				})
			}
		})
	}
}

// buildLargeToolsCallBody constructs a realistic MCP JSON-RPC body with
// deterministic field ordering matching real MCP SDK output: method and
// params.name appear early, arguments (the large payload) comes last.
// This mirrors the actual serialization from MCP TypeScript/Python SDKs.
func buildLargeToolsCallBody(toolName string, argumentsSize int) []byte {
	padding := strings.Repeat("x", argumentsSize)
	// Use ordered struct to guarantee field order (like real MCP SDKs)
	type args struct {
		Content string `json:"content"`
	}
	type params struct {
		Name      string `json:"name"`
		Arguments args   `json:"arguments"`
	}
	type request struct {
		JSONRPC string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Method  string `json:"method"`
		Params  params `json:"params"`
	}
	b, _ := json.Marshal(request{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  params{Name: toolName, Arguments: args{Content: padding}},
	})
	return b
}

var benchPolicy = &Config{
	DefaultAction: "deny",
	Rules: []RuleEntry{
		{Method: "tools/call", ToolNames: []string{"read_file", "write_file"}, Action: "allow"},
	},
}

var bodySizes = []struct {
	name string
	size int
}{
	{"100B", 0},
	{"1KB", 1024},
	{"10KB", 10 * 1024},
	{"100KB", 100 * 1024},
	{"1MB", 1024 * 1024},
}

// Approach A: buffered — the full body arrives as one piece and
// json.Unmarshal extracts the fields.
func bufferedDecide(body []byte, policy *Config) string {
	if isBatchBody(body) {
		return policy.DefaultAction
	}
	method, toolName := parseJSONRPCBody(body)
	if !governedMethods[method] {
		return "allow"
	}
	return evaluate(configOf(policy), method, toolName)
}

// Approach B: streamed — the body arrives in chunks and StreamingParser
// decides as early as possible, parsing only the minimal prefix needed for
// method and params.name.
func streamedDecide(body []byte, chunkSize int, policy *Config) (decision string, bytesProcessed int) {
	sp := &StreamingParser{}
	chunks := splitIntoChunks(body, chunkSize)

	for i, chunk := range chunks {
		isLast := i == len(chunks)-1
		if isLast {
			sp.FeedEOS(chunk)
		} else {
			if sp.Feed(chunk) {
				// Decision made early! Remaining chunks don't need parsing.
				bytesProcessed = (i + 1) * chunkSize
				break
			}
		}
		if sp.decided {
			bytesProcessed = (i + 1) * chunkSize
			break
		}
	}
	if bytesProcessed == 0 {
		bytesProcessed = len(body)
	}

	if sp.IsBatch() {
		return policy.DefaultAction, bytesProcessed
	}
	method, toolName := sp.Result()
	if !governedMethods[method] {
		return "allow", bytesProcessed
	}
	return evaluate(configOf(policy), method, toolName), bytesProcessed
}

// BenchmarkBuffered measures the buffered approach: full-body parse.
func BenchmarkBuffered(b *testing.B) {
	for _, bs := range bodySizes {
		body := buildLargeToolsCallBody("read_file", bs.size)
		b.Run(bs.name, func(b *testing.B) {
			b.SetBytes(int64(len(body)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				bufferedDecide(body, benchPolicy)
			}
		})
	}
}

// BenchmarkStreamed_4KB measures STREAMED approach with 4KB chunks (typical
// Envoy chunk size for HTTP/1.1 with default buffer settings).
func BenchmarkStreamed_4KB(b *testing.B) {
	for _, bs := range bodySizes {
		body := buildLargeToolsCallBody("read_file", bs.size)
		b.Run(bs.name, func(b *testing.B) {
			b.SetBytes(int64(len(body)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				streamedDecide(body, 4096, benchPolicy)
			}
		})
	}
}

// BenchmarkStreamed_16KB measures STREAMED approach with 16KB chunks (HTTP/2
// default flow control window is 64KB, typical chunk ~16KB).
func BenchmarkStreamed_16KB(b *testing.B) {
	for _, bs := range bodySizes {
		body := buildLargeToolsCallBody("read_file", bs.size)
		b.Run(bs.name, func(b *testing.B) {
			b.SetBytes(int64(len(body)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				streamedDecide(body, 16384, benchPolicy)
			}
		})
	}
}

// BenchmarkBuffered_FullPlugin benchmarks the buffered decision path through
// Finalize.
func BenchmarkBuffered_FullPlugin(b *testing.B) {
	p := newLegacyPlugin()
	rule := makeRule(benchPolicy)

	for _, bs := range bodySizes {
		body := buildLargeToolsCallBody("read_file", bs.size)
		b.Run(bs.name, func(b *testing.B) {
			b.SetBytes(int64(len(body)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				rctx := makeRctx("application/json")
				rctx.RequestBody = body
				p.Finalize(context.Background(), rctx, nil, rule)
			}
		})
	}
}

// BenchmarkStreamed_FullDecision benchmarks streaming parse → evaluate, which
// represents the critical path in STREAMED mode: only the first chunk is
// parsed (simulating that ext_proc makes the decision on the first chunk
// without waiting for the rest).
func BenchmarkStreamed_FullDecision(b *testing.B) {
	for _, bs := range bodySizes {
		body := buildLargeToolsCallBody("read_file", bs.size)
		b.Run(bs.name, func(b *testing.B) {
			b.SetBytes(int64(len(body)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				// Simulate: ext_proc only sees the first 4KB chunk for
				// decision; the rest flows through with CONTINUE responses.
				sp := &StreamingParser{}
				if len(body) <= 4096 {
					sp.FeedEOS(body)
				} else {
					if !sp.Feed(body[:4096]) {
						sp.FeedEOS(body[4096:8192]) // second chunk at most
					}
				}
				method, toolName := sp.Result()
				if governedMethods[method] {
					evaluate(configOf(benchPolicy), method, toolName)
				}
			}
		})
	}
}

// BenchmarkStreamed_NonGoverned benchmarks the fast path for non-governed
// methods (initialize, tools/list, etc.). In STREAMED mode, these are
// detected and passed through after parsing just the "method" field.
func BenchmarkStreamed_NonGoverned(b *testing.B) {
	for _, bs := range bodySizes {
		body := buildLargeToolsCallBody("", bs.size)
		body = bytes.Replace(body, []byte(`"tools/call"`), []byte(`"initialize"`), 1)
		b.Run(bs.name, func(b *testing.B) {
			b.SetBytes(int64(len(body)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sp := &StreamingParser{}
				sp.Feed(body[:min(4096, len(body))])
				sp.Result()
			}
		})
	}
}

// TestPerformanceReport prints a formatted comparison table.
// Run with: go test -run TestPerformanceReport -v -timeout 300s
func TestPerformanceReport(t *testing.T) {
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║      MCP ACL: BUFFERED vs STREAMED Body Processing             ║")
	fmt.Println("╠══════════════════════════════════════════════════════════════════╣")
	fmt.Println()

	fmt.Println("--- CPU Latency (decision time only, body already in memory) ---")
	fmt.Printf("%-10s │ %-14s │ %-14s │ %-14s │ %-8s\n",
		"Body Size", "Buffered", "Stream(4KB)", "Stream(16KB)", "Speedup")
	fmt.Println(strings.Repeat("─", 72))

	for _, bs := range bodySizes {
		body := buildLargeToolsCallBody("read_file", bs.size)

		rBuf := testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				bufferedDecide(body, benchPolicy)
			}
		})
		rS4 := testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				streamedDecide(body, 4096, benchPolicy)
			}
		})
		rS16 := testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				streamedDecide(body, 16384, benchPolicy)
			}
		})

		speedup := float64(rBuf.NsPerOp()) / float64(rS4.NsPerOp())
		fmt.Printf("%-10s │ %12dns │ %12dns │ %12dns │ %6.1fx\n",
			bs.name, rBuf.NsPerOp(), rS4.NsPerOp(), rS16.NsPerOp(), speedup)
	}

	fmt.Println()
	fmt.Println("--- Early Decision: bytes processed before allow/deny ---")
	fmt.Printf("%-10s │ %-14s │ %-14s │ %-10s\n",
		"Body Size", "Total Bytes", "Bytes Parsed", "Ratio")
	fmt.Println(strings.Repeat("─", 56))

	for _, bs := range bodySizes {
		body := buildLargeToolsCallBody("read_file", bs.size)
		_, bytesProcessed := streamedDecide(body, 4096, benchPolicy)
		ratio := float64(bytesProcessed) / float64(len(body)) * 100
		fmt.Printf("%-10s │ %12d │ %12d │ %7.1f%%\n",
			bs.name, len(body), bytesProcessed, ratio)
	}

	fmt.Println()
	fmt.Println("--- Real-world latency estimate (including network I/O) ---")
	fmt.Println()
	fmt.Println("  Assumption: 1Gbps network between client and Envoy")
	fmt.Println()
	fmt.Printf("  %-10s │ %-20s │ %-20s │ %-10s\n",
		"Body Size", "BUFFERED (wait all)", "STREAMED (first 4KB)", "Saved")
	fmt.Println("  " + strings.Repeat("─", 68))

	for _, bs := range bodySizes {
		body := buildLargeToolsCallBody("read_file", bs.size)
		totalBytes := len(body)
		// Network time at 1Gbps = bytes * 8 / 1e9 seconds
		networkTimeUs := float64(totalBytes) * 8 / 1e3 // microseconds at 1Gbps
		firstChunkUs := float64(min(4096, totalBytes)) * 8 / 1e3

		bufferedTotal := networkTimeUs + float64(testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				bufferedDecide(body, benchPolicy)
			}
		}).NsPerOp())/1000.0

		streamedTotal := firstChunkUs + float64(testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				streamedDecide(body, 4096, benchPolicy)
			}
		}).NsPerOp())/1000.0

		saved := bufferedTotal - streamedTotal
		fmt.Printf("  %-10s │ %16.0f µs │ %16.0f µs │ %7.0f µs\n",
			bs.name, bufferedTotal, streamedTotal, saved)
	}

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║ Conclusion:                                                     ║")
	fmt.Println("║ - Bodies < 4KB: no benefit (single chunk covers everything)     ║")
	fmt.Println("║ - Bodies 10KB+: streaming is beneficial                         ║")
	fmt.Println("║ - Bodies 100KB+: significant win (network + parse savings)      ║")
	fmt.Println("║ - The real gain is NETWORK LATENCY, not CPU parse speed:        ║")
	fmt.Println("║   ext_proc doesn't block waiting for the full body to arrive    ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
}
