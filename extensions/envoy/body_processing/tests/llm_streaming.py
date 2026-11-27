#!/usr/bin/env python3
# Copyright 2026 The Kruise Authors
# SPDX-License-Identifier: Apache-2.0
"""A fixture-backed LLM upstream and a streaming HTTP client for the Envoy E2E."""

import argparse
import http.client
import http.server
import json
import pathlib
import sys
import threading
import uuid


FIXTURES = pathlib.Path(__file__).parent.parent / "testdata"
HOST = "stream.llm.test"
CHAT = "/v1/chat/completions"
RESPONSES = "/v1/responses"
ANTHROPIC = "/v1/messages"
CHAT_ALTERNATIVES = [(1, "alternate"), (0, "primary")]
DEFAULT_CASE = {CHAT: "chat-mixed", RESPONSES: "responses-revised", ANTHROPIC: "anthropic-tools"}
CASES = {
    "chat-mixed": (CHAT, "openai.sse"),
    "chat-text": (CHAT, "chat-obfuscation.sse"),
    "chat-alternatives": (CHAT, None),
    "chat-tool-only": (CHAT, "chat-empty-content.sse"),
    "chat-large-frame": (CHAT, "openai.sse"),
    "chat-incomplete": (CHAT, "openai.sse"),
    "chat-invalid-json": (CHAT, "openai.sse"),
    "responses-revised": (RESPONSES, "responses.sse"),
    "responses-search": (RESPONSES, "responses.sse"),
    "anthropic-tools": (ANTHROPIC, "anthropic.sse"),
    "anthropic-mcp": (ANTHROPIC, "anthropic.sse"),
}


def request_body(path):
    request = {"model": "test", "stream": True}
    if path == RESPONSES:
        request["input"] = "Hello"
    else:
        request["messages"] = [{"role": "user", "content": "Hello"}]
        if path == CHAT:
            request["stream_options"] = {"include_usage": True}
        else:
            request["max_tokens"] = 128
    return json.dumps(request).encode()


def response_body(case):
    if case == "chat-alternatives":
        choices = [{"index": index, "delta": {"role": "assistant", "content": text}, "finish_reason": "stop"}
                   for index, text in CHAT_ALTERNATIVES]
        return ("data: " + json.dumps({"model": "test", "choices": choices}) + "\n\ndata: [DONE]\n\n").encode()
    data = (FIXTURES / CASES[case][1]).read_bytes()
    if case == "chat-text":
        return data.replace(b'"Hello"', br'"line\n\"quoted\" \ud83d\ude42"')
    if case == "responses-revised":
        early, terminal = data.split(b"event: response.completed\n")
        return early + b"event: response.completed\n" + terminal.replace("你好".encode(), "最终".encode())
    if case == "responses-search":
        kind = "response.web_search_call.in_progress"
        progress = json.dumps({"type": kind, "item_id": "search_1", "output_index": 3, "sequence_number": 14})
        return data.replace(b"event: response.completed\n", f"event: {kind}\ndata: {progress}\n\nevent: response.completed\n".encode()).replace(
            b'"object":"response"', b'"object":"response","instructions":[{"role":"developer","content":"Use tools"}]')
    if case == "anthropic-mcp":
        return data.replace(b'"type":"tool_use"', b'"type":"mcp_tool_use","server_name":"clock"').replace(
            b'"stop_sequence":null}', b'"stop_sequence":null,"container":null,"stop_details":null}')
    if case == "chat-large-frame":
        return data.replace("好".encode(), b"x" * (80 << 10))
    if case == "chat-incomplete":
        return data.removesuffix(b"data: [DONE]\n\n")
    if case == "chat-invalid-json":
        return data.replace(b"data: [DONE]", b"data: {broken}\n\ndata: [DONE]")
    return data


class StreamHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    pending = {}

    def do_GET(self):
        # The client releases its own stream over a second connection.
        gate = self.pending.get(self.path)
        if gate is None:
            self.send_error(404)
            return
        gate.set()
        self.send_response(204)
        self.end_headers()

    def do_POST(self):
        case = self.headers.get("X-LLM-Case", DEFAULT_CASE.get(self.path))
        if case not in CASES or self.path != CASES[case][0]:
            self.send_error(404, "Unknown replay case or endpoint")
            return
        body = self.rfile.read(int(self.headers["Content-Length"]))
        try:
            request = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.send_error(400, "Expected a JSON request")
            return
        prompt = "input" if self.path == RESPONSES else "messages"
        if not isinstance(request, dict) or request.get("stream") is not True or prompt not in request:
            self.send_error(400, f"Expected stream=true and {prompt}")
            return
        wire = response_body(case)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        offset = 0
        token = self.headers.get("X-LLM-Gate")
        if case == "chat-mixed" and token:
            path = f"/_fixture/continue/{token}"
            gate = self.pending[path] = threading.Event()
            try:
                # Send one complete event and one byte of 好 in the next event.
                offset = wire.index("好".encode()) + 1
                self.write_chunk(wire[:offset])
                if not gate.wait(10):
                    raise TimeoutError("Client did not receive the SSE prefix before HTTP end")
            finally:
                del self.pending[path]
        for start in range(offset, len(wire), 97):
            self.write_chunk(wire[start:start + 97])
        self.write_chunk(b"")

    def write_chunk(self, chunk):
        self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
        self.wfile.flush()


def exercise(gateway):
    connection = http.client.HTTPConnection(gateway, timeout=15)
    try:
        for case, (path, _) in CASES.items():
            headers = {"Host": HOST, "Content-Type": "application/json", "X-LLM-Case": case}
            if case == "responses-search":
                headers["Host"] = HOST.upper() + ".:443"
            if case == "chat-mixed":
                headers["X-LLM-Gate"] = uuid.uuid4().hex
            if case == "chat-large-frame":
                headers["X-Agent-Note"] = "n" * 2048
            connection.request("POST", path, request_body(path), headers)
            response = connection.getresponse()
            assert response.status == 200, (case, response.status, response.read())
            assert response.getheader("Content-Type") == "text/event-stream", (case, response.getheaders())
            expected = response_body(case)
            if case == "chat-mixed":
                end = expected.index("好".encode()) + 1
                assert response.read(end) == expected[:end], case
                control = http.client.HTTPConnection(gateway, timeout=10)
                try:
                    control.request("GET", "/_fixture/continue/" + headers["X-LLM-Gate"], headers={"Host": HOST})
                    assert control.getresponse().status == 204, case
                finally:
                    control.close()
                expected = expected[end:]
            assert response.read() == expected, case
    finally:
        connection.close()


def check_audits(lines):
    records = {case: [] for case in CASES}
    for line in lines:
        assert line.endswith(b"\n"), line
        row = json.loads(line)
        if row.get("chain") == "streaming":
            records[row["case"]].append(row)

    calls = [{"kind": "call", "id": "call_1", "name": "lookup"},
             {"kind": "call", "id": "call_2", "name": "clock"}]
    expected = {
        "chat-mixed": ({"answer": "你好", "model": "test-model", "tokens": 8}, {"tokens": 8, "calls": calls}),
        "chat-alternatives": ({"answer": "primary", "model": "test"}, {}),
        "chat-text": ({"answer": 'line\n"quoted" 🙂 world', "model": "test"}, {}),
        "chat-tool-only": ({"answer": "", "model": "claude-opus-4-8", "tokens": 20}, {"tokens": 20, "calls": [
            {"kind": "call", "id": "toolu_empty_content", "name": "Bash"}]}),
        "chat-large-frame": ({"answer": "你" + "x" * 765, "model": "test-model", "tokens": 8,
                              "note": "n" * 128, "answerStatus": "truncated"}, {"tokens": 8, "calls": calls}),
        "chat-incomplete": ({"answerStatus": "incomplete_stream", "model": "test-model", "answer": "你好", "tokens": 8},
                            {"usageStatus": "incomplete_stream", "tokens": 8, "calls": calls}),
        "chat-invalid-json": ({"answerStatus": "invalid_json"}, {"usageStatus": "invalid_json"}),
        "responses-revised": ({"answer": "最终no", "model": "test-responses", "tokens": 8}, {"tokens": 8, "calls": calls[:1]}),
        "responses-search": ({"answer": "你好no", "model": "test-responses", "tokens": 8}, {"tokens": 8, "calls": calls[:1]}),
        "anthropic-tools": ({"answer": "你好", "model": "test-claude", "tokens": 12}, {"tokens": 12, "calls": [
            {"kind": "call", "id": "tool_1", "name": "lookup"}]}),
    }
    expected["anthropic-mcp"] = expected["anthropic-tools"]
    for case, pair in records.items():
        assert len(pair) == 2, (case, pair)
        answer, usage = pair
        common = {"chain": "streaming", "case": case, "id": answer["id"], "bytes": len(response_body(case))}
        assert common["id"], case
        wanted_answer, wanted_usage = expected[case]
        assert answer == {**common, "answerStatus": "complete", **wanted_answer}, (case, answer)
        assert usage == {**common, "usageStatus": "complete", **wanted_usage}, (case, usage)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    server = commands.add_parser("serve")
    server.add_argument("--listen", default="127.0.0.1")
    server.add_argument("--port", type=int, default=9000)
    client = commands.add_parser("client")
    client.add_argument("--gateway", default="127.0.0.1:8080", help="HTTP gateway host:port")
    commands.add_parser("check-logs", help="verify one client's run from Envoy audit JSONL on stdin")
    args = parser.parse_args()
    if args.command == "serve":
        with http.server.ThreadingHTTPServer((args.listen, args.port), StreamHandler) as server:
            server.serve_forever()
    elif args.command == "client":
        exercise(args.gateway)
        print(f"Verified {len(CASES)} streaming responses")
    else:
        check_audits(sys.stdin.buffer)
        print(f"Verified {2 * len(CASES)} audit records")
