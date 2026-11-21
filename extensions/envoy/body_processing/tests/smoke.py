#!/usr/bin/env python3
# Copyright 2026 The Kruise Authors
# SPDX-License-Identifier: Apache-2.0
"""Exercise the installed module and Envoy access logger in a Linux container."""

import gzip
import http.client
import http.server
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid


def address(port):
    return {"socket_address": {"address": "127.0.0.1", "port_value": port}}


def access_log():
    return {
        "name": "envoy.access_loggers.stdout",
        "filter": {"extension_filter": {
            "name": "envoy.access_loggers.extension_filters.cel",
            "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.access_loggers.filters.cel.v3.ExpressionFilter",
                "expression": "'agentio.body_processing.audit' in filter_state",
            },
        }},
        "typed_config": {
            "@type": "type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog",
            "log_format": {"text_format_source": {
                "inline_string": "%FILTER_STATE(agentio.body_processing.audit:PLAIN)%",
            }},
        },
    }


def bootstrap(port, upstream):
    common = {"chain":"%CHAIN%", "direction":"%DIRECTION%", "requestID":"%REQ(X-REQUEST-ID)%",
              "path":"%PATH%", "bytesSeen":"%BYTES_SEEN%", "decodedBytes":"%DECODED_BYTES%",
              "captureStatus":"%CAPTURE_STATUS%", "llm.protocol":"%EVENT(llm.protocol)%"}
    def audit(fields, **options):
        return {"audit": {"format": {"json": {**common, **fields}}, **options}}
    messages = {"messages":"%EVENT(llm.messages)%", "tools":"%EVENT(llm.toolDefinitions)%",
                "model":"%EVENT(llm.model)%", "gen_ai.operation.name":"%EVENT(llm.operation)%",
                "gen_ai.usage.output_tokens":"%EVENT(llm.usage.outputTokens)%"}
    question = {"llm.question":"%EVENT(llm.question)%"}
    tools = {"gen_ai.tool.definitions":"%EVENT(llm.toolDefinitions)%"}
    attributes = {
        "app.tenant.id": "%REQ(X-TENANT)%",
        "sandbox": "%FILTER_STATE(test.tenant:PLAIN)%",
        "namespace": "%DYNAMIC_METADATA(workload:namespace)%",
        "missing": "%DYNAMIC_METADATA(workload:absent)%",
        "object": "%DYNAMIC_METADATA(workload:labels)%",
    }
    settings = {
        "filterChains": [
            {"name": "custom", "matcher": {"hosts": ["*.llm.test"], "paths": ["/custom"],
                       "filterState": [{"key": "test.tenant", "values": ["green", "blue"]}]},
             "parser": {"llm": {"protocol": "openai-responses"}},
             "filters": [audit(messages | attributes, request={}, response={"maxSize":"1KiB"}, maxSize="2KiB"),
                         audit(question, request={}, maxSize="1KiB")]},
            *[{"name": name, "matcher": {"paths": ["/" + name]},
               "parser":{"llm":{"protocol":"openai-chat-completions", **options}},
               "filters":[audit(question, request={}, maxSize="2KiB"),audit(tools, request={}, maxSize="8KiB")]}
              for name, options in (("dual",{}),("dual-small",{"request":{"maxItemSize":"2KiB"}}))],
            {"name":"image","matcher":{"hosts":["image.test"],"filterState":[{"key":"test.empty"}]},
             "parser":{"llm":{"protocol":"openai-chat-completions"}},
             "filters":[audit({"messages":"%EVENT(llm.messages)%"}, request={}, maxSize="2KiB")]},
            {"name":"qa","matcher":{"hosts":["qa.test"]},"parser":{"llm":{}},
             "filters":[audit(attributes | question | {"llm.answer":"%EVENT(llm.answer)%","agentio.tool.calls":"%EVENT(llm.toolCallRefs)%"},
                    request={},response={"maxSize":"1KiB"},maxSize="2KiB")]},
            {"name": "sse-audits", "matcher": {"hosts": ["sse.test"]}, "parser": {"llm": {}},
             "filters": [
                 audit({"text": "%EVENT(llm.answer)%"}, response={"maxSize": "1KiB", "maxContentBytes": 16384}),
                 audit({"tokens": "%EVENT(llm.usage.totalTokens)%"}, response={"maxSize": "2KiB"}),
             ]},
            {"name":"standard","matcher":{"hosts":["127.0.0.1","custom.llm.test"],"paths":[*STREAMS,"/custom","/internal/messages"]},
             "parser":{"llm":{}},"filters":[audit(messages,request={},response={"maxSize":"1KiB"},maxSize="2KiB")]},
        ],
    }
    module = {
        "name": "envoy.filters.http.dynamic_modules",
        "typed_config": {
            "@type": "type.googleapis.com/envoy.extensions.filters.http.dynamic_modules.v3.DynamicModuleFilter",
            "dynamic_module_config": {"name": "envoy_agentio_contentguard"},
            "filter_name": "contentguard",
            "filter_config": {
                "@type": "type.googleapis.com/google.protobuf.StringValue",
                "value": json.dumps(settings),
            },
        },
    }
    state = {
        "name": "envoy.filters.http.set_filter_state",
        "typed_config": {
            "@type": "type.googleapis.com/envoy.extensions.filters.http.set_filter_state.v3.Config",
            "on_request_headers": [
                {"object_key": key, "factory_key": "envoy.string", "skip_if_empty": skip_empty,
                 "format_string": {"text_format_source": {"inline_string": "%REQ(X-TENANT)%"},
                                   "omit_empty_values": True}}
                for key, skip_empty in [("test.tenant", True), ("test.empty", False)]
            ],
        },
    }
    metadata = {
        "name": "envoy.filters.http.set_metadata",
        "typed_config": {
            "@type": "type.googleapis.com/envoy.extensions.filters.http.set_metadata.v3.Config",
            "metadata": [{"metadata_namespace": "workload",
                          "value": {"namespace": "research", "labels": {"app": "api"}}}],
        },
    }
    manager = {
        "@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
        "stat_prefix": "test",
        "route_config": {"name": "test", "virtual_hosts": [{
            "name": "test", "domains": ["*"],
            "routes": [{"match": {"prefix": "/"}, "route": {"cluster": "upstream"}}],
        }]},
        "http_filters": [state, metadata, module, {
            "name": "envoy.filters.http.router",
            "typed_config": {"@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"},
        }],
        "access_log": [access_log()],
    }
    return {
        "static_resources": {
            "listeners": [{"name": "test", "address": address(port), "filter_chains": [{
                "filters": [{"name": "envoy.filters.network.http_connection_manager", "typed_config": manager}],
            }]}],
            "clusters": [{
                "name": "upstream", "connect_timeout": "1s", "type": "STATIC",
                "load_assignment": {"cluster_name": "upstream", "endpoints": [{
                    "lb_endpoints": [{"endpoint": {"address": address(upstream)}}],
                }]},
            }],
        },
    }


FIXTURES = pathlib.Path(__file__).resolve().parent.parent / "testdata"
STREAMS = {
    "/v1/chat/completions": ({"model": "test", "messages": [{"role": "user", "content": "hello"}]}, "chat-empty-content"),
    "/v1/messages": ({"model": "test", "messages": [{"role": "user", "content": "hello"}]}, "anthropic-usage"),
    "/v1/responses": ({"model": "test", "input": "hello"}, "responses-refusal"),
}


# Each input ends with tool output. The earlier user text supplies question.
QA = {
    "/v1/messages": ({"model": "test", "messages": [
        {"role": "user", "content": "weather?"},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "c", "content": "private result"}]},
    ]}, "anthropic", "你好"),
    "/v1/chat/completions": ({"model": "test", "messages": [
        {"role": "user", "content": "weather?"}, {"role": "tool", "tool_call_id": "c", "content": "private result"},
    ]}, "openai", "你好"),
    "/v1/responses": ({"model": "test", "input": [
        {"role": "user", "content": "weather?"}, {"type": "function_call_output", "call_id": "c", "output": "private result"},
    ]}, "responses", "你好no"),
}


# Exercise line clipping with both JSON escapes and multi-byte characters.
LONG_TEXT = '水"'.join(["问"] * 800)


def dual_sse(path):
    wire = (FIXTURES / (QA[path][1] + ".sse")).read_text()
    if path == "/v1/responses":
        # The terminal snapshot revises the already-sealed item.
        early, terminal = wire.split("event: response.completed")
        wire = early.replace("你", "draft") + "event: response.completed" + terminal
    return wire.replace("你", json.dumps(LONG_TEXT, ensure_ascii=False)[1:-1]).encode()


class Echo(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        if self.path.startswith("/gzip/"):
            assert self.headers.get("Content-Encoding") == "gzip"
        self.send_response(200)
        if self.path in STREAMS:
            request, stream = QA[self.path][:2] if self.headers["Host"] == "qa.test" else STREAMS[self.path]
            assert body == json.dumps(request).encode()
            body = dual_sse(self.path) if self.headers["Host"] == "sse.test" else (FIXTURES / (stream + ".sse")).read_bytes()
            self.send_header("Content-Type", "text/event-stream")
        else:
            self.send_header("Content-Type", self.headers["Content-Type"])
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def exercise(port):
    size = int(os.environ.get("CONTENTGUARD_SMOKE_FILE_BYTES", 262144))
    body = json.dumps({"model": "test", "messages": [{"role": "user", "content": [
        {"type": "image_url", "image_url": {"url": "data:image/png;base64," + "A" * size}},
        {"type": "text", "text": "after image"},
    ]}]}).encode()
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    connection.request("POST", "/upload", body, {"Content-Type": "application/json", "Host": "image.test"})
    response = connection.getresponse()
    assert response.status == 200 and response.read() == body
    compressed = gzip.compress(body, compresslevel=1, mtime=0)
    for path, payload in [("/gzip/valid", compressed), ("/gzip/corrupt", compressed[:-1])]:
        connection.request("POST", path, payload, {
            "Content-Type": "application/json", "Host": "image.test", "Content-Encoding": "gzip",
        })
        response = connection.getresponse()
        assert response.status == 200 and response.read() == payload
    connection.close()
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    custom = b'{"input":"hello","model":"m","output":[]}'
    for host in ["ignored.test", "llm.test", "other.test", "Custom.LLM.test:443"]:
        connection.request("POST", "/custom", custom, {
            "Host": host, "Content-Type": "application/json", "x-tenant": "green",
        })
        response = connection.getresponse()
        assert response.status == 200 and response.read() == custom
    for path, tenant in [("/custom", "red"), ("/custom", None), ("/custom/extra", "green"), ("/upload", None)]:
        headers = {"Host": "other.llm.test", "Content-Type": "application/json"}
        if tenant:
            headers["x-tenant"] = tenant
        connection.request("POST", path, custom, headers)
        response = connection.getresponse()
        assert response.status == 200 and response.read() == custom
    connection.close()
    for path, host, media, payload in [
        ("/internal/messages", "127.0.0.1", "application/json", b'{"model":"m","messages":[],"secret":"private"}'),
        ("/v1/messages/", "127.0.0.1", "text/plain", b"private unsupported text"),
    ]:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
        headers = {"Host": host, "Content-Type": media}
        connection.request("POST", path, payload, headers)
        response = connection.getresponse()
        assert response.status == 200 and response.read() == payload
        connection.close()
    dual = json.dumps({
        "messages": [{"role": "user", "content": "a" * (2 << 20)}, {"content": "latest?", "role": "user"}],
        "tools": [{"type": "function", "function": {"name": "get_weather",
                  "parameters": {"type": "object", "description": "d" * 3000}}}],
    }).encode()
    for path in ("/dual", "/dual-small"):
        connection.request("POST", path, dual, {"Content-Type": "application/json"})
        response = connection.getresponse()
        assert response.status == 200 and response.read() == dual
        connection.close()
    for path, (request, stream) in STREAMS.items():
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        request_body = json.dumps(request).encode()
        connection.request("POST", path, request_body, {"Content-Type": "application/json"})
        response = connection.getresponse()
        assert response.status == 200 and response.read() == (FIXTURES / (stream + ".sse")).read_bytes()
        connection.close()
    for path, (request, stream, _) in QA.items():
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        connection.request("POST", path, json.dumps(request), {"Host": "qa.test", "Content-Type": "application/json",
                                                               "x-tenant": "qa"})
        response = connection.getresponse()
        assert response.status == 200 and response.read() == (FIXTURES / (stream + ".sse")).read_bytes()
        connection.close()
    for path, (request, _) in STREAMS.items():
        connection.request("POST", path, json.dumps(request), {"Host": "sse.test", "Content-Type": "application/json"})
        response = connection.getresponse()
        assert response.status == 200 and response.read() == dual_sse(path)
        connection.close()
    return len(body)


def check_records(lines, json_bytes):
    dual = {"dual": [], "dual-small": []}
    extra = []
    qa_records = []
    sse_records = {path: [] for path in STREAMS}
    other_lines = []
    custom_directions = []
    for line in lines:
        assert line.endswith(b"\n")
        record = json.loads(line)
        if record["chain"] == "sse-audits":
            sse_records[record["path"]].append((record, len(line)))
            continue
        if record["chain"] in dual:
            dual[record["chain"]].append((record, len(line)))
            continue
        if record["path"] == "/custom":
            custom_directions.append(record["direction"])
        assert "filterIndex" not in record and "schema" not in record
        assert "attributes" not in record and "content" not in record
        attrs = record
        if record["chain"] == "custom" and "llm.question" in record:
            extra.append(record)
            continue
        if record["chain"] in ("qa", "custom"):
            assert attrs["sandbox"] == attrs["app.tenant.id"]
            assert attrs["namespace"] == "research" and "missing" not in attrs and "object" not in attrs
        if attrs.get("app.tenant.id") == "qa":
            assert len(line) <= {"request": 2048, "response": 1024}[record["direction"]]
            assert b"private result" not in line and "北京" not in json.dumps(record, ensure_ascii=False)
            qa_records.append(record)
        else:
            other_lines.append(line)
    for path, pair in sse_records.items():
        (answer, answer_bytes), (usage, usage_bytes) = pair
        assert answer["requestID"] == usage["requestID"] and answer["bytesSeen"] == usage["bytesSeen"] == len(dual_sse(path))
        assert answer_bytes <= 1024 and usage_bytes <= 2048 and answer["direction"] == usage["direction"] == "response"
        assert answer["captureStatus"] == "truncated" and answer["text"] and LONG_TEXT.startswith(answer["text"])
        assert "tokens" not in answer and "text" not in usage
        assert usage["captureStatus"] == "complete" and usage["tokens"] == (12 if path == "/v1/messages" else 8)
    for name, records in dual.items():
        (question, question_bytes), (tools, tools_bytes) = records
        assert question["requestID"] == tools["requestID"] and question["bytesSeen"] == tools["bytesSeen"]
        assert question["llm.question"] == "latest?" and "gen_ai.tool.definitions" not in question
        assert "llm.question" not in tools and question_bytes <= 2048 and tools_bytes <= 8192
        definition, = tools["gen_ai.tool.definitions"]
        assert definition["name"] == "get_weather"
        length = len(definition["parameters"]["description"])
        if name == "dual-small":
            assert tools["captureStatus"] == "truncated" and 0 < length < 2048
        else:
            assert tools["captureStatus"] == "complete" and length == 3000 and tools_bytes > 2048
    assert len(qa_records) == 2 * len(QA)
    for path, (_, _, answer) in QA.items():
        pair = [r for r in qa_records if r["path"] == path]
        req, = (r for r in pair if r["direction"] == "request")
        res, = (r for r in pair if r["direction"] == "response")
        assert req["captureStatus"] == res["captureStatus"] == "complete" and req["requestID"] == res["requestID"]
        assert req["llm.question"] == "weather?" and res["llm.answer"] == answer
        assert req["agentio.tool.calls"] == [{"kind": "result", "id": "c"}]
        assert res["agentio.tool.calls"][0]["name"] == "lookup"
        assert "gen_ai.input.messages" not in req and "gen_ai.output.messages" not in res
    lines = other_lines
    assert custom_directions == ["request", "response", "request"]
    assert len(extra) == 1 and extra[0]["direction"] == "request"
    assert extra[0]["llm.question"] == "hello" and "app.tenant.id" not in extra[0]
    assert len(lines) == 2 * (3 + len(STREAMS)) + 3, lines
    records = [json.loads(line) for line in lines]
    assert {r["direction"] for r in records} == {"request", "response"}
    for path in ["/custom", "/internal/messages", *STREAMS]:
        pair = [r for r in records if r["path"] == path]
        assert len(pair) == 2 and {r["direction"] for r in pair} == {"request", "response"}
        assert pair[0]["requestID"] and pair[0]["requestID"] == pair[1]["requestID"]
    for path in ["/upload"]:
        assert [r["direction"] for r in records if r["path"] == path] == ["request"]
    assert {r["direction"] for r in records if r["path"] == "/v1/messages/"} == {"request", "response"}
    for line, record in zip(lines, records):
        assert len(line) <= {"request": 2048, "response": 1024}[record["direction"]]
        if record["path"] == "/custom":
            assert record["app.tenant.id"] == "green"
            assert record["gen_ai.operation.name"] == "chat"
            assert record["llm.protocol"] == "openai-responses"
            assert record["captureStatus"] == "complete", record
        elif record["path"] == "/gzip/corrupt":
            assert record["captureStatus"] == "invalid_encoding" and "messages" not in record
        elif record["path"] in ["/upload", "/gzip/valid"]:
            assert record["chain"] == "image" and record["direction"] == "request"
            assert record["captureStatus"] == "truncated"
            if record["path"] == "/gzip/valid":
                assert record["decodedBytes"] == json_bytes and 0 < record["bytesSeen"] < json_bytes
            else:
                assert record["bytesSeen"] == json_bytes and "decodedBytes" not in record
            image, text = record["messages"][0]["parts"]
            assert image == {"type":"blob","modality":"image","mime_type":"image/png"} and text["content"] == "after image"
        elif record["path"] == "/internal/messages":
            assert record["captureStatus"] == "unknown_protocol" and "http.body" not in record and "messages" not in record
            assert record["bytesSeen"] == len(b'{"model":"m","messages":[],"secret":"private"}') and b"private" not in line
        elif record["path"] == "/v1/messages/":
            assert record["captureStatus"] == "unsupported_media_type" and "http.body" not in record and "messages" not in record
            assert b"private" not in line
        else:
            request, stream = STREAMS[record["path"]]
            assert record["captureStatus"] == "complete", record
            if record["direction"] == "response":
                assert record["bytesSeen"] == (FIXTURES / (stream + ".sse")).stat().st_size
                expected = json.loads((FIXTURES / (stream + ".want.json")).read_text())
                attrs = record
                assert attrs["model"] == expected["model"]
                assert attrs["gen_ai.usage.output_tokens"] == expected["usage"]["outputTokens"]
                for message, actual in zip(expected["outputMessages"], attrs["messages"], strict=True):
                    assert actual["role"] == message["role"] and actual["parts"] == message["content"]
                assert record["llm.protocol"] == expected["format"]
            else:
                assert record["bytesSeen"] == len(json.dumps(request).encode())
                assert "messages" in record


def main(image):
    with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Echo) as origin, tempfile.TemporaryDirectory() as tmp:
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        cfg = pathlib.Path(tmp, "envoy.json")
        config = bootstrap(port, origin.server_port)
        cfg.write_text(json.dumps(config))
        name = f"contentguard-{uuid.uuid4().hex}"
        with pathlib.Path(tmp, "audit.jsonl").open("w+b") as logs:
            process = subprocess.Popen([
                "docker", "run", "--rm", "--name", name, "--network", "host",
                "-v", f"{cfg}:/etc/envoy/test.json:ro", "--entrypoint", "/usr/local/bin/envoy",
                "-e", "ENVOY_DYNAMIC_MODULES_SEARCH_PATH=/usr/local/lib",
                image, "-c", "/etc/envoy/test.json", "--concurrency", "2", "--log-level", "warning",
            ], stdout=logs)
            try:
                for _ in range(200):
                    if process.poll() is not None:
                        raise RuntimeError(f"Envoy exited with {process.returncode}")
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                            break
                    except ConnectionRefusedError:
                        time.sleep(0.05)
                json_bytes = exercise(port)
            finally:
                subprocess.run(["docker", "stop", name], check=False, stdout=subprocess.DEVNULL)
                process.wait(timeout=15)
                origin.shutdown()
            logs.seek(0)
            lines = logs.readlines()
        check_records(lines, json_bytes)


if __name__ == "__main__":
    main(sys.argv[1])
