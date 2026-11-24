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

import llm_streaming


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
    common = {"chain": "%CHAIN%", "requestID": "%REQ(X-REQUEST-ID)%",
              "path": "%PATH%", "llm.protocol": "%EVENT(llm.protocol)%"}
    request_info = {"requestBytes": "%BYTES_SEEN(request)%", "decodedBytes": "%DECODED_BYTES(request)%",
                    "requestStatus": "%CAPTURE_STATUS(request)%"}
    response_info = {"responseBytes": "%BYTES_SEEN(response)%", "responseStatus": "%CAPTURE_STATUS(response)%"}

    def audit(fields):
        return {"audit": {"format": {"json": {**common, **fields}}}}

    messages = {"input": "%EVENT(llm.request.messages)%", "output": "%EVENT(llm.response.messages)%",
                "tools": "%EVENT(llm.toolDefinitions)%", "requestModel": "%EVENT(llm.request.model)%",
                "responseModel": "%EVENT(llm.response.model)%", "gen_ai.operation.name": "%EVENT(llm.operation)%",
                "gen_ai.usage.output_tokens": "%EVENT(llm.usage.outputTokens)%"}
    question = {"llm.question": "%EVENT(llm.question):2048%"}
    tools = {"gen_ai.tool.definitions": "%EVENT(llm.toolDefinitions):8192%"}
    stream_fields = {"chain": "%CHAIN%", "case": "%REQ(X-LLM-CASE)%", "id": "%REQ(X-REQUEST-ID)%",
                     "bytes": "%BYTES_SEEN(response)%"}
    attributes = {
        "app.tenant.id": "%REQ(X-TENANT)%",
        "sandbox": "%FILTER_STATE(test.tenant:PLAIN)%",
        "namespace": "%DYNAMIC_METADATA(workload:namespace)%",
        "stringFlag": "%DYNAMIC_METADATA(workload:stringFlag)%",
        "retries": "%DYNAMIC_METADATA_NUMBER(workload:retries)%",
        "weight": "%DYNAMIC_METADATA_NUMBER(workload:weight)%",
        "sampled": "%DYNAMIC_METADATA_BOOL(workload:sampled)%",
        "missing": "%DYNAMIC_METADATA(workload:absent)%",
        "missingNumber": "%DYNAMIC_METADATA_NUMBER(workload:absent)%",
        "missingBool": "%DYNAMIC_METADATA_BOOL(workload:absent)%",
        "object": "%DYNAMIC_METADATA(workload:labels)%",
    }
    settings = {
        "filterChains": [
            {"name": "context-only", "matcher": {"paths": ["/context-only"]}, "parser": {"llm": {}},
             "filters": [audit({"tenant": "%REQ(X-TENANT)%"}), {"audit": {"format": {"json": {"absent": "%REQ(X-ABSENT)%"}}}}]},
            {"name": "chat-choices", "matcher": {"hosts": ["choices.test", "reset.test"]}, "parser": {"llm": {}},
             "filters": [audit({"question": "%EVENT(llm.question)%", "answer": "%EVENT(llm.answer)%",
                                "input": "%EVENT(llm.request.messages):62%", "requestStatus": "%CAPTURE_STATUS(request)%",
                                "preview": "%EVENT(llm.response.retainedText)%",
                                "tokens": "%EVENT(llm.usage.totalTokens)%", "status": "%CAPTURE_STATUS(response)%"})]},
            {"name": "custom", "matcher": {"hosts": ["*.llm.test"], "paths": ["/custom"],
                       "filterState": [{"key": "test.tenant", "values": ["green", "blue"]}]},
             "parser": {"llm": {"protocol": "openai-responses"}},
             "filters": [audit(messages | attributes | request_info | response_info | {"shortTenant": "%REQ(X-TENANT):2%"}),
                         audit(question | request_info)]},
            *[{"name": name, "matcher": {"paths": ["/" + name]},
               "parser":{"llm":{"protocol":"openai-chat-completions", **options}},
               "filters":[audit(question | request_info),audit(tools | request_info)]}
              for name, options in (("dual",{}),("dual-small",{"request":{"maxItemSize":"2KiB"}}))],
            {"name":"image","matcher":{"hosts":["image.test"],"filterState":[{"key":"test.empty"}]},
             "parser":{"llm":{"protocol":"openai-chat-completions"}},
             "filters":[audit({"input":"%EVENT(llm.request.messages):2048%"} | request_info)]},
            {"name": "attachments", "matcher": {"hosts": ["attachments.test"]}, "parser": {"llm": {}},
             "filters": [audit({"case": "%REQ(X-LLM-CASE)%", "messages": f"%EVENT(llm.request.messages):{limit}%",
                                "status": "%CAPTURE_STATUS(request)%"}) for limit in (1024, 8192)]},
            {"name":"qa","matcher":{"hosts":["qa.test"]},"parser":{"llm":{}},
             "filters":[audit(attributes | question | request_info | response_info | {"llm.answer":"%EVENT(llm.answer)%", "requestCalls":"%EVENT(llm.request.toolCallRefs)%", "responseCalls":"%EVENT(llm.response.toolCallRefs)%"})]},
            {"name": "sse-audits", "matcher": {"hosts": ["sse.test"]}, "parser": {"llm": {}},
             "filters": [
                 audit({"text": "%EVENT(llm.answer):1024%", "messages": "%EVENT(llm.response.messages):256%"} | response_info),
                 audit({"tokens": "%EVENT(llm.usage.totalTokens)%"} | response_info),
             ]},
            {"name": "streaming", "matcher": {"hosts": [llm_streaming.HOST + "."], "paths": list(STREAMS)},
             "parser": {"llm": {}}, "filters": [
                 {"audit": {"format": {"json": {**stream_fields, "answerStatus": "%CAPTURE_STATUS(response)%",
                                                "answer": "%EVENT(llm.answer):768%",
                                                "tokens": "%EVENT(llm.usage.totalTokens)%",
                                                "model": "%EVENT(llm.response.model)%",
                                                "note": "%REQ(X-AGENT-NOTE):128%"}}}},
                 {"audit": {"format": {"json": {**stream_fields, "usageStatus": "%CAPTURE_STATUS(response)%",
                                                "tokens": "%EVENT(llm.usage.totalTokens)%",
                                                "calls": "%EVENT(llm.response.toolCallRefs)%"}}}},
             ]},
            {"name":"standard","matcher":{"hosts":["127.0.0.1","custom.llm.test"],"paths":[*STREAMS,"/custom","/internal/messages"]},
             "parser":{"llm":{}},"filters":[audit(messages | request_info | response_info)]},
        ],
    }
    module = {
        "name": "envoy.filters.http.dynamic_modules",
        "typed_config": {
            "@type": "type.googleapis.com/envoy.extensions.filters.http.dynamic_modules.v3.DynamicModuleFilter",
            "dynamic_module_config": {"name": "envoy_agentio_body_processing"},
            "filter_name": "body_processing",
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
                          "value": {"namespace": "research", "labels": {"app": "api"},
                                    "stringFlag": "false", "retries": 0, "weight": -0.5, "sampled": False}}],
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


FIXTURES = llm_streaming.FIXTURES
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


# Exercise answer-field clipping with both JSON escapes and multi-byte characters.
LONG_TEXT = '水"'.join(["问"] * 800)


def dual_sse(path):
    wire = (FIXTURES / (QA[path][1] + ".sse")).read_text()
    if path == "/v1/responses":
        # The terminal snapshot revises the already-sealed item.
        early, terminal = wire.split("event: response.completed")
        wire = early.replace("你", "draft") + "event: response.completed" + terminal
    return wire.replace("你", json.dumps(LONG_TEXT, ensure_ascii=False)[1:-1]).encode()


RESET_PREFIX = (b'data: {"model":"m","choices":[{"index":1,"delta":{"content":"alternate"}},'
                b'{"index":0,"delta":{"content":"retry"}}]}\n\ndata: {"partial":')
RESET_RECEIVED = threading.Event()
JSON_CHOICES = json.dumps({"model": "test", "choices": [
    {"index": index, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}
    for index, text in llm_streaming.CHAT_ALTERNATIVES
]}).encode()

ATTACHMENT_DATA = "YWFh" * 1024
SMALL_ATTACHMENT_DATA = "c21hbGwgZmlsZQ=="


def anthropic_document(data):
    return {"type": "document", "title": "report",
            "source": {"type": "base64", "media_type": "application/pdf", "data": data}}


ATTACHMENTS = {
    "screenshot": (llm_streaming.RESPONSES, lambda s: {
        "type": "computer_screenshot", "detail": "original", "image_url": "data:image/png;base64," + s}),
    "responses-file": (llm_streaming.RESPONSES, lambda s: {
        "type": "input_file", "filename": "a.pdf", "file_data": "data:application/pdf;base64," + s}),
    "responses-file-url": (llm_streaming.RESPONSES, lambda s: {
        "type": "input_file", "filename": "a.csv", "file_url": "data:text/csv;base64," + s}),
    "chat-file": (llm_streaming.CHAT, lambda s: {
        "type": "file", "file": {"filename": "a.pdf", "file_data": s}}),
    "chat-audio": (llm_streaming.CHAT, lambda s: {
        "type": "input_audio", "input_audio": {"format": "wav", "data": s}}),
    "anthropic-document": (llm_streaming.ANTHROPIC, anthropic_document),
    "anthropic-tool-result": (llm_streaming.ANTHROPIC, anthropic_document),
}


class Echo(llm_streaming.StreamHandler):
    def do_POST(self):
        if self.headers["Host"].partition(":")[0].removesuffix(".").lower() == llm_streaming.HOST:
            return super().do_POST()
        body = self.rfile.read(int(self.headers["Content-Length"]))
        if self.path.startswith("/gzip/"):
            assert self.headers.get("Content-Encoding") == "gzip"
        self.send_response(200)
        if self.headers["Host"] == "reset.test":
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(RESET_PREFIX) + 100))
            self.end_headers()
            self.wfile.write(RESET_PREFIX)
            self.wfile.flush()
            assert RESET_RECEIVED.wait(timeout=10)
            self.close_connection = True
            return
        if self.headers["Host"] == "choices.test":
            body = JSON_CHOICES
            self.send_header("Content-Type", "application/json")
        elif self.path in STREAMS and self.headers["Host"] != "attachments.test":
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
    size = int(os.environ.get("BODY_PROCESSING_SMOKE_FILE_BYTES", 262144))
    body = json.dumps({"model": "test", "messages": [{"role": "user", "content": [
        {"type": "image_url", "image_url": {"url": "data:image/png;base64," + "A" * size, "detail": "high"}},
        {"type": "text", "text": "after image"},
    ]}]}).encode()
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    for case, (path, make_part) in ATTACHMENTS.items():
        part = make_part(ATTACHMENT_DATA)
        text = {"type": "input_text" if path == llm_streaming.RESPONSES else "text", "text": "after attachment"}
        if case == "screenshot":
            messages = [{"type": "computer_call_output", "call_id": "c1", "output": part},
                        {"role": "user", "content": [text]}]
        else:
            parts = [part, make_part(SMALL_ATTACHMENT_DATA), text]
            if case == "anthropic-tool-result":
                parts = [{"type": "tool_result", "tool_use_id": "c1", "content": parts}, text]
            messages = [{"role": "user", "content": parts}]
        prompt_key = "input" if path == llm_streaming.RESPONSES else "messages"
        payload = json.dumps({"model": "test", prompt_key: messages}).encode()
        connection.request("POST", path, payload, {
            "Content-Type": "application/json", "Host": "attachments.test", "X-LLM-Case": case})
        response = connection.getresponse()
        assert response.status == 200 and response.read() == payload, case
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
    connection.request("POST", "/context-only", b"opaque", {"Content-Type": "text/plain", "X-Tenant": "alpha"})
    response = connection.getresponse()
    assert response.status == 200 and response.read() == b"opaque"
    connection.request("POST", llm_streaming.CHAT, json.dumps({"model": "test", "messages": [
        {"role": "user", "content": "天气很好"}], "n": 2}), {"Host": "choices.test", "Content-Type": "application/json"})
    response = connection.getresponse()
    assert response.status == 200 and response.read() == JSON_CHOICES
    connection.request("POST", "/v1/chat/completions", json.dumps({"messages": [{"role": "user", "content": "retry?"}]}),
                       {"Host": "reset.test", "Content-Type": "application/json"})
    response = connection.getresponse()
    try:
        assert response.status == 200 and response.read(len(RESET_PREFIX)) == RESET_PREFIX
    finally:
        response.close()
        connection.close()
        RESET_RECEIVED.set()
    custom = json.dumps({"model": "m", "output": [], "input": [{"role": "user", "content": [
        {"type": "input_text", "text": "hello"},
        {"type": "input_image", "file_id": "file-42", "detail": "high"},
        {"type": "input_image", "image_url": "https://example.test/cat.png", "detail": "low"},
    ]}]}).encode()
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
    streaming_lines = []
    sse_records = {path: [] for path in STREAMS}
    other_lines = []
    custom_records = []
    context_records = []
    choice_records = []
    attachments = {case: [] for case in ATTACHMENTS}
    for line in lines:
        assert line.endswith(b"\n")
        record = json.loads(line)
        if not record or record["chain"] == "context-only":
            context_records.append(record)
            continue
        if record["chain"] == "chat-choices":
            choice_records.append(record)
            continue
        if record["chain"] == "attachments":
            attachments[record["case"]].append(record)
            continue
        if record["chain"] == "streaming":
            streaming_lines.append(line)
            continue
        if record["chain"] == "sse-audits":
            sse_records[record["path"]].append(record)
            continue
        if record["chain"] in dual:
            dual[record["chain"]].append(record)
            continue
        if record["path"] == "/custom":
            custom_records.append(record)
        assert "filterIndex" not in record and "schema" not in record
        assert "attributes" not in record and "content" not in record
        attrs = record
        if record["chain"] == "custom" and "llm.question" in record:
            extra.append(record)
            continue
        if record["chain"] in ("qa", "custom"):
            assert attrs["sandbox"] == attrs["app.tenant.id"]
            assert attrs["namespace"] == "research" and attrs["stringFlag"] == "false"
            assert type(attrs["retries"]) in (int, float) and attrs["retries"] == 0
            assert attrs["weight"] == -0.5 and attrs["sampled"] is False
            assert {"missing", "missingNumber", "missingBool", "object"}.isdisjoint(attrs)
        if attrs.get("app.tenant.id") == "qa":
            assert b"private result" not in line and "北京" not in json.dumps(record, ensure_ascii=False)
            qa_records.append(record)
        else:
            other_lines.append(line)
    context, empty = context_records
    assert context == {"chain": "context-only", "path": "/context-only", "requestID": context["requestID"], "tenant": "alpha"} and not empty
    assert len(choice_records) == 2, choice_records
    complete, = (r for r in choice_records if r["status"] == "complete")
    assert complete["question"] == "天气很好" and complete["answer"] == "primary"
    assert complete["input"] == [{"role": "user", "parts": [{"type": "text", "content": "天气"}]}]
    assert complete["requestStatus"] == "truncated"
    assert complete["preview"] == ["primary", "alternate"], complete
    reset, = (r for r in choice_records if r["status"] == "incomplete")
    assert reset["question"] == "retry?" and reset["answer"] == "retry" and reset["preview"] == ["retry", "alternate"]
    assert reset["input"] == [{"role": "user", "parts": [{"type": "text", "content": "retry?"}]}]
    assert reset["requestStatus"] == "complete"
    assert "tokens" not in reset, reset
    for case, (_, make_part) in ATTACHMENTS.items():
        small, full = attachments[case]
        assert small["requestID"] == full["requestID"]
        for row, data, status in [(small, "[omitted]", "truncated"), (full, ATTACHMENT_DATA, "complete")]:
            messages = row["messages"]
            parts = messages[0]["parts"]
            if case in ("screenshot", "anthropic-tool-result"):
                assert parts[0]["type"] == "tool_call_response" and parts[0]["id"] == "c1"
                parts = parts[0]["response"]
            envelope = {"type": "provider_content", "format": row["llm.protocol"]}
            assert parts[0] == (envelope | {"data": make_part(data)}), case
            text = {"type": "text", "content": "after attachment"}
            if case != "screenshot":
                assert parts[1:] == [envelope | {"data": make_part(SMALL_ATTACHMENT_DATA)}, text], case
            assert messages[-1]["parts"][-1] == text, case
            assert row["status"] == status, case
    llm_streaming.check_audits(streaming_lines)
    for path, pair in sse_records.items():
        answer, usage = pair
        assert answer["requestID"] == usage["requestID"] and answer["responseBytes"] == usage["responseBytes"] == len(dual_sse(path))
        prefix = answer["text"]
        assert answer["responseStatus"] == "truncated" and prefix and LONG_TEXT.startswith(prefix)
        size = len(json.dumps(prefix, ensure_ascii=False).encode()) - 2
        next_size = len(json.dumps(LONG_TEXT[:len(prefix) + 1], ensure_ascii=False).encode()) - 2
        assert size <= 1024 < next_size
        message, = answer["messages"]
        part, = message["parts"]
        text = part["content"]
        assert message["role"] == "assistant" and message["index"] == 0
        assert part["type"] == "text" and text and LONG_TEXT.startswith(text), path
        size = len(json.dumps(answer["messages"], ensure_ascii=False, separators=(",", ":")).encode())
        next_char_bytes = len(json.dumps(LONG_TEXT[len(text)], ensure_ascii=False).encode()) - 2
        assert size <= 256 < size + next_char_bytes
        assert "messages" not in usage
        assert "tokens" not in answer and "text" not in usage
        assert usage["responseStatus"] == "complete" and usage["tokens"] == (12 if path == "/v1/messages" else 8)
    for name, records in dual.items():
        question, tools = records
        assert question["requestID"] == tools["requestID"] and question["requestBytes"] == tools["requestBytes"]
        assert question["llm.question"] == "latest?" and "gen_ai.tool.definitions" not in question
        assert "llm.question" not in tools
        definition, = tools["gen_ai.tool.definitions"]
        assert definition["name"] == "get_weather"
        length = len(definition["parameters"]["description"])
        if name == "dual-small":
            assert tools["requestStatus"] == "truncated" and 0 < length < 2048
        else:
            assert tools["requestStatus"] == "complete" and length == 3000
    assert len(qa_records) == len(QA)
    for path, (_, _, answer) in QA.items():
        row, = [r for r in qa_records if r["path"] == path]
        assert row["requestStatus"] == row["responseStatus"] == "complete" and row["requestID"]
        assert row["llm.question"] == "weather?" and row["llm.answer"] == answer
        assert row["requestCalls"] == [{"kind": "result", "id": "c"}]
        assert row["responseCalls"][0]["name"] == "lookup"
        assert "gen_ai.input.messages" not in row and "gen_ai.output.messages" not in row
    assert len(custom_records) == 2 and extra == [custom_records[1]]
    assert custom_records[0]["requestID"] == extra[0]["requestID"]
    assert extra[0]["llm.question"] == "hello" and "app.tenant.id" not in extra[0]
    assert extra[0]["requestStatus"] == "complete"
    records = [json.loads(line) for line in other_lines]
    paths = ["/custom", "/internal/messages", "/v1/messages/", "/upload", "/gzip/valid", "/gzip/corrupt", *STREAMS]
    assert sorted(row["path"] for row in records) == sorted(paths)
    for line, record in zip(other_lines, records):
        assert record["requestID"]
        if record["path"] == "/custom":
            assert record["app.tenant.id"] == "green" and record["gen_ai.operation.name"] == "chat"
            assert record["llm.protocol"] == "openai-responses"
            assert record["input"][0]["parts"] == [
                {"type": "text", "content": "hello"},
                {"type": "file", "modality": "image", "file_id": "file-42", "detail": "high"},
                {"type": "uri", "modality": "image", "uri": "https://example.test/cat.png", "detail": "low"},
            ]
            assert record["requestModel"] == record["responseModel"] == "m"
            assert record["shortTenant"] == "gr" and record["requestStatus"] == "truncated", record
            assert record["responseStatus"] == "complete", record
        elif record["path"] == "/gzip/corrupt":
            assert record["requestStatus"] == "invalid_encoding" and "input" not in record
        elif record["path"] in ["/upload", "/gzip/valid"]:
            assert record["chain"] == "image" and "responseStatus" not in record
            assert record["requestStatus"] == "truncated"
            if record["path"] == "/gzip/valid":
                assert record["decodedBytes"] == json_bytes and 0 < record["requestBytes"] < json_bytes
            else:
                assert record["requestBytes"] == json_bytes and "decodedBytes" not in record
            image, text = record["input"][0]["parts"]
            assert image == {"type":"blob","modality":"image","mime_type":"image/png","detail":"high"} and text["content"] == "after image"
        elif record["path"] in ["/internal/messages", "/v1/messages/"]:
            expected = "unknown_protocol" if record["path"] == "/internal/messages" else "unsupported_media_type"
            assert record["requestStatus"] == record["responseStatus"] == expected
            assert {"http.body", "input", "output"}.isdisjoint(record) and b"private" not in line
            if record["path"] == "/internal/messages":
                assert record["requestBytes"] == len(b'{"model":"m","messages":[],"secret":"private"}')
        else:
            request, stream = STREAMS[record["path"]]
            assert record["requestStatus"] == record["responseStatus"] == "complete", record
            assert record["requestBytes"] == len(json.dumps(request).encode()) and "input" in record
            assert record["responseBytes"] == (FIXTURES / (stream + ".sse")).stat().st_size
            expected = json.loads((FIXTURES / (stream + ".want.json")).read_text())
            assert record["requestModel"] == request["model"] and record["responseModel"] == expected["model"]
            assert record["gen_ai.usage.output_tokens"] == expected["usage"]["outputTokens"]
            for message, actual in zip(expected["outputMessages"], record["output"], strict=True):
                assert actual["role"] == message["role"] and actual["parts"] == message["content"]
            assert record["llm.protocol"] == expected["format"]


def main(image):
    with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Echo) as origin, tempfile.TemporaryDirectory() as tmp:
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        cfg = pathlib.Path(tmp, "envoy.json")
        config = bootstrap(port, origin.server_port)
        cfg.write_text(json.dumps(config))
        name = f"body-processing-{uuid.uuid4().hex}"
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
                llm_streaming.exercise(f"127.0.0.1:{port}")
            finally:
                subprocess.run(["docker", "stop", name], check=False, stdout=subprocess.DEVNULL)
                process.wait(timeout=15)
                origin.shutdown()
            logs.seek(0)
            lines = logs.readlines()
        check_records(lines, json_bytes)


if __name__ == "__main__":
    main(sys.argv[1])
