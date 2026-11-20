#!/usr/bin/env python3
# Copyright 2026 The Kruise Authors
# SPDX-License-Identifier: Apache-2.0
"""Exercise the installed module and Envoy access logger in a Linux container."""

import http.client
import http.server
import json
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


def access_log(direction):
    return {
        "name": "envoy.access_loggers.stdout",
        "filter": {"extension_filter": {
            "name": "envoy.access_loggers.extension_filters.cel",
            "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.access_loggers.filters.cel.v3.ExpressionFilter",
                "expression": f"'agentio.contentguard.{direction}' in filter_state",
            },
        }},
        "typed_config": {
            "@type": "type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog",
            "log_format": {"text_format_source": {
                "inline_string": f"%FILTER_STATE(agentio.contentguard.{direction}:PLAIN)%\n",
            }},
        },
    }


def bootstrap(port, upstream):
    module = {
        "name": "envoy.filters.http.dynamic_modules",
        "typed_config": {
            "@type": "type.googleapis.com/envoy.extensions.filters.http.dynamic_modules.v3.DynamicModuleFilter",
            "dynamic_module_config": {"name": "envoy_agentio_contentguard"},
            "filter_name": "contentguard",
            "filter_config": {
                "@type": "type.googleapis.com/google.protobuf.StringValue",
                "value": json.dumps({"request": {"maxLogBytes": 2048}, "response": {"maxLogBytes": 1024}}),
            },
        },
    }
    manager = {
        "@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
        "stat_prefix": "test",
        "route_config": {"name": "test", "virtual_hosts": [{
            "name": "test", "domains": ["*"],
            "routes": [{"match": {"prefix": "/"}, "route": {"cluster": "upstream"}}],
        }]},
        "http_filters": [module, {
            "name": "envoy.filters.http.router",
            "typed_config": {"@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"},
        }],
        "access_log": [access_log("request"), access_log("response")],
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


class Echo(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        self.send_response(200)
        if self.path in STREAMS:
            request, stream = STREAMS[self.path]
            assert body == json.dumps(request).encode()
            body = (FIXTURES / (stream + ".sse")).read_bytes()
            self.send_header("Content-Type", "text/event-stream")
        else:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main(image):
    with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Echo) as origin, tempfile.TemporaryDirectory() as tmp:
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        cfg = pathlib.Path(tmp, "envoy.json")
        config = bootstrap(port, origin.server_port)
        manager = config["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
        module_config = manager["http_filters"][0]["typed_config"]["filter_config"]
        settings = json.loads(module_config["value"])
        settings["rules"] = [
            {"match": {"hosts": ["skip.llm.test"]}, "action": "skip"},
            {"match": {"hosts": ["*.llm.test"]}, "action": "audit", "format": "openai-responses"},
            {"match": {"hosts": ["127.0.0.1"]}, "action": "audit"},
        ]
        settings["audit"] = {"attributes": {"app.tenant.id": {"requestHeader": "x-tenant"}}}
        module_config["value"] = json.dumps(settings)
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
                body = json.dumps({"image_url": "data:image/png;base64," + "A" * 262144, "text": "after image"}).encode()
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                connection.request("POST", "/echo", body, {"Content-Type": "application/json"})
                response = connection.getresponse()
                assert response.status == 200 and response.read() == body
                connection.close()
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                custom = b'{"input":"hello","model":"m","output":[]}'
                for host in ["skip.llm.test", "llm.test", "other.test", "Custom.LLM.test:443"]:
                    connection.request("POST", "/custom", custom, {
                        "Host": host, "Content-Type": "application/json", "x-tenant": "green",
                    })
                    response = connection.getresponse()
                    assert response.status == 200 and response.read() == custom
                connection.close()
                for path, (request, stream) in STREAMS.items():
                    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                    request_body = json.dumps(request).encode()
                    connection.request("POST", path, request_body, {"Content-Type": "application/json"})
                    response = connection.getresponse()
                    assert response.status == 200 and response.read() == (FIXTURES / (stream + ".sse")).read_bytes()
                    connection.close()
            finally:
                subprocess.run(["docker", "stop", name], check=False, stdout=subprocess.DEVNULL)
                process.wait(timeout=15)
                origin.shutdown()
            logs.seek(0)
            lines = logs.readlines()
        assert len(lines) == 2 * (2 + len(STREAMS)), lines
        records = [json.loads(line) for line in lines]
        assert {r["direction"] for r in records} == {"request", "response"}
        for path in ["/echo", "/custom", *STREAMS]:
            pair = [r for r in records if r["path"] == path]
            assert len(pair) == 2 and {r["direction"] for r in pair} == {"request", "response"}
            assert pair[0]["requestID"] and pair[0]["requestID"] == pair[1]["requestID"]
        for line, record in zip(lines, records):
            assert len(line) <= {"request": 2048, "response": 1024}[record["direction"]]
            if record["path"] == "/custom":
                assert record["attributes"] == {"app.tenant.id": "green"}
                assert record["content"]["format"] == "openai-responses"
                assert record["status"] == "complete", record
            elif record["path"] == "/echo":
                assert record["status"] == "truncated" and record["bytesSeen"] == len(body)
                assert record["content"] == {"image_url": "[omitted]", "text": "after image"}
            else:
                request, stream = STREAMS[record["path"]]
                assert record["status"] == "complete", record
                if record["direction"] == "response":
                    assert record["bytesSeen"] == (FIXTURES / (stream + ".sse")).stat().st_size
                    assert record["content"] == json.loads((FIXTURES / (stream + ".want.json")).read_text())
                else:
                    assert record["bytesSeen"] == len(json.dumps(request).encode())
                    assert "inputMessages" in record["content"]


if __name__ == "__main__":
    main(sys.argv[1])
