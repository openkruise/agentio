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


class Echo(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        self.send_response(200)
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
        cfg.write_text(json.dumps(bootstrap(port, origin.server_port)))
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
            finally:
                subprocess.run(["docker", "stop", name], check=False, stdout=subprocess.DEVNULL)
                process.wait(timeout=15)
                origin.shutdown()
            logs.seek(0)
            lines = logs.readlines()
        assert len(lines) == 2, lines
        records = [json.loads(line) for line in lines]
        assert {r["direction"] for r in records} == {"request", "response"}
        assert records[0]["requestID"] and records[0]["requestID"] == records[1]["requestID"]
        for line, record in zip(lines, records):
            assert len(line) <= {"request": 2048, "response": 1024}[record["direction"]]
            assert record["status"] == "truncated" and record["bytesSeen"] == len(body)
            assert record["content"] == {"image_url": "[omitted]", "text": "after image"}


if __name__ == "__main__":
    main(sys.argv[1])
