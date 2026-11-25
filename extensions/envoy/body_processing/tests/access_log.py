#!/usr/bin/env python3
# Copyright 2026 The Kruise Authors
# SPDX-License-Identifier: Apache-2.0
"""Compare audit fields with Envoy's native formatter on the same HTTP streams."""

import datetime
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

from smoke import bootstrap


FIELDS = {
    "id": "%REQ(X-TEST-ID)%",
    "start": "%START_TIME%",
    "epoch": "%START_TIME(%s.%9f)%",
    "date": "%START_TIME(%Y/%m/%dT%H:%M:%S%z)%",
    "duration": "%DURATION%",
    "request_duration": "%REQUEST_DURATION%",
    "response_duration": "%RESPONSE_DURATION%",
    "code": "%RESPONSE_CODE%",
    "details": "%RESPONSE_CODE_DETAILS%",
    "flags": "%RESPONSE_FLAGS%",
    "trace": "%TRACE_ID%",
    "span": "%SPAN_ID%",
    "response_header": "%RESP(X-ABSENT?X-MODEL-ID)%",
    "short_header": "%RESP(X-MODEL-ID):4%",
    "missing": "%RESP(X-MISSING)%",
    "environment": "%ENVIRONMENT(AGENTIO_AUDIT_CLUSTER)%",
    "short_environment": "%ENVIRONMENT(AGENTIO_AUDIT_CLUSTER):4%",
    "missing_environment": "%ENVIRONMENT(AGENTIO_AUDIT_UNSET)%",
}


def config(port, upstream):
    value = bootstrap(port, upstream)
    manager = value["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
    module = next(f for f in manager["http_filters"] if f["name"] == "envoy.filters.http.dynamic_modules")
    module["typed_config"]["filter_config"]["value"] = json.dumps({
        "filterChains": [{"name": "fields", "parser": {"llm": {}},
                          "filters": [{"audit": {"format": {"json": {"kind": "audit", **FIELDS}}}}]}],
    })
    manager["http_filters"] = [module, manager["http_filters"][-1]]
    manager["route_config"]["validate_clusters"] = False
    logger = json.loads(json.dumps(manager["access_log"][0]))
    logger.pop("filter")
    logger["typed_config"]["log_format"] = {"json_format": {"kind": "native", **FIELDS}, "omit_empty_values": True}
    manager["access_log"].append(logger)
    manager["tracing"] = {
        "provider": {"name": "envoy.tracers.opentelemetry", "typed_config": {
            "@type": "type.googleapis.com/envoy.config.trace.v3.OpenTelemetryConfig",
            "service_name": "audit-access-fields",
            "http_service": {"http_uri": {
                "uri": "http://collector/v1/traces", "cluster": "upstream", "timeout": "1s",
            }},
        }},
        "random_sampling": {"value": 100},
    }
    routes = manager["route_config"]["virtual_hosts"][0]["routes"]
    routes[:] = [
        {"name": "deny", "match": {"path": "/deny"}, "direct_response": {"status": 403}},
        {"name": "no-cluster", "match": {"path": "/no-cluster"}, "route": {"cluster": "missing"}},
        {"name": "retry", "match": {"path": "/retry"}, "route": {
            "cluster": "upstream", "retry_policy": {"retry_on": "5xx", "num_retries": 1}}},
        {"name": "model-route", "match": {"prefix": "/"}, "route": {"cluster": "upstream"}},
    ]
    return value


class Origin(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    attempts = 0

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if self.path == "/v1/traces":
            self.send_response(200)
            self.send_header("Content-Type", "application/x-protobuf")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        retry = self.path == "/retry" and type(self).attempts == 0
        if self.path == "/retry":
            type(self).attempts += 1
        if self.path == "/abort":
            self.send_response(200)
            self.send_header("Content-Length", "100")
            self.end_headers()
            self.wfile.write(b"partial")
            self.wfile.flush()
            time.sleep(0.3)
            self.close_connection = True
            return
        time.sleep(0.035)
        self.send_response(503 if retry else 200)
        if retry:
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_header("X-Model-ID", "test-model")
        self.send_header("Content-Length", "6")
        self.end_headers()
        self.wfile.write(b"one")
        self.wfile.flush()
        time.sleep(0.025)
        self.wfile.write(b"two")
        self.wfile.flush()

    def log_message(self, format, *args):
        pass


def exercise(port):
    start = time.time_ns()
    for case in ["slow", "retry", "deny", "no-cluster", "abort"]:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.putrequest("POST", "/" + case)
        for k, v in {"Content-Type": "application/octet-stream", "Content-Length": "6", "X-Test-ID": case,
                     "traceparent": "00-1234567890abcdef1234567890abcdef-1234567890abcdef-01"}.items():
            conn.putheader(k, v)
        conn.endheaders()
        conn.send(b"abc")
        if case == "slow":
            time.sleep(0.04)
        conn.send(b"def")
        response = conn.getresponse()
        if case == "abort":
            assert response.read(7) == b"partial"
        else:
            assert response.status == {"deny": 403, "no-cluster": 503}.get(case, 200)
            assert response.read() == (b"" if case in ["deny", "no-cluster"] else b"onetwo")
        response.close()
        conn.close()
    return start


def check(path, started):
    groups = {}
    for line in path.read_bytes().splitlines():
        row = json.loads(line)
        groups.setdefault(row["id"], {})[row.pop("kind")] = row
    assert set(groups) == {"slow", "retry", "deny", "no-cluster", "abort"}, groups.keys()
    differences = []
    for case, records in groups.items():
        audit, native = records["audit"], records["native"]
        for key in FIELDS:
            a, n = audit.get(key), native.get(key)
            # Native typed JSON uses null for absent strings when omission is enabled.
            if a is None and n is None:
                continue
            if a != n:
                differences.append((case, key, a, n))
        assert audit["environment"] == "cluster-hk-test"
        assert audit["short_environment"] == "clus"
        assert audit["missing_environment"] == "-" and "missing" not in audit
        assert int(float(audit["epoch"]) * 1e9) >= started - 1_000_000
        assert datetime.datetime.fromisoformat(audit["start"].replace("Z", "+00:00")).tzinfo is not None
        assert audit["trace"] == "1234567890abcdef1234567890abcdef"
        assert len(audit["span"]) == 16
        assert "content" not in audit
        if case in ("slow", "retry"):
            assert audit["response_header"] == "test-model" and audit["short_header"] == "test"
            assert audit["flags"] == "-"
        if case == "slow":
            assert audit["request_duration"] >= 25
            assert audit["response_duration"] >= audit["request_duration"] + 20
            assert audit["duration"] >= audit["response_duration"] + 15
    assert not differences, differences
    print(f"{len(groups)} HTTP streams matched Envoy's native formatter for {len(FIELDS)} fields")


def main(image):
    with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin) as origin, tempfile.TemporaryDirectory() as tmp:
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        cfg, logs = pathlib.Path(tmp, "envoy.json"), pathlib.Path(tmp, "logs.jsonl")
        cfg.write_text(json.dumps(config(port, origin.server_port)))
        name = "audit-access-fields-" + uuid.uuid4().hex[:10]
        with logs.open("wb") as output:
            process = subprocess.Popen([
                "docker", "run", "--rm", "--name", name, "--network", "host",
                "-v", f"{cfg}:/etc/envoy/test.json:ro", "--entrypoint", "/usr/local/bin/envoy",
                "-e", "ENVOY_DYNAMIC_MODULES_SEARCH_PATH=/usr/local/lib",
                "-e", "AGENTIO_AUDIT_CLUSTER=cluster-hk-test",
                image, "-c", "/etc/envoy/test.json", "--concurrency", "1", "--log-level", "warning",
                "--file-flush-interval-msec", "10",
            ], stdout=output)
            try:
                for _ in range(160):
                    if process.poll() is not None:
                        raise RuntimeError(f"Envoy exited {process.returncode}")
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                            break
                    except OSError:
                        time.sleep(0.05)
                else:
                    raise RuntimeError("Envoy did not start")
                started = exercise(port)
                time.sleep(0.4)
            finally:
                subprocess.run(["docker", "stop", name], stdout=subprocess.DEVNULL, check=False)
                process.wait(timeout=15)
                origin.shutdown()
        check(logs, started)


if __name__ == "__main__":
    main(sys.argv[1])
