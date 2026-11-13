#!/usr/bin/env python3
# Copyright 2026 The Kruise Authors
# SPDX-License-Identifier: Apache-2.0
"""Linux + Docker integration: CONNECT -> inspectors -> module -> real TLS/relay."""
import argparse
import copy
import json
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
from pathlib import Path


def typed(name, **fields):
    return {"@type": "type.googleapis.com/" + name, **fields}


def address(port):
    return {"socket_address": {"address": "127.0.0.1", "port_value": port}}


def policy_store():
    return {"name": "agentio.connection_policy_store", "typed_config": typed(
        "envoy.extensions.filters.http.dynamic_modules.v3.DynamicModuleFilter",
        dynamic_module_config={"name": "envoy_agentio_connection_policy", "do_not_close": True},
        filter_name="envoy_agentio_connection_policy_store")}


def policy_hash():
    return {"name": "envoy.filters.http.set_filter_state", "typed_config": typed(
        "envoy.extensions.filters.http.set_filter_state.v3.Config", on_request_headers=[{
            "object_key": "agentio.connection.policy_hash", "factory_key": "envoy.hashable_string",
            "shared_with_upstream": "ONCE", "read_only": True, "skip_if_empty": True,
            "format_string": {"text_format_source": {"inline_string": "%DYNAMIC_METADATA(agentio.connection:policy_hash)%"}}}])}


def config(port, legacy_port, plain_port, tls_port, cert, key):
    def relay(cluster):
        return [{"name": "envoy.filters.network.tcp_proxy", "typed_config": typed(
            "envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy", stat_prefix=cluster,
            cluster=cluster, idle_timeout="10s")}]

    chains = [{"name": "tls-terminate", "filters": relay("plain"),
        "transport_socket": {"name": "envoy.transport_sockets.tls", "typed_config": typed(
            "envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext",
            common_tls_context={"tls_certificates": [{"certificate_chain": {"inline_string": cert},
                "private_key": {"inline_string": key}}]})}},
        {"name": "forward-tcp", "filters": relay("tls-origin")},
        {"name": "cleartext", "filters": relay("plain")}]
    chains.append({"name": "deny", "filters": [
        {"name": "envoy.filters.network.set_filter_state", "typed_config": typed(
            "envoy.extensions.filters.network.set_filter_state.v3.Config", on_new_connection=[{
                "object_key": "agentio.egress.denial_reason", "factory_key": "envoy.string", "skip_if_empty": True,
                "format_string": {"text_format_source": {"inline_string":
                    "%CEL('agentio.egress.denial_reason' in filter_state ? '' : 'sni_policy_denied')%"}}}])},
        {"name": "envoy.filters.network.direct_response", "typed_config": typed(
            "envoy.extensions.filters.network.direct_response.v3.Config")}]})
    actions = {value: {"action": {"name": name, "typed_config": typed("google.protobuf.StringValue", value=name)}}
               for value, name in [("terminate", "tls-terminate"), ("passthrough", "forward-tcp"), ("fallthrough", "forward-tcp"), ("cleartext", "cleartext"), ("deny", "deny")]}
    inner = {"name": "inner", "internal_listener": {}, "listener_filters_timeout": "1s",
        "access_log": [{"name": "envoy.access_loggers.stdout", "typed_config": typed(
            "envoy.extensions.access_loggers.stream.v3.StdoutAccessLog", log_format={"json_format": {
                "denial_reason": "%FILTER_STATE(agentio.egress.denial_reason:PLAIN)%"}})}],
        "continue_on_listener_filters_timeout": False,
        "listener_filters": [
            {"name": "envoy.filters.listener.original_dst", "typed_config": typed("envoy.extensions.filters.listener.original_dst.v3.OriginalDst")},
            {"name": "envoy.filters.listener.tls_inspector", "typed_config": typed("envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector")},
            {"name": "envoy.filters.listener.http_inspector", "typed_config": typed("envoy.extensions.filters.listener.http_inspector.v3.HttpInspector")},
            {"name": "envoy.filters.listener.dynamic_modules", "typed_config": typed(
                "envoy.extensions.filters.listener.dynamic_modules.v3.DynamicModuleListenerFilter",
                dynamic_module_config={"name": "envoy_agentio_connection_policy"}, filter_name="envoy_agentio_sni_policy")}],
        "filter_chains": chains,
        "filter_chain_matcher": {"matcher_tree": {"input": {"name": "tls-action", "typed_config": typed(
            "envoy.extensions.matching.common_inputs.network.v3.FilterStateInput", key="agentio.tls.action")},
            "exact_match_map": {"map": actions}}}}
    # Example-only ingress: a trusted CONNECT producer supplies canonical JSON.
    # A production ext_proc integration can use %DYNAMIC_METADATA(...)% instead.
    state = {"name": "envoy.filters.http.set_filter_state", "typed_config": typed(
        "envoy.extensions.filters.http.set_filter_state.v3.Config", on_request_headers=[{
            "object_key": "envoy.filters.listener.original_dst.local_ip",
            "shared_with_upstream": "ONCE",
            "format_string": {"text_format_source": {"inline_string": "%REQ(:AUTHORITY)%"}}}, {
            "object_key": "agentio.connection.policy_json", "factory_key": "envoy.string",
            "skip_if_empty": True,
            "format_string": {"text_format_source": {"inline_string": "%REQ(x-test-connection-policy)%"}}}])}
    hcm = typed("envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
        stat_prefix="connect", codec_type="AUTO", upgrade_configs=[{"upgrade_type": "CONNECT"}],
        route_config={"name": "connect", "virtual_hosts": [{"name": "all", "domains": ["*"], "routes": [{
            "match": {"connect_matcher": {}}, "route": {"cluster": "internal", "timeout": "0s",
                "upgrade_configs": [{"upgrade_type": "CONNECT", "connect_config": {}}]}}]}]},
        http_filters=[state, policy_store(), policy_hash(), {"name": "envoy.filters.http.router", "typed_config": typed("envoy.extensions.filters.http.router.v3.Router")}])
    outer = {"name": "connect", "address": address(port), "filter_chains": [{"filters": [
        {"name": "envoy.filters.network.http_connection_manager", "typed_config": hcm}]}]}
    # A separate test-only listener reproduces the conflicting legacy writer.
    legacy = copy.deepcopy(outer)
    legacy["name"], legacy["address"] = "legacy-connect", address(legacy_port)
    legacy_state = legacy["filter_chains"][0]["filters"][0]["typed_config"]["http_filters"][0]["typed_config"]
    legacy_state["on_request_headers"].append({"object_key": "agentio.tls.action",
        "factory_key": "envoy.hashable_string", "shared_with_upstream": "ONCE",
        "format_string": {"text_format_source": {"inline_string": "passthrough"}}})
    clusters = [{"name": name, "type": "STATIC", "connect_timeout": "1s", "load_assignment": {
        "cluster_name": name, "endpoints": [{"lb_endpoints": [{"endpoint": {"address": address(p)}}]}]}}
        for name, p in [("plain", plain_port), ("tls-origin", tls_port)]]
    clusters.append({"name": "internal", "type": "STATIC", "connect_timeout": "1s",
        "transport_socket": {"name": "envoy.transport_sockets.internal_upstream", "typed_config": typed(
            "envoy.extensions.transport_sockets.internal_upstream.v3.InternalUpstreamTransport",
            transport_socket={"name": "envoy.transport_sockets.raw_buffer", "typed_config": typed("envoy.extensions.transport_sockets.raw_buffer.v3.RawBuffer")})},
        "load_assignment": {"cluster_name": "internal", "endpoints": [{"lb_endpoints": [{"endpoint": {
            "address": {"envoy_internal_address": {"server_listener_name": "inner"}}}}]}]}})
    return {"bootstrap_extensions": [{"name": "envoy.bootstrap.internal_listener", "typed_config": typed(
        "envoy.extensions.bootstrap.internal_listener.v3.InternalListener")}],
        "static_resources": {"listeners": [outer, legacy, inner], "clusters": clusters}}


class Origin(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def get_request(self):
        sock, addr = super().get_request()
        sock.settimeout(5)
        if self.tls_context:
            sock = self.tls_context.wrap_socket(sock, server_side=True)
        return sock, addr


class Echo(socketserver.StreamRequestHandler):
    def handle(self):
        data = self.rfile.readline()
        if data:
            self.wfile.write(self.server.marker + b":" + data)


def connect(port, policy):
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    headers = "" if policy is None else f"x-test-connection-policy: {policy}\r\n"
    sock.sendall((f"CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n{headers}\r\n").encode())
    response = bytearray()
    while not response.endswith(b"\r\n\r\n"):
        byte = sock.recv(1)
        if not byte:
            raise AssertionError(f"CONNECT closed: {response!r}")
        response.extend(byte)
    if not response.startswith(b"HTTP/1.1 200"):
        sock.close()
        raise ConnectionError(f"CONNECT denied: {response!r}")
    return sock


def exercise(port, policy, host, want, cleartext=False):
    try:
        tunnel = connect(port, policy)
    except ConnectionError:
        if want == "deny":
            return
        raise
    with tunnel:
        if cleartext:
            channel = tunnel
        else:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            # Self-signed test fixture: this test validates routing, not PKI.
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                channel = ctx.wrap_socket(tunnel, server_hostname=host)
            except (ssl.SSLError, ConnectionResetError):
                if want == "deny":
                    return
                raise
        with channel:
            assert want != "deny", "denied connection completed TLS"
            channel.sendall(b"ping\n")
            response = channel.makefile("rb").readline()
            assert response == want.encode() + b":ping\n", response


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", default="agentio-envoy-connection-policy:dev")
    args = parser.parse_args()
    policy = json.dumps(json.loads(Path(__file__).with_name("policy.json").read_text()), separators=(",", ":"))
    with tempfile.TemporaryDirectory(prefix="agentio-sni-") as directory:
        root = Path(directory)
        # The official image drops privileges to the envoy user.
        root.chmod(0o755)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=agentio-sni-test", "-keyout", str(root / "key.pem"), "-out", str(root / "cert.pem")],
            check=True, capture_output=True)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(root / "cert.pem", root / "key.pem")
        servers = []
        for marker, context in [(b"plain", None), (b"tls", tls)]:
            server = Origin(("127.0.0.1", 0), Echo)
            server.marker, server.tls_context = marker, context
            threading.Thread(target=server.serve_forever, daemon=True).start()
            servers.append(server)
        with socket.socket() as sock, socket.socket() as legacy_sock:
            sock.bind(("127.0.0.1", 0))
            legacy_sock.bind(("127.0.0.1", 0))
            port, legacy_port = sock.getsockname()[1], legacy_sock.getsockname()[1]
        configuration = config(port, legacy_port, *(s.server_address[1] for s in servers),
            (root / "cert.pem").read_text(), (root / "key.pem").read_text())
        (root / "envoy.json").write_text(json.dumps(configuration))
        base = ["docker", "run", "--rm", "--network", "host", "-v", f"{root}:/config:ro", args.image,
            "envoy", "-c", "/config/envoy.json", "--concurrency", "2", "--log-level", "error"]
        subprocess.run(base + ["--mode", "validate"], check=True)
        container = subprocess.check_output(base[:2] + ["-d"] + base[2:], text=True).strip()
        try:
            for attempt in range(100):
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=.1):
                        break
                except ConnectionRefusedError:
                    time.sleep(.05)
            else:
                raise AssertionError("Envoy failed to listen")
            cases = [
                ("terminate", policy, "api.example.com", "plain", False),
                ("first-match passthrough", policy, "skip.example.com", "tls", False),
                ("multi-label wildcard", policy, "a.b.example.com", "plain", False),
                ("normalization", policy, "API.EXAMPLE.COM.", "plain", False),
                ("no match", policy, "other.test", "tls", False),
                ("no SNI", policy, None, "tls", False),
                ("explicit deny", policy, "denied.example.com", "deny", False),
                ("TCP deny without SNI match", '{"profiles":[{"uid":"profile","tcpPolicy":{"rules":[{"name":"deny-all","match":[{}],"action":"TCP_ACTION_DENY"}]}}]}', "other.test", "deny", False),
                ("original port match", '{"profiles":[{"uid":"profile","sniPolicy":{"rules":[{"match":{"sni":["*"],"ports":[443]},"action":"SNI_ACTION_DENY"}]}}]}', "api.example.com", "deny", False),
                ("original port mismatch", '{"profiles":[{"uid":"profile","sniPolicy":{"rules":[{"match":{"sni":["*"],"ports":[8443]},"action":"SNI_ACTION_DENY"}]}}]}', "api.example.com", "tls", False),
                ("empty policy", '{"profiles":[]}', "api.example.com", "tls", False),
                ("missing policy", None, "api.example.com", "deny", False),
                ("malformed policy", "not-json", "api.example.com", "deny", False),
                ("invalid later SNI pattern rejects snapshot", '{"profiles":[{"uid":"profile","sniPolicy":{"rules":[{"match":{"sni":["*"]},"action":"SNI_ACTION_PASSTHROUGH"},{"match":{"sni":["bad*"]},"action":"SNI_ACTION_DENY"}]}}]}', "api.example.com", "deny", False),
                ("invalid later SNI port rejects snapshot", '{"profiles":[{"uid":"profile","sniPolicy":{"rules":[{"match":{"sni":["*"]},"action":"SNI_ACTION_PASSTHROUGH"},{"match":{"sni":["*"],"ports":[65536]},"action":"SNI_ACTION_DENY"}]}}]}', "api.example.com", "deny", False),
                ("flat SNI policy is rejected", '{"rules":[]}', "api.example.com", "deny", False),
                ("cleartext", '{"profiles":[]}', None, "plain", True),
                ("cleartext does not parse unused policy", "not-json", None, "plain", True),
                # Alternate policies for the same SNI to detect stale policy reuse.
                ("new policy on same SNI", '{"profiles":[]}', "api.example.com", "tls", False),
                ("restore policy on same SNI", policy, "api.example.com", "plain", False),
            ]
            for label, value, host, want, cleartext in cases:
                exercise(port, value, host, want, cleartext)
                print(f"PASS {label}", flush=True)
            exercise(legacy_port, policy, "denied.example.com", "deny")
            print("PASS legacy action cannot bypass policy", flush=True)
            expected_reasons = {"sni_policy_denied", "tcp_policy_denied", "connection_policy_invalid"}
            for _ in range(50):
                logs = subprocess.check_output(["docker", "logs", container], stderr=subprocess.STDOUT, text=True)
                reasons = {json.loads(line).get("denial_reason") for line in logs.splitlines() if line.startswith("{")}
                if expected_reasons <= reasons:
                    break
                time.sleep(.1)
            assert expected_reasons <= reasons, (expected_reasons, reasons)
            print("PASS listener logs preserve SNI, TCP and policy-error reasons", flush=True)
        finally:
            logs = subprocess.check_output(["docker", "logs", container], stderr=subprocess.STDOUT, text=True)
            subprocess.run(["docker", "stop", "-t", "1", container], check=True, stdout=subprocess.DEVNULL)
            for server in servers:
                server.shutdown()
                server.server_close()
            if logs:
                print(logs)


if __name__ == "__main__":
    main()
