#!/usr/bin/env python3
# Copyright 2026 The Kruise Authors
# SPDX-License-Identifier: Apache-2.0
"""Real Envoy: ordered SP policies, SNI resolution, pinned targets and server-first TCP."""
import argparse
import copy
import json
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from smoke import Origin, Echo, address, config, typed


class CountedOrigin(Origin):
    calls = 0

    def get_request(self):
        sock, peer = super(Origin, self).get_request()
        self.calls += 1
        sock.settimeout(5)
        if self.tls_context:
            sock = self.tls_context.wrap_socket(sock, server_side=True)
        return sock, peer


class Greeting(Echo):
    def handle(self):
        self.wfile.write(b"hello\n")


class PersistentEcho(Echo):
    def handle(self):
        for _ in range(2):
            data = self.rfile.readline()
            if not data:
                return
            self.wfile.write(self.server.marker + b":" + data)


def tcp(action, cidrs=None, ports=None):
    clause = {}
    if cidrs is not None:
        clause["cidrs"] = cidrs
    if ports is not None:
        clause["ports"] = ports
    return {"name": "tcp", "match": [clause], "action": "TCP_ACTION_" + action.upper()}


def profile(uid, rules=(), sni=None):
    p = {"uid": uid, "tcpPolicy": {"rules": list(rules)}}
    if sni:
        p["sniPolicy"] = {"rules": [{"match": {"sni": ["*"]}, "action": "SNI_ACTION_" + sni.upper()}]}
    return p


def network(resolve_sni=False):
    return {"name": "agentio.tcp_policy", "typed_config": typed(
        "envoy.extensions.filters.network.dynamic_modules.v3.DynamicModuleNetworkFilter",
        dynamic_module_config={"name": "envoy_agentio_connection_policy", "do_not_close": True},
        filter_name="envoy_agentio_tcp_policy", filter_config=typed(
            "google.protobuf.Struct", value={"resolveSni": resolve_sni, "skipMatchedProfile": resolve_sni, "deniedCidrs": []}))}


def fixture(port, legacy_port, plain_port, tls_port, cert, key):
    result = config(port, legacy_port, plain_port, tls_port, cert, key)
    resources = result["static_resources"]
    outer, _, inner = resources["listeners"]
    hcm = outer["filter_chains"][0]["filters"][0]["typed_config"]
    # The original-destination cluster consumes only the module's pinned numerical address.
    resources["clusters"].append({"name": "pinned", "type": "ORIGINAL_DST",
                                  "lb_policy": "CLUSTER_PROVIDED", "connect_timeout": "1s"})
    proxy = {"name": "envoy.filters.network.tcp_proxy", "typed_config": typed(
        "envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy", stat_prefix="pinned", cluster="pinned")}
    raw_filters = [network(), proxy]
    for chain in inner["filter_chains"]:
        if chain["name"] in ("forward-tcp", "cleartext"):
            chain["filters"] = copy.deepcopy(raw_filters)
    inner["filter_chains"].append({"name": "tls-passthrough", "filters": [network(True), copy.deepcopy(proxy)]})
    actions = inner["filter_chain_matcher"]["matcher_tree"]["exact_match_map"]["map"]
    for action, chain in [("fallthrough", "forward-tcp"), ("passthrough", "tls-passthrough")]:
        actions[action] = {"action": {"name": chain, "typed_config": typed("google.protobuf.StringValue", value=chain)}}
    # Server-first takes the same authorization path, without protocol inspectors.
    raw_inner = {"name": "raw-inner", "internal_listener": {}, "listener_filters": [inner["listener_filters"][0]],
                 "filter_chains": [{"filters": copy.deepcopy(raw_filters)}]}
    resources["listeners"].append(raw_inner)
    raw_cluster = copy.deepcopy(next(c for c in resources["clusters"] if c["name"] == "internal"))
    raw_cluster["name"] = raw_cluster["load_assignment"]["cluster_name"] = "raw-internal"
    raw_cluster["load_assignment"]["endpoints"][0]["lb_endpoints"][0]["endpoint"]["address"]["envoy_internal_address"]["server_listener_name"] = "raw-inner"
    resources["clusters"].append(raw_cluster)
    # Mirror the production TLS-termination relay into another internal listener.
    post = copy.deepcopy(raw_inner)
    post["name"] = "post-tls"
    resources["listeners"].append(post)
    post_cluster = copy.deepcopy(raw_cluster)
    post_cluster["name"] = post_cluster["load_assignment"]["cluster_name"] = "post-tls"
    post_cluster["load_assignment"]["endpoints"][0]["lb_endpoints"][0]["endpoint"]["address"]["envoy_internal_address"]["server_listener_name"] = "post-tls"
    resources["clusters"].append(post_cluster)
    relay = {"name": "envoy.filters.network.set_filter_state", "typed_config": typed(
        "envoy.extensions.filters.network.set_filter_state.v3.Config", on_new_connection=[{
            "object_key": k, "factory_key": factory, "shared_with_upstream": "ONCE",
            "format_string": {"text_format_source": {"inline_string": f"%FILTER_STATE({k}:PLAIN)%"}}}
            for k, factory in [("envoy.filters.listener.original_dst.local_ip", "envoy.filters.listener.original_dst.local_ip"),
                               ("agentio.connection.policy_hash", "envoy.hashable_string"), ("agentio.policy.start", "envoy.hashable_string")]])}
    terminal = next(c for c in inner["filter_chains"] if c["name"] == "tls-terminate")
    terminal["filters"] = [relay, {"name": "envoy.filters.network.tcp_proxy", "typed_config": typed(
        "envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy", stat_prefix="post-tls", cluster="post-tls")}]
    routes = hcm["route_config"]["virtual_hosts"][0]["routes"]
    raw_route = copy.deepcopy(routes[0])
    raw_route["match"]["headers"] = [{"name": "x-test-server-first", "string_match": {"exact": "true"}}]
    raw_route["route"]["cluster"] = "raw-internal"
    routes.insert(0, raw_route)
    return result


def connect(port, target, profiles, server_first):
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    policy = json.dumps({"profiles": profiles}, separators=(",", ":"))
    policy_header = f"x-test-connection-policy: {policy}\r\n" if profiles is not None else ""
    raw = "x-test-server-first: true\r\n" if server_first else ""
    sock.sendall((f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{policy_header}{raw}\r\n").encode())
    response = bytearray()
    while not response.endswith(b"\r\n\r\n"):
        value = sock.recv(1)
        if not value:
            raise AssertionError(f"CONNECT failed: {response!r}")
        response.extend(value)
    if not response.startswith(b"HTTP/1.1 200"):
        sock.close()
        raise ConnectionError(f"CONNECT denied: {response!r}")
    return sock


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="agentio-tcp-policy-") as directory:
        root = Path(directory)
        root.chmod(0o755)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost",
                        "-keyout", str(root / "key.pem"), "-out", str(root / "cert.pem")], check=True, capture_output=True)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(root / "cert.pem", root / "key.pem")
        servers = []
        for marker, context, handler in [(b"plain", None, Echo), (b"tls", tls, Echo), (b"greeting", None, Greeting), (b"plain", None, PersistentEcho)]:
            server = CountedOrigin(("127.0.0.1", 0), handler)
            server.marker, server.tls_context = marker, context
            threading.Thread(target=server.serve_forever, daemon=True).start()
            servers.append(server)
        plain, tls_origin, greeting, persistent = servers
        with socket.socket() as a, socket.socket() as b:
            a.bind(("127.0.0.1", 0)); b.bind(("127.0.0.1", 0))
            port, legacy_port = a.getsockname()[1], b.getsockname()[1]
        data = fixture(port, legacy_port, plain.server_address[1], tls_origin.server_address[1],
                       (root / "cert.pem").read_text(), (root / "key.pem").read_text())
        (root / "envoy.json").write_text(json.dumps(data))
        base = ["docker", "run", "--rm", "--network", "host", "-v", f"{root}:/config:ro", args.image,
                "envoy", "-c", "/config/envoy.json", "--concurrency", "2", "--log-level", "error"]
        subprocess.run(base + ["--mode", "validate"], check=True)
        container = subprocess.check_output(base[:2] + ["-d"] + base[2:], text=True).strip()
        try:
            for attempt in range(100):
                try:
                    socket.create_connection(("127.0.0.1", port), timeout=.1).close()
                    break
                except OSError:
                    time.sleep(.05)
            else:
                raise AssertionError("Envoy did not start")

            def exercise(name, profiles, origin=plain, host=None, denied=False, original="127.0.0.1", first=False, terminate=False):
                before = origin.calls
                target = f"{original}:{origin.server_address[1]}"
                try:
                    with connect(port, target, profiles, first) as tunnel:
                        channel = tunnel
                        if origin is tls_origin or terminate:
                            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                            ctx.check_hostname = False
                            ctx.verify_mode = ssl.CERT_NONE
                            channel = ctx.wrap_socket(tunnel, server_hostname=host)
                        with channel:
                            if not first:
                                channel.sendall(b"ping\n")
                            response = channel.makefile("rb").readline()
                            if denied:
                                assert not response, (name, response)
                            else:
                                expected = b"hello\n" if first else origin.marker + b":ping\n"
                                assert response == expected, (name, response)
                except (OSError, ssl.SSLError):
                    if not denied:
                        raise
                if denied:
                    assert origin.calls == before, f"{name}: denied connection reached upstream"
                else:
                    assert origin.calls == before + 1, (name, origin.calls, before)
                print("PASS", name, flush=True)

            exercise("raw default allow", [])
            exercise("missing TCP policy fails closed", None, denied=True)
            exercise("malformed TCP policy fails closed", [profile("a", [tcp("deny", ["invalid"])])], denied=True)
            exercise("raw deny before connect", [profile("a", [tcp("deny")])], denied=True)
            exercise("raw ordered allow before deny", [profile("a", [tcp("allow")]), profile("b", [tcp("deny")])])
            exercise("port mismatch continues", [profile("a", [tcp("deny", ports=[1])]), profile("b", [tcp("allow")])])
            exercise("server-first allow", [profile("a", [tcp("allow")])], origin=greeting, first=True)
            exercise("server-first deny before connect", [profile("a", [tcp("deny")])], origin=greeting, first=True, denied=True)
            exercise("TLS TCP allow precedes lower SNI deny", [profile("a", [tcp("allow")]), profile("b", sni="deny")], origin=tls_origin, host="unresolved.invalid")
            exercise("TLS TCP deny precedes lower SNI passthrough", [profile("a", [tcp("deny")]), profile("b", sni="passthrough")], origin=tls_origin, host="localhost", denied=True)
            exercise("SNI passthrough skips own TCP deny", [profile("a", [tcp("deny")], sni="passthrough")], origin=tls_origin, host="localhost")
            exercise("SNI resolved target instead of original", [profile("a", sni="passthrough")], origin=tls_origin, host="localhost", original="192.0.2.254")
            exercise("SNI DNS failure never uses original address", [profile("a", sni="passthrough")], origin=tls_origin, host="agentio-tcp-policy.unresolved.invalid", denied=True)
            exercise("SNI target rechecks higher TCP deny", [profile("a", [tcp("deny", ["127.0.0.0/8"])]), profile("b", sni="passthrough")], origin=tls_origin, host="localhost", original="192.0.2.254", denied=True)
            exercise("empty SNI uses TCP policy", [profile("a", [tcp("allow")])], origin=tls_origin)
            exercise("empty SNI TCP deny", [profile("a", [tcp("deny")])], origin=tls_origin, denied=True)
            exercise("empty SNI wildcard deny precedes own TCP allow", [profile("a", [tcp("allow")], sni="deny")], origin=tls_origin, denied=True)
            exercise("empty SNI passthrough skips own TCP deny", [profile("a", [tcp("deny")], sni="passthrough")], origin=tls_origin)
            exercise("empty SNI passthrough retains higher TCP deny", [profile("a", [tcp("deny")]), profile("b", sni="passthrough")], origin=tls_origin, denied=True)
            exercise("TLS termination preserves policy across listener", [profile("a", [tcp("allow")], sni="tls_termination")], host="localhost", terminate=True)
            exercise("TLS termination still evaluates own TCP deny", [profile("a", [tcp("deny")], sni="tls_termination")], host="localhost", terminate=True, denied=True)

            target = f"127.0.0.1:{persistent.server_address[1]}"
            with connect(port, target, [profile("changing", [tcp("allow")])], True) as old:
                old.sendall(b"first\n")
                reader = old.makefile("rb")
                assert reader.readline() == b"plain:first\n"
                exercise("updated profile denies new connection while old snapshot is live",
                         [profile("changing", [tcp("deny")])], origin=persistent, denied=True, first=True)
                old.sendall(b"second\n")
                assert reader.readline() == b"plain:second\n"
                reader.close()
            exercise("released snapshot can be registered again", [profile("changing", [tcp("allow")])])
        finally:
            subprocess.run(["docker", "logs", container], check=False)
            subprocess.run(["docker", "stop", container], check=False, stdout=subprocess.DEVNULL)
            for server in servers:
                server.shutdown(); server.server_close()


if __name__ == "__main__":
    main()
