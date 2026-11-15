#!/usr/bin/env python3
# Copyright 2026 The Kruise Authors
# SPDX-License-Identifier: Apache-2.0
"""Isolated kind fixture: real LDS updates, counted DNS, TCP authorization and A/B load.

See README.md for deployment and invocation. The CONNECT policy headers are test-only.
"""
import argparse
import asyncio
import collections
import json
import os
from pathlib import Path
import socket
import struct
import time
import urllib.request

from smoke import typed, policy_store, policy_hash
from tcp_smoke import network

SLOTS = 16
ROOT = Path('/work')


def address(port):
    return {'socket_address': {'address': '0.0.0.0', 'port_value': port}}


def listeners(denied, generation):
    resources = []
    for slot in range(SLOTS):
        policy = network(True)
        policy['typed_config']['filter_config']['value']['denied_cidrs'] = denied.get(str(slot), [])
        resources.append(typed('envoy.config.listener.v3.Listener',
            internal_listener={}, metadata={'filter_metadata': {'test': {'generation': generation}}},
            listener_filters=[{'name': 'envoy.filters.listener.original_dst', 'typed_config': typed(
                'envoy.extensions.filters.listener.original_dst.v3.OriginalDst')}],
            filter_chains=[{'filters': [policy, {'name': 'envoy.filters.network.tcp_proxy', 'typed_config': typed(
                'envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy', stat_prefix=f'target-{slot}',
                cluster='pinned', idle_timeout='60s')}]}]))
        resources[-1]['name'] = f'target-{slot}'
    return {'version_info': str(generation), 'resources': resources, 'type_url': 'type.googleapis.com/envoy.config.listener.v3.Listener'}


def publish(denied, generation, build_listeners=listeners):
    temporary = ROOT / 'lds.tmp'
    temporary.write_text(json.dumps(build_listeners(denied, generation)))
    temporary.replace(ROOT / 'lds.json')


def initialize(variant='candidate'):
    publish({}, 0)
    state = {'name': 'envoy.filters.http.set_filter_state', 'typed_config': typed(
        'envoy.extensions.filters.http.set_filter_state.v3.Config', on_request_headers=[
            {'object_key': 'envoy.filters.listener.original_dst.local_ip', 'shared_with_upstream': 'ONCE',
             'format_string': {'text_format_source': {'inline_string': '%REQ(:AUTHORITY)%'}}},
            {'object_key': 'envoy.upstream.dynamic_host' if variant == 'baseline' else 'agentio.tls.outer_sni', 'factory_key': 'envoy.hashable_string', 'shared_with_upstream': 'ONCE',
             'format_string': {'text_format_source': {'inline_string': '%REQ(x-test-host)%'}}},
            # Synthetic targets must partition the internal connection pool, like production SNI.
            {'object_key': 'agentio.test.target', 'factory_key': 'envoy.hashable_string', 'shared_with_upstream': 'ONCE',
             'format_string': {'text_format_source': {'inline_string': '%REQ(x-test-host)%'}}},
            {'object_key': 'agentio.connection.policy_json', 'factory_key': 'envoy.string',
             'format_string': {'text_format_source': {'inline_string': '%REQ(x-test-connection-policy)%'}}}])}
    routes, clusters = [], []
    for slot in range(SLOTS):
        name = f'target-{slot}'
        routes.append({'match': {'connect_matcher': {}, 'headers': [{'name': 'x-test-slot', 'string_match': {'exact': str(slot)}}]},
            'route': {'cluster': name, 'timeout': '0s', 'upgrade_configs': [{'upgrade_type': 'CONNECT', 'connect_config': {}}]}})
        clusters.append({'name': name, 'type': 'STATIC', 'connect_timeout': '1s',
            'transport_socket': {'name': 'envoy.transport_sockets.internal_upstream', 'typed_config': typed(
                'envoy.extensions.transport_sockets.internal_upstream.v3.InternalUpstreamTransport',
                transport_socket={'name': 'envoy.transport_sockets.raw_buffer', 'typed_config': typed(
                    'envoy.extensions.transport_sockets.raw_buffer.v3.RawBuffer')})},
            'load_assignment': {'cluster_name': name, 'endpoints': [{'lb_endpoints': [{'endpoint': {'address': {
                'envoy_internal_address': {'server_listener_name': name}}}}]}]}})
    clusters.append({'name': 'pinned', 'type': 'ORIGINAL_DST', 'lb_policy': 'CLUSTER_PROVIDED', 'connect_timeout': '1s',
        'circuit_breakers': {'thresholds': [{'max_connections': 16384, 'max_pending_requests': 16384}]}})
    hcm = typed('envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager',
        stat_prefix='connect', delayed_close_timeout='0s', upgrade_configs=[{'upgrade_type': 'CONNECT'}],
        route_config={'name': 'connect', 'virtual_hosts': [{'name': 'all', 'domains': ['*'], 'routes': routes}]},
        http_filters=[state, policy_store(), policy_hash(), {'name': 'envoy.filters.http.router',
            'typed_config': typed('envoy.extensions.filters.http.router.v3.Router')}])
    bootstrap = {'node': {'id': 'dns-sharing', 'cluster': 'dns-sharing'}, 'admin': {'address': address(9901)},
        'bootstrap_extensions': [{'name': 'envoy.bootstrap.internal_listener', 'typed_config': typed(
            'envoy.extensions.bootstrap.internal_listener.v3.InternalListener')}],
        'dynamic_resources': {'lds_config': {'path_config_source': {'path': '/work/lds.json'}, 'resource_api_version': 'V3'}},
        'static_resources': {'listeners': [{'name': 'connect', 'address': address(18000), 'filter_chains': [{'filters': [
            {'name': 'envoy.filters.network.http_connection_manager', 'typed_config': hcm}]}]}], 'clusters': clusters}}
    (ROOT / 'envoy.json').write_text(json.dumps(bootstrap))


def process_stats():
    for proc in Path('/proc').iterdir():
        if proc.name.isdigit():
            try:
                if (proc / 'comm').read_text().strip() != 'envoy':
                    continue
                status = dict(line.split(':', 1) for line in (proc / 'status').read_text().splitlines() if ':' in line)
                stat = (proc / 'stat').read_text().split()
                return {'pid': int(proc.name), 'threads': int(status['Threads']),
                    'rss_kib': int(status['VmRSS'].split()[0]),
                    'cpu_seconds': (int(stat[13]) + int(stat[14])) / os.sysconf('SC_CLK_TCK')}
            except FileNotFoundError:
                continue
    raise RuntimeError('Envoy process not found')


async def serve(build_listeners=listeners, dns_addresses=lambda name, count: ["127.0.0.1"], publish_resources=publish):
    counts = collections.Counter()
    origin = {'accepted': 0}
    generation = 0

    class DNS(asyncio.DatagramProtocol):
        def connection_made(self, transport):
            self.transport = transport

        def datagram_received(self, data, peer):
            offset, labels = 12, []
            while data[offset]:
                size = data[offset]
                labels.append(data[offset + 1:offset + size + 1].decode())
                offset += size + 1
            name = '.'.join(labels)
            offset += 1
            qtype, _ = struct.unpack('!HH', data[offset:offset + 4])
            counts[name] += 1
            missing = name.startswith('missing.')
            answer = qtype == 1 and not missing
            flags = 0x8183 if missing else 0x8180
            addresses = dns_addresses(name, counts[name]) if answer else []
            response = data[:2] + struct.pack('!HHHHH', flags, 1, len(addresses), 0, 0) + data[12:offset + 4]
            if answer:
                ttl = 1 if name.startswith('ttl.') else 300
                for ip in addresses:
                    response += b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, ttl, 4) + socket.inet_aton(ip)
            if name.startswith('slow.'):
                asyncio.get_running_loop().call_later(.25, self.transport.sendto, response, peer)
            else:
                self.transport.sendto(response, peer)

    async def echo(reader, writer):
        origin['accepted'] += 1
        try:
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
                if data == b'close\n':
                    break
        except ConnectionError:
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    async def admin(reader, writer):
        nonlocal generation
        try:
            header = await reader.readuntil(b'\r\n\r\n')
            lines = header.decode().split('\r\n')
            method, path, _ = lines[0].split()
            headers = dict(line.lower().split(': ', 1) for line in lines[1:] if ': ' in line)
            if method == 'POST' and path == '/update':
                denied = json.loads(await reader.readexactly(int(headers['content-length'])))
                generation += 1
                publish_resources(denied, generation, build_listeners)
                response = {'generation': generation}
            elif path == '/state':
                response = {'dns': dict(counts), 'origin': origin.copy(), 'process': process_stats()}
            else:
                raise ValueError(path)
            body = json.dumps(response).encode()
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ' + str(len(body)).encode() + b'\r\nConnection: close\r\n\r\n' + body)
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(DNS, local_addr=('0.0.0.0', 53))
    servers = [await asyncio.start_server(echo, '0.0.0.0', 18080), await asyncio.start_server(admin, '0.0.0.0', 18081)]
    async with servers[0], servers[1]:
        await asyncio.Future()


def get(host, port, path, body=None):
    request = urllib.request.Request(f'http://{host}:{port}{path}', data=None if body is None else json.dumps(body).encode(),
                                    headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)


async def tunnel(host, slot, name, profiles=None, denied=False):
    reader, writer = await asyncio.open_connection(host, 18000)
    policy = json.dumps({'profiles': [] if profiles is None else profiles}, separators=(',', ':'))
    writer.write((f'CONNECT 192.0.2.254:18080 HTTP/1.1\r\nHost: 192.0.2.254:18080\r\n'
                  f'x-test-slot: {slot}\r\nx-test-host: {name}\r\nx-test-connection-policy: {policy}\r\n\r\n').encode())
    await writer.drain()
    response = await reader.readuntil(b'\r\n\r\n')
    if not response.startswith(b'HTTP/1.1 200'):
        writer.close()
        await writer.wait_closed()
        if denied and response.startswith(b'HTTP/1.1 503 '):
            return None
        raise AssertionError(response)
    return reader, writer


async def exchange(host, slot, name, profiles=None, denied=False, close=False):
    connection = await tunnel(host, slot, name, profiles, denied=denied)
    if connection is None:
        return  # A cached denial can reject the internal connection before CONNECT responds 200.
    reader, writer = connection
    try:
        payload = b'close\n' if close else b'ping\n'
        writer.write(payload)
        await writer.drain()
        response = await reader.read(1) if denied else await reader.readexactly(len(payload))
        assert response == (b'' if denied else payload), (slot, name, denied, response)
        if close:
            assert await reader.read(1) == b''
    except (ConnectionResetError, BrokenPipeError):
        if not denied:
            raise
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionResetError, BrokenPipeError):
            if not denied:
                raise


def update(host, denied):
    version = str(get(host, 18081, '/update', denied)['generation'])
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        dump = get(host, 9901, '/config_dump')
        configs = [c for c in dump['configs'] if c['@type'].endswith('ListenersConfigDump')]
        active = configs[0].get('dynamic_listeners', [])
        if len(active) == SLOTS and all(c.get('active_state', {}).get('version_info') == version for c in active):
            return
        time.sleep(.05)
    raise AssertionError(f'LDS version {version} not active')


async def verify(host):
    state = lambda: get(host, 18081, '/state')
    update(host, {})
    start = state()
    name = f'shared-{time.time_ns()}.test'
    await exchange(host, 0, name)
    warm = state()
    assert warm['dns'].get(name) == 1, warm
    for slot in range(1, SLOTS):
        await exchange(host, slot, name)
    assert state()['dns'][name] == 1, 'different filter configs do not share cached answers'
    retained_reader, retained_writer = await tunnel(host, 0, name)
    retained_writer.write(b'before\n')
    await retained_writer.drain()
    assert await retained_reader.readexactly(7) == b'before\n'
    for iteration in range(20):
        update(host, {'0': ['127.0.0.0/8']})
        before = state()['origin']['accepted']
        await exchange(host, 0, name, denied=True)
        assert state()['origin']['accepted'] == before, 'denied connection touched origin'
        await exchange(host, 1, name)
        update(host, {})
        await exchange(host, 0, name)
        current = state()
        assert current['dns'][name] == 1, 'LDS update discarded cached answers'
        assert current['process']['threads'] == start['process']['threads'], current
    retained_writer.write(b'after\n')
    await retained_writer.drain()
    assert await retained_reader.readexactly(6) == b'after\n'
    retained_writer.close()
    await retained_writer.wait_closed()
    # Different profile snapshots must not reuse another connection's authorization.
    deny = [{'uid': 'deny', 'tcpPolicy': {'rules': [{'name': 'deny-loopback', 'match': [{'cidrs': ['127.0.0.0/8']}], 'action': 'TCP_ACTION_DENY'}]}}]
    before = state()['origin']['accepted']
    await exchange(host, 0, name, profiles=deny, denied=True)
    assert state()['origin']['accepted'] == before
    await exchange(host, 0, name)
    before = state()['origin']['accepted']
    await exchange(host, 0, f'missing.{time.time_ns()}.test', denied=True)
    assert state()['origin']['accepted'] == before
    short = f'ttl.{time.time_ns()}.test'
    await exchange(host, 0, short)
    await asyncio.sleep(1.2)
    await exchange(host, 1, short)
    assert state()['dns'][short] == 2, 'shared cache ignored DNS TTL'
    slow = f'slow.{time.time_ns()}.test'
    readers_writers = await asyncio.gather(*(tunnel(host, slot % SLOTS, slow) for slot in range(32)))
    for _, writer in readers_writers[:16]:
        writer.close()
    for reader, writer in readers_writers[16:]:
        writer.write(b'ok\n')
        await writer.drain()
        assert await reader.readexactly(3) == b'ok\n'
        writer.close()
    await asyncio.gather(*(writer.wait_closed() for _, writer in readers_writers))
    await asyncio.sleep(.5)
    end = state()
    assert end['process']['pid'] == start['process']['pid'], 'Envoy restarted'
    assert end['process']['threads'] == start['process']['threads'], (start, end)
    print(json.dumps({'result': 'PASS', 'checks': ['16 configs share cache', '40 LDS updates preserve cache and threads',
        'deny blocks before origin', 'other config remains allowed', 'existing connection survives',
        'profile snapshots isolated', 'DNS failure denies', 'TTL expires', 'cancellation isolated'], 'before': start, 'after': end}))


async def bench(host, seconds, concurrency, mode):
    # Warm each config equally; cold mode then uses a unique name per connection.
    for slot in range(SLOTS):
        await exchange(host, slot, 'bench.test')
    before = get(host, 18081, '/state')
    deadline = time.monotonic() + seconds
    latencies, errors, transferred = [], collections.Counter(), 0
    prefix = str(time.time_ns())

    async def worker(worker_id):
        nonlocal transferred
        counter = 0
        reader = writer = None
        try:
            if mode == 'stream':
                reader, writer = await tunnel(host, worker_id % SLOTS, 'bench.test')
            while time.monotonic() < deadline:
                start = time.monotonic()
                try:
                    if mode == 'stream':
                        payload = b'x' * 16384
                        writer.write(payload)
                        await writer.drain()
                        assert await reader.readexactly(len(payload)) == payload
                        transferred += len(payload)
                    else:
                        name = 'bench.test'
                        if mode == 'cold':
                            name = f'{prefix}-{worker_id}-{counter}.test'
                        elif mode == 'many':
                            name = f'pool-{worker_id % SLOTS}-{counter % 64}.test'
                        await exchange(host, worker_id % SLOTS, name, close=True)
                    latencies.append((time.monotonic() - start) * 1000)
                except (OSError, AssertionError, asyncio.IncompleteReadError) as error:
                    errors[f'{type(error).__name__}: {error}'] += 1
                counter += 1
        finally:
            if writer:
                writer.close()
                await writer.wait_closed()

    start = time.monotonic()
    await asyncio.gather(*(worker(i) for i in range(concurrency)))
    elapsed = time.monotonic() - start
    after = get(host, 18081, '/state')
    if mode == 'cold':
        assert sum(v for k, v in after['dns'].items() if k.startswith(prefix + '-')) >= len(latencies), \
            'unique targets did not each perform DNS resolution'
    latencies.sort()
    pct = lambda p: latencies[min(len(latencies) - 1, int(len(latencies) * p))] if latencies else None
    print(json.dumps({'mode': mode, 'concurrency': concurrency, 'seconds': elapsed, 'requests': len(latencies),
        'errors': dict(errors), 'rps': len(latencies) / elapsed, 'p50_ms': pct(.5), 'p95_ms': pct(.95), 'p99_ms': pct(.99),
        'mib_s': transferred / elapsed / 1048576,
        'envoy_cpu_cores': (after['process']['cpu_seconds'] - before['process']['cpu_seconds']) / elapsed,
        'dns_queries': sum(after['dns'].values()) - sum(before['dns'].values()),
        'before': before['process'], 'after': after['process']}))
    assert not errors, errors


def manifest(baseline, candidate, namespace, script="shared_dns_kind.py"):
    files = {name: Path(__file__).with_name(name).read_text() for name in dict.fromkeys(['shared_dns_kind.py', 'smoke.py', 'tcp_smoke.py', script])}
    resources = [{'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': namespace, 'labels': {'istio-injection': 'disabled'}}},
        {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'fixture', 'namespace': namespace}, 'data': files}]
    mounts = [{'name': 'scripts', 'mountPath': '/scripts'}, {'name': 'work', 'mountPath': '/work'}]
    for name, image in [('baseline', baseline), ('candidate', candidate)]:
        resources.append({'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': name, 'namespace': namespace, 'labels': {'app': name},
            'annotations': {'sidecar.istio.io/inject': 'false'}}, 'spec': {'shareProcessNamespace': True,
            'dnsPolicy': 'None', 'dnsConfig': {'nameservers': ['127.0.0.1'], 'options': [{'name': 'ndots', 'value': '1'}]},
            'volumes': [{'name': 'scripts', 'configMap': {'name': 'fixture'}}, {'name': 'work', 'emptyDir': {}}],
            'initContainers': [{'name': 'init', 'image': 'python:3.13-alpine', 'imagePullPolicy': 'Never', 'volumeMounts': mounts,
                'command': ['python3', f'/scripts/{script}', 'init', '--variant', name]}],
            'containers': [{'name': 'envoy', 'image': image, 'imagePullPolicy': 'Never', 'volumeMounts': mounts,
                'command': ['envoy', '-c', '/work/envoy.json', '--concurrency', '2', '--log-level', 'error', '--drain-time-s', '60'],
                'resources': {'requests': {'cpu': '2', 'memory': '256Mi'}, 'limits': {'cpu': '2', 'memory': '1Gi'}},
                'readinessProbe': {'httpGet': {'path': '/ready', 'port': 9901}}},
                {'name': 'fixture', 'image': 'python:3.13-alpine', 'imagePullPolicy': 'Never', 'volumeMounts': mounts,
                 'command': ['python3', f'/scripts/{script}', 'serve', '--variant', name],
                 'readinessProbe': {'tcpSocket': {'port': 18081}},
                 'resources': {'requests': {'cpu': '1', 'memory': '64Mi'}, 'limits': {'cpu': '2', 'memory': '512Mi'}}}]}})
    resources.append({'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': 'loadgen', 'namespace': namespace,
        'annotations': {'sidecar.istio.io/inject': 'false'}}, 'spec': {'containers': [{'name': 'loadgen', 'image': 'python:3.13-alpine',
        'imagePullPolicy': 'Never', 'command': ['sleep', 'infinity'], 'volumeMounts': [{'name': 'scripts', 'mountPath': '/scripts'}],
        'resources': {'requests': {'cpu': '2', 'memory': '128Mi'}, 'limits': {'cpu': '4', 'memory': '1Gi'}}}],
        'volumes': [{'name': 'scripts', 'configMap': {'name': 'fixture'}}]}})
    print(json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': resources}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['init', 'serve', 'manifest', 'verify', 'bench'])
    parser.add_argument('--host')
    parser.add_argument('--variant')
    parser.add_argument('--baseline')
    parser.add_argument('--candidate')
    parser.add_argument('--namespace', default='agentio-dns-sharing')
    parser.add_argument('--seconds', type=int, default=10)
    parser.add_argument('--concurrency', type=int, default=32)
    parser.add_argument('--mode', choices=['warm', 'cold', 'many', 'stream'], default='warm')
    args = parser.parse_args()
    if args.command == 'init':
        initialize(args.variant)
    elif args.command == 'manifest':
        manifest(args.baseline, args.candidate, args.namespace)
    elif args.command == 'serve':
        asyncio.run(serve())
    elif args.command == 'verify':
        asyncio.run(asyncio.wait_for(verify(args.host), 90))
    else:
        asyncio.run(asyncio.wait_for(bench(args.host, args.seconds, args.concurrency, args.mode), args.seconds + 30))


if __name__ == '__main__':
    main()
