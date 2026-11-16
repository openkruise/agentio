#!/usr/bin/env python3
# Copyright 2026 The Kruise Authors
# SPDX-License-Identifier: Apache-2.0
"""Real Envoy HTTP egress authorization, RDS replacement and A/B load in kind."""
import argparse
import asyncio
import collections
import json
import os
import time

import shared_dns_kind as base
from smoke import typed

VARIANT = 'candidate'
CACHE = {'name': 'egress_dns', 'dns_lookup_family': 'V4_ONLY', 'max_hosts': 16384}


def policy(mode, denied):
    settings = {'mode': mode, 'denied_cidrs': denied, 'default_port': 80}
    if VARIANT == 'candidate':
        settings['dns'] = {'max_hosts': 16384, 'max_pending_requests': int(os.environ.get('TEST_DNS_PENDING', '4096'))}
    return typed('envoy.extensions.filters.http.dynamic_modules.v3.DynamicModuleFilterPerRoute',
        dynamic_module_config={'name': 'envoy_agentio_connection_policy', 'do_not_close': True},
        filter_name='envoy_agentio_egress_authorization',
        filter_config=typed('google.protobuf.Struct', value=settings))


def routes(slot, denied):
    connect = {'match': {'connect_matcher': {}}, 'route': {'cluster': 'original', 'timeout': '0s'}}
    config = {'name': f'egress-{slot}', 'virtual_hosts': [{'name': 'all', 'domains': ['*'], 'routes': [connect,
        {'match': {'prefix': '/'}, 'route': {'cluster': 'dfp', 'timeout': '5s'}}]}]}
    if VARIANT in ('candidate', 'baseline'):
        config['typed_per_filter_config'] = {'authorization': policy('DYNAMIC_FORWARD', denied)}
        connect['typed_per_filter_config'] = {'authorization': policy('ORIGINAL_DST', denied)}
    return config


def publish(denied, generation, unused=None):
    for slot in range(base.SLOTS):
        config = routes(slot, ['127.0.0.2/32'] + denied.get(str(slot), []))
        config['metadata'] = {'filter_metadata': {'test': {'generation': generation}}}
        config['@type'] = 'type.googleapis.com/envoy.config.route.v3.RouteConfiguration'
        data = {'version_info': str(generation), 'resources': [config],
                'type_url': 'type.googleapis.com/envoy.config.route.v3.RouteConfiguration'}
        temporary = base.ROOT / f'rds-{slot}.tmp'
        temporary.write_text(json.dumps(data))
        temporary.replace(base.ROOT / f'rds-{slot}.json')


def update(host, denied):
    version = str(base.get(host, 18081, '/update', denied)['generation'])
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        dump = base.get(host, 9901, '/config_dump')
        configs = [c for c in dump['configs'] if c['@type'].endswith('RoutesConfigDump')]
        active = [r for config in configs for r in config.get('dynamic_route_configs', [])]
        if len(active) == base.SLOTS and all(c.get('version_info') == version for c in active):
            return
        time.sleep(.05)
    raise AssertionError(f'RDS version {version} not active')


def listeners(denied, generation):
    resources = []
    for slot in range(base.SLOTS):
        ranges = ['127.0.0.2/32'] + denied.get(str(slot), [])
        cache = dict(CACHE)
        values = []
        for key, header, readonly in [('agentio.route.upstream' if VARIANT == 'candidate' else 'envoy.upstream.dynamic_host', 'x-test-target', False),
                ('envoy.filters.listener.original_dst.local_ip', 'x-test-original', True)]:
            values.append({'object_key': key, **({'factory_key': 'envoy.string'} if key == 'agentio.route.upstream' else {}), 'skip_if_empty': True, 'read_only': readonly,
                'format_string': {'omit_empty_values': True, 'text_format_source': {'inline_string': f'%REQ({header})%'}}})
        filters = [{'name': 'target', 'typed_config': typed('envoy.extensions.filters.http.set_filter_state.v3.Config', on_request_headers=values)}]
        if VARIANT in ('candidate', 'baseline'):
            filters.append({'name': 'authorization', 'typed_config': typed(
                'envoy.extensions.filters.http.dynamic_modules.v3.DynamicModuleFilter',
                dynamic_module_config={'name': 'envoy_agentio_connection_policy', 'do_not_close': True},
                filter_name='envoy_agentio_egress_authorization')})
        filters.extend([{'name': 'envoy.filters.http.dynamic_forward_proxy', 'typed_config': typed(
            'envoy.extensions.filters.http.dynamic_forward_proxy.v3.FilterConfig', dns_cache_config=cache,
            allow_dynamic_host_from_filter_state=True)}, {'name': 'envoy.filters.http.router', 'typed_config': typed(
            'envoy.extensions.filters.http.router.v3.Router')}])
        if VARIANT == 'candidate':
            filters = [f for f in filters if f['name'] != 'envoy.filters.http.dynamic_forward_proxy']
        hcm = typed('envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager', stat_prefix=f'http-{slot}',
            codec_type='AUTO', http2_protocol_options={}, delayed_close_timeout='0s', upgrade_configs=[{'upgrade_type': 'CONNECT'}],
            rds={'route_config_name': f'egress-{slot}', 'config_source': {'path_config_source': {'path': f'/work/rds-{slot}.json'}, 'resource_api_version': 'V3'}}, http_filters=filters)
        resources.append(typed('envoy.config.listener.v3.Listener', address=base.address(18000 + slot),
            metadata={'filter_metadata': {'test': {'generation': generation}}},
            filter_chains=[{'filters': [{'name': 'envoy.filters.network.http_connection_manager', 'typed_config': hcm}]}]))
        resources[-1]['name'] = f'http-{slot}'
    return {'version_info': str(generation), 'resources': resources, 'type_url': 'type.googleapis.com/envoy.config.listener.v3.Listener'}


def initialize():
    cache = dict(CACHE)
    cluster = {'name': 'dfp', 'connect_timeout': '1s', 'lb_policy': 'CLUSTER_PROVIDED',
        'cluster_type': {'name': 'envoy.clusters.dynamic_forward_proxy', 'typed_config': typed(
            'envoy.extensions.clusters.dynamic_forward_proxy.v3.ClusterConfig', dns_cache_config=cache, allow_insecure_cluster_options=True)},
        'typed_extension_protocol_options': {'envoy.extensions.upstreams.http.v3.HttpProtocolOptions': typed(
            'envoy.extensions.upstreams.http.v3.HttpProtocolOptions', explicit_http_config={'http_protocol_options': {}})}}
    if VARIANT == 'candidate':
        cluster.pop('cluster_type')
        cluster['type'] = 'ORIGINAL_DST'
    bootstrap = {'node': {'id': 'egress-http', 'cluster': 'egress-http'}, 'admin': {'address': base.address(9901)},
        'dynamic_resources': {'lds_config': {'path_config_source': {'path': '/work/lds.json'}, 'resource_api_version': 'V3'}},
        'static_resources': {'clusters': [cluster, {'name': 'original', 'type': 'ORIGINAL_DST', 'lb_policy': 'CLUSTER_PROVIDED', 'connect_timeout': '1s'}]}}
    publish({}, 0)
    base.publish({}, 0, listeners)
    (base.ROOT / 'envoy.json').write_text(json.dumps(bootstrap))


def answers(name, count):
    if name.startswith('deny.') or (name.startswith('ttl.rebind.') and count > 1):
        return ['127.0.0.2']
    if name.startswith('mixed.'):
        return ['127.0.0.2', '127.0.0.1']
    return ['127.0.0.1']


async def serve():
    requests = 0
    async def origin(reader, writer):
        nonlocal requests
        try:
            while True:
                try:
                    raw = await reader.readuntil(b'\r\n\r\n')
                except asyncio.IncompleteReadError:
                    break
                lines = raw.decode().split('\r\n')
                method, path, _ = lines[0].split()
                headers = dict(line.lower().split(': ', 1) for line in lines[1:] if ': ' in line)
                body = await reader.readexactly(int(headers.get('content-length', 0)))
                if path != '/stats':
                    requests += 1
                if path == '/slow':
                    await asyncio.sleep(.4)
                data = json.dumps({'host': headers.get('host'), 'path': path, 'body_bytes': len(body), 'requests': requests, 'local_ip': writer.get_extra_info('sockname')[0]}).encode()
                writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(data)).encode() + b'\r\n\r\n' + data)
                await writer.drain()
                if headers.get('connection') == 'close' or method == 'CONNECT':
                    break
        finally:
            writer.close()
            await writer.wait_closed()
    server = await asyncio.start_server(origin, '0.0.0.0', 18082)
    async with server:
        await base.serve(listeners, answers, publish)


async def request(host, authority, headers=None, connection=None, method='GET', path='/', body=b'', slot=0):
    owned = connection is None
    reader, writer = connection or await asyncio.open_connection(host, 18000 + slot)
    lines = [f'{method} {authority if method == "CONNECT" else path} HTTP/1.1', f'Host: {authority}', f'Content-Length: {len(body)}']
    lines += [f'{k}: {v}' for k, v in (headers or {}).items()]
    if owned and method != 'CONNECT':
        lines.append('Connection: close')
    writer.write(('\r\n'.join(lines) + '\r\n\r\n').encode() + body)
    await writer.drain()
    raw = await reader.readuntil(b'\r\n\r\n')
    status = int(raw.split(b' ', 2)[1])
    fields = dict(line.lower().split(b': ', 1) for line in raw.split(b'\r\n')[1:] if b': ' in line)
    data = await reader.readexactly(int(fields.get(b'content-length', 0)))
    if owned:
        if method != 'CONNECT':
            assert await reader.read(1) == b''
        writer.close()
        await writer.wait_closed()
    return status, json.loads(data) if data.startswith(b'{') else data


async def verify(host):
    state = lambda: base.get(host, 18081, '/state')
    origin_count = lambda: base.get(host, 18082, '/stats')['requests']
    update(host, {})
    name = f'shared-{time.time_ns()}.test'
    for slot in range(base.SLOTS):
        code, body = await request(host, name + ':18082', slot=slot)
        assert code == 200 and body['host'] == name + ':18082', (code, body)
    assert state()['dns'][name] == 1
    connection = await asyncio.open_connection(host, 18000)
    for authority, expected in [('127.0.0.1:18082', 200), ('127.0.0.2:18082', 403), ('[::ffff:127.0.0.2]:18082', 403), (name + ':18082', 200)]:
        before = origin_count()
        code, _ = await request(host, authority, connection=connection)
        assert code == expected, (authority, code)
        if expected == 403:
            assert origin_count() == before
    connection[1].close()
    await connection[1].wait_closed()
    for authority, headers, expected in [('missing.test:18082', {'x-test-target': '127.0.0.1:18082', 'x-test-port': '1'}, 200),
            (name + ':18082', {'x-test-target': '127.0.0.2:18082'}, 403),
            (name + ':1', {'x-test-target': '127.0.0.1:18082'}, 200),
            ('deny.test:18082', {}, 403), ('mixed.test:18082', {}, 200), ('missing.test:18082', {}, 503)]:
        before = origin_count()
        code, body = await request(host, authority, headers)
        assert code == expected, (authority, headers, code, body)
        if expected != 200:
            assert origin_count() == before
    for ip, expected in [('127.0.0.1', 200), ('127.0.0.2', 403)]:
        code, _ = await request(host, 'inner.invalid:443', {'x-test-original': f'{ip}:18082', 'x-test-target': '127.0.0.2:1'}, method='CONNECT')
        assert code == expected, (ip, code)
    code, body = await request(host, f'slow.body.{time.time_ns()}.test:18082', method='POST', body=b'x' * 65536)
    assert code == 200 and body['body_bytes'] == 65536
    before = origin_count()
    assert (await request(host, f'deny.body.{time.time_ns()}.test:18082', method='POST', body=b'x' * 65536))[0] == 403
    assert origin_count() == before
    start = state()['process']
    keepalive = await asyncio.open_connection(host, 18000)
    assert (await request(host, name + ':18082', connection=keepalive))[0] == 200
    for _ in range(20):
        update(host, {'0': ['127.0.0.1/32']})
        before = origin_count()
        assert (await request(host, name + ':18082', connection=keepalive))[0] == 403
        assert (await request(host, name + ':18082'))[0] == 403
        assert origin_count() == before
        assert (await request(host, name + ':18082', slot=1))[0] == 200
        update(host, {})
        assert (await request(host, name + ':18082', connection=keepalive))[0] == 200
        assert state()['dns'][name] == 1
        assert state()['process']['threads'] == start['threads']
    keepalive[1].close()
    await keepalive[1].wait_closed()
    slow = asyncio.create_task(request(host, name + ':18082', path='/slow'))
    await asyncio.sleep(.1)
    update(host, {'0': ['127.0.0.1/32']})
    assert (await slow)[0] == 200
    assert (await request(host, name + ':18082'))[0] == 403
    # A rejected RDS update must leave the last accepted deny policy active.
    rejected_before = sum(s['value'] for s in base.get(host, 9901, '/stats?format=json&filter=update_rejected')['stats']
                          if s['name'].endswith('.update_rejected'))
    base.get(host, 18081, '/update', {'0': ['invalid']})
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        rejected = sum(s['value'] for s in base.get(host, 9901, '/stats?format=json&filter=update_rejected')['stats']
                       if s['name'].endswith('.update_rejected'))
        if rejected > rejected_before: break
        await asyncio.sleep(.05)
    else: raise AssertionError('invalid RDS was not rejected')
    before = origin_count()
    assert (await request(host, name + ':18082'))[0] == 403
    assert origin_count() == before
    update(host, {})
    # DNS already in flight keeps its request snapshot; the next request uses the update.
    slow_name = f'slow.{time.time_ns()}.test:18082'
    pending = asyncio.create_task(request(host, slow_name))
    await asyncio.sleep(.05)
    update(host, {'0': ['127.0.0.1/32']})
    assert (await pending)[0] == 200
    assert (await request(host, slow_name))[0] == 403
    update(host, {})
    # A different spelling can hit Hickory's cache with a rounded remaining TTL.
    ttl_name = f'ttl.cache-rounding.{time.time_ns()}.test'
    alternate = ttl_name[:-4] + 'TEST'
    query_count = lambda: sum(n for key, n in state()['dns'].items() if key.lower() == ttl_name)
    assert (await request(host, ttl_name + ':18082'))[0] == 200
    await asyncio.sleep(.65)
    assert (await request(host, alternate + ':18082'))[0] == 200
    assert query_count() == 1
    await asyncio.sleep(.5)
    assert (await request(host, alternate + ':18082'))[0] == 200
    assert query_count() == 2
    rebind = f'ttl.rebind.{time.time_ns()}.test'
    assert (await request(host, rebind + ':18082'))[0] == 200
    await asyncio.sleep(1.2)
    before = origin_count()
    assert (await request(host, rebind + ':18082'))[0] == 403
    assert origin_count() == before and state()['dns'][rebind] == 2
    final = state()
    assert start['pid'] == final['process']['pid'] and start['threads'] == final['process']['threads']
    print(json.dumps({'result': 'PASS', 'checks': ['literal and mapped IPv6 denial', 'per-request keepalive authorization',
        'hostname and port precedence', 'original proxy CONNECT', 'Host preserved', 'request body buffering',
        '16 configs share DNS', '40 RDS replacements update existing keepalive connections and preserve cache and threads', 'deny before origin',
        'other config isolated', 'invalid RDS retains accepted policy', 'in-flight DNS snapshot survives', 'in-flight request survives', 'DNS rebinding denied', 'cached TTL is not extended', 'mixed answers', 'DNS failure'],
        'before': start, 'after': final['process'], 'queries': {name: final['dns'][name], rebind: final['dns'][rebind]}}))


async def bench(host, mode, concurrency, seconds):
    for slot in range(base.SLOTS):
        assert (await request(host, 'bench.test:18082', slot=slot))[0] == 200
    before = base.get(host, 18081, '/state')
    deadline = time.monotonic() + seconds
    prefix = str(time.time_ns())
    latencies, errors = [], collections.Counter()
    async def worker(i):
        connection = await asyncio.open_connection(host, 18000 + i % base.SLOTS)
        counter = 0
        try:
            while time.monotonic() < deadline:
                name = '127.0.0.1' if mode == 'literal' else 'bench.test'
                if mode == 'cold': name = f'{prefix}-{i}-{counter}.test'
                elif mode == 'many': name = f'pool-{i % 16}-{counter % 64}.test'
                start = time.monotonic()
                try:
                    code, _ = await request(host, name + ':18082', connection=connection,
                        method='POST' if mode == 'body' else 'GET', body=b'x' * 16384 if mode == 'body' else b'')
                    assert code == 200, code
                    latencies.append((time.monotonic() - start) * 1000)
                except (OSError, AssertionError, asyncio.IncompleteReadError) as error:
                    errors[f'{type(error).__name__}: {error}'] += 1
                    break
                counter += 1
        finally:
            connection[1].close()
            await connection[1].wait_closed()
    start = time.monotonic()
    await asyncio.gather(*(worker(i) for i in range(concurrency)))
    elapsed = time.monotonic() - start
    after = base.get(host, 18081, '/state')
    if mode == 'cold':
        assert sum(v for k, v in after['dns'].items() if k.startswith(prefix + '-')) >= len(latencies)
    latencies.sort()
    pct = lambda p: latencies[min(len(latencies) - 1, int(len(latencies) * p))] if latencies else None
    print(json.dumps({'mode': mode, 'concurrency': concurrency, 'seconds': elapsed, 'requests': len(latencies),
        'errors': dict(errors), 'rps': len(latencies) / elapsed, 'p50_ms': pct(.5), 'p95_ms': pct(.95), 'p99_ms': pct(.99),
        'envoy_cpu_cores': (after['process']['cpu_seconds'] - before['process']['cpu_seconds']) / elapsed,
        'dns_queries': sum(after['dns'].values()) - sum(before['dns'].values()), 'before': before['process'], 'after': after['process']}))
    assert not errors


async def verify_h2(host):
    from h2.config import H2Configuration
    from h2.connection import H2Connection
    from h2.events import ResponseReceived, DataReceived, StreamEnded, ConnectionTerminated
    from h2.errors import ErrorCodes
    update(host, {})
    reader, writer = await asyncio.open_connection(host, 18000)
    h2 = H2Connection(config=H2Configuration(client_side=True, header_encoding='utf-8'))
    h2.initiate_connection()
    writer.write(h2.data_to_send())
    def send(authority):
        stream = h2.get_next_available_stream_id()
        h2.send_headers(stream, [(':method', 'GET'), (':scheme', 'http'), (':authority', authority), (':path', '/')], end_stream=True)
        return stream
    async def receive(expected, destinations=None):
        statuses, done, bodies = {}, set(), collections.defaultdict(bytes)
        writer.write(h2.data_to_send()); await writer.drain()
        while done != set(expected):
            data = await reader.read(65536)
            assert data, 'HTTP/2 connection closed'
            for event in h2.receive_data(data):
                if isinstance(event, ResponseReceived): statuses[event.stream_id] = int(dict(event.headers)[':status'])
                elif isinstance(event, DataReceived):
                    h2.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    bodies[event.stream_id] += event.data
                elif isinstance(event, StreamEnded): done.add(event.stream_id)
                elif isinstance(event, ConnectionTerminated): raise AssertionError(event)
            writer.write(h2.data_to_send()); await writer.drain()
        assert statuses == expected, statuses
        if destinations:
            for stream, ip in destinations.items():
                assert json.loads(bodies[stream])['local_ip'] == ip, bodies[stream]
    expected = {send('127.0.0.1:18082' if i % 2 else '127.0.0.2:18082'): 200 if i % 2 else 403 for i in range(64)}
    await receive(expected)
    destinations = {send(f'127.0.0.{1 if i % 2 else 3}:18082'): f'127.0.0.{1 if i % 2 else 3}' for i in range(64)}
    await receive({stream: 200 for stream in destinations}, destinations)
    for _ in range(10):
        update(host, {'0': ['127.0.0.1/32']})
        before = base.get(host, 18082, '/stats')['requests']
        await receive({send('127.0.0.1:18082'): 403})
        assert base.get(host, 18082, '/stats')['requests'] == before
        update(host, {})
        await receive({send('127.0.0.1:18082'): 200})
    slow = f'slow.{time.time_ns()}.test:18082'
    cancelled, survivor = send(slow), send(slow)
    writer.write(h2.data_to_send()); await writer.drain()
    await asyncio.sleep(.05)
    h2.reset_stream(cancelled, error_code=ErrorCodes.CANCEL)
    await receive({survivor: 200})
    writer.close(); await writer.wait_closed()
    print(json.dumps({'result': 'PASS', 'checks': ['64 concurrent HTTP/2 streams authorize independently', '64 allowed streams dial their individual IPs',
        '20 RDS updates affect new streams on the same HTTP/2 connection', 'cancelled DNS stream does not cancel another stream']}))


async def verify_limit(host):
    update(host, {})
    warm = f'warm.budget.{time.time_ns()}.test:18082'
    assert (await request(host, warm))[0] == 200
    slow = f'slow.budget.{time.time_ns()}.test:18082'
    pending = asyncio.create_task(request(host, slow))
    await asyncio.sleep(.05)
    # Another listener shares the same process-wide admission budget.
    assert (await request(host, f'slow.second.{time.time_ns()}.test:18082', slot=1))[0] == 503
    assert (await request(host, warm))[0] == 200
    update(host, {})
    assert (await request(host, f'slow.third.{time.time_ns()}.test:18082', slot=2))[0] == 503
    assert (await pending)[0] == 200
    assert (await request(host, f'slow.after.{time.time_ns()}.test:18082'))[0] == 200
    reader, writer = await asyncio.open_connection(host, 18000)
    writer.write(f'GET / HTTP/1.1\r\nHost: slow.cancel.{time.time_ns()}.test:18082\r\n\r\n'.encode())
    await writer.drain(); await asyncio.sleep(.05)
    writer.close(); await writer.wait_closed(); await asyncio.sleep(.05)
    assert (await request(host, f'slow.released.{time.time_ns()}.test:18082'))[0] == 200
    print(json.dumps({'result': 'PASS', 'checks': ['pending limit shared across listeners and RDS replacements',
        'cache hits bypass pending limit', 'completion and cancellation release pending slot']}))


def main():
    global VARIANT
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('command', choices=['manifest', 'init', 'serve', 'verify', 'verify-h2', 'verify-limit', 'bench'])
    p.add_argument('--variant', default='candidate')
    p.add_argument('--baseline'); p.add_argument('--candidate'); p.add_argument('--host')
    p.add_argument('--namespace', default='agentio-egress-http')
    p.add_argument('--mode', choices=['warm', 'cold', 'many', 'body', 'literal'], default='warm')
    p.add_argument('--concurrency', type=int, default=32); p.add_argument('--seconds', type=int, default=10)
    args = p.parse_args(); VARIANT = args.variant
    if args.command == 'manifest': base.manifest(args.baseline, args.candidate, args.namespace, 'http_egress_kind.py')
    elif args.command == 'init': initialize()
    elif args.command == 'serve': asyncio.run(serve())
    elif args.command == 'verify-h2': asyncio.run(asyncio.wait_for(verify_h2(args.host), 90))
    elif args.command == 'verify-limit': asyncio.run(asyncio.wait_for(verify_limit(args.host), 30))
    elif args.command == 'verify': asyncio.run(asyncio.wait_for(verify(args.host), 90))
    else: asyncio.run(asyncio.wait_for(bench(args.host, args.mode, args.concurrency, args.seconds), args.seconds + 30))


if __name__ == '__main__': main()
