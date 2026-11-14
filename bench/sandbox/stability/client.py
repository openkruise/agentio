# Copyright 2026 The Kruise Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""Real Sandbox HTTPS load client; no automatic request retry."""
import bisect, collections, http.client, http.server, json, queue, ssl, threading, time
BOUNDS = [i / 10 for i in range(1, 201)] + [20.48 * 2 ** i for i in range(12)]
assert BOUNDS == sorted(set(BOUNDS))
LOCK = threading.Lock()
STOP = threading.Event()
JOBS = queue.Queue(maxsize=32)
CONFIG = {'rate': 0, 'domain_count': 500, 'client_index': 0, 'clients': 100, 'cold_fraction': 0.2, 'scheme': 'https', 'port': 8443, 'fault': False, 'mixed': False}

class PolicyViolation(AssertionError):
    pass
STARTED = False
STATS = {}
SEEN = set()
CERTS = {}
SAMPLES = collections.deque(maxlen=100)
COLD_SEQUENCE = 0
CONTEXT = None

def record(group, elapsed, queued, error=None, status=None, cert=None):
    with LOCK:
        s = STATS.setdefault(group, {'requests': 0, 'errors': 0, 'histogram': [0] * (len(BOUNDS) + 1), 'queue_histogram': [0] * (len(BOUNDS) + 1), 'statuses': collections.Counter(), 'error_types': collections.Counter()})
        s['requests'] += 1
        s['histogram'][bisect.bisect_left(BOUNDS, elapsed)] += 1
        s['queue_histogram'][bisect.bisect_left(BOUNDS, queued)] += 1
        if status is not None:
            s['statuses'][str(status)] += 1
        if cert:
            (host, info) = cert
            prior = CERTS.get(host)
            CERTS[host] = info
            if prior and prior['serialNumber'] != info['serialNumber']:
                SAMPLES.append({'time': time.time(), 'event': 'leaf-rotated', 'host': host, 'before': prior, 'after': info})
        if error:
            s['errors'] += 1
            s['error_types'][type(error).__name__] += 1
            SAMPLES.append({'time': time.time(), 'group': group, 'error': str(error), 'error_type': type(error).__name__, 'stage': getattr(error, 'request_stage', None)})

def worker(index):
    global COLD_SEQUENCE
    hot = None
    key = None
    opened = 0
    try:
        while not STOP.is_set() or not JOBS.empty():
            try:
                (seq, scheduled) = JOBS.get(timeout=0.2)
            except queue.Empty:
                continue
            with LOCK:
                cfg = dict(CONFIG)
            cold = seq * 37 % 100 < round(cfg['cold_fraction'] * 100)
            with LOCK:
                ordinal = COLD_SEQUENCE
                if cold:
                    COLD_SEQUENCE += 1
            host = 'host-%06d' % ((ordinal * cfg['clients'] + cfg['client_index']) % cfg['domain_count']) + '.load.test' if cold else 'hot-%02d.load.test' % (index % 8)
            with LOCK:
                first = host not in SEEN
                SEEN.add(host)
            group = 'domain-first' if first else 'long-tail' if cold else 'hot'
            path = '/deny' if seq % 10 == 7 else '/allow'
            method = 'GET'
            body = None
            if cfg['mixed'] and seq % 50 == 20:
                path = '/stream'
                group = 'stream'
            elif cfg['mixed'] and seq % 50 == 30:
                path = '/download'
                group = 'download'
            elif cfg['mixed'] and seq % 50 == 40:
                path = '/upload'
                method = 'POST'
                body = b'x' * (1 << 20)
                group = 'upload'
            elif cfg['fault'] and seq % 10 == 1:
                path = '/fault'
                group = 'fault'
            queued = (time.monotonic() - scheduled) * 1000
            start = time.monotonic()
            conn = None
            error = None
            status = None
            cert = None
            stage = 'connect'
            try:
                current = (cfg['scheme'], host, cfg['port'])
                if not cold and hot is not None and (current == key) and (hot.sock is not None) and (time.monotonic() - opened < 60):
                    conn = hot
                else:
                    conn = http.client.HTTPSConnection(host, cfg['port'], context=CONTEXT, timeout=8) if cfg['scheme'] == 'https' else http.client.HTTPConnection(host, cfg['port'], timeout=8)
                    conn.connect()
                    if cfg['scheme'] == 'https':
                        peer = conn.sock.getpeercert()
                        cert = (host, {k: peer.get(k) for k in ['serialNumber', 'notBefore', 'notAfter', 'issuer']})
                    if not cold:
                        if hot is not None:
                            hot.close()
                        hot = conn
                        key = current
                        opened = time.monotonic()
                stage = 'send'
                conn.request(method, path, body=body, headers={'Host': host + ':' + str(cfg['port']), 'X-Stability-Client': str(cfg['client_index'])})
                stage = 'headers'
                response = conn.getresponse()
                status = response.status
                stage = 'body'
                payload = response.read()
                expected = 451 if path == '/deny' and cfg.get('deny', True) else 200
                if status != expected:
                    error_class = PolicyViolation if status == 200 and expected == 451 else AssertionError
                    raise error_class('status %d expected %d, %s %s: %s' % (status, expected, host, path, payload[:200]))
                if path == '/stream' and payload.count(b'data:') != 20:
                    raise AssertionError('stream truncated')
                if path == '/download' and len(payload) != 1 << 20:
                    raise AssertionError('download truncated')
                if path == '/upload' and payload != b'uploaded:1048576':
                    raise AssertionError('upload differs')
                if path == '/allow':
                    data = json.loads(payload)
                    if data['marker'] != 'STABILITY-UPSTREAM' or data['host'] != host + ':' + str(cfg['port']):
                        raise AssertionError('upstream host or marker mismatch')
                    if cfg['scheme'] == 'https' and data.get('tls_sni') != host:
                        raise AssertionError('upstream SNI mismatch')
                    header = data['headers'].get('X-Stability-Client')
                    if header != [str(cfg['client_index'])]:
                        raise PolicyViolation('identity header changed')
                    if cfg.get('group') and data['headers'].get('X-Policy-Group') != [cfg['group']]:
                        raise PolicyViolation('policy identity group crossed')
            except (OSError, http.client.HTTPException, ValueError, AssertionError) as e:
                error = e
                error.request_stage = stage
                if conn:
                    conn.close()
            finally:
                if cold and conn:
                    conn.close()
                record(group, (time.monotonic() - start) * 1000, queued, error, status, cert)
                JOBS.task_done()
    finally:
        if hot:
            hot.close()

def run(duration):
    deadline = time.monotonic() + duration
    seq = 0
    tick = time.monotonic()
    workers = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(8)]
    for t in workers:
        t.start()
    while time.monotonic() < deadline and (not STOP.is_set()):
        with LOCK:
            rate = CONFIG['rate']
        if rate <= 0:
            STOP.wait(0.1)
            tick = time.monotonic()
            continue
        if STOP.wait(max(0, tick - time.monotonic())):
            break
        try:
            JOBS.put_nowait((seq, tick))
        except queue.Full:
            record('generator', 0, 0, RuntimeError('bounded generator queue full'))
        seq += 1
        tick += 1 / rate
    STOP.set()
    for t in workers:
        t.join()
    print(json.dumps({'event': 'run-complete', 'time': time.time(), 'stats': status()}), flush=True)

def status():
    with LOCK:
        return {'time': time.time(), 'config': dict(CONFIG), 'stopped': STOP.is_set(), 'queue': JOBS.qsize(), 'bounds_ms': BOUNDS, 'groups': json.loads(json.dumps(STATS)), 'domains_seen': len(SEEN), 'certificates': dict(CERTS), 'samples': list(SAMPLES)}

def probe(options):
    start = time.monotonic()
    conn = None
    try:
        host = options.get('host', 'hot-00.load.test')
        port = int(options.get('port', 8443))
        scheme = options.get('scheme', 'https')
        conn = http.client.HTTPSConnection(host, port, context=CONTEXT, timeout=8) if scheme == 'https' else http.client.HTTPConnection(host, port, timeout=8)
        conn.connect()
        cert = None
        if scheme == 'https':
            peer = conn.sock.getpeercert()
            cert = {k: peer.get(k) for k in ['serialNumber', 'issuer', 'notAfter']}
        conn.request('GET', options.get('path', '/allow'), headers={'Host': host + ':' + str(port)})
        r = conn.getresponse()
        body = r.read()
        return {'status': r.status, 'body': body[:4096].decode(), 'certificate': cert, 'latency_ms': (time.monotonic() - start) * 1000}
    except (OSError, http.client.HTTPException) as e:
        return {'error': str(e), 'error_type': type(e).__name__, 'latency_ms': (time.monotonic() - start) * 1000}
    finally:
        if conn:
            conn.close()

class API(http.server.BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path == '/health':
            self.respond({'healthy': True})
        elif self.path in ['/', '/status']:
            self.respond(status())
        else:
            self.respond({'error': 'unknown path'}, 404)

    def do_POST(self):
        global STARTED
        body = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))) or '{}')
        if self.path == '/probe':
            self.respond(probe(body))
            return
        if self.path == '/stop':
            STOP.set()
            self.respond({'stopping': True})
            return
        with LOCK:
            CONFIG.update(body)
        if self.path == '/start':
            if STARTED:
                self.respond({'error': 'already started'}, 409)
                return
            STARTED = True
            threading.Thread(target=run, args=(body.get('duration', 21600),), daemon=True).start()
        self.respond({'updated': True})

    def respond(self, body, code=200):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass
if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ca', default='/trust/mitm.crt', help='trusted MITM CA PEM bundle')
    parser.add_argument('--port', type=int, default=8088, help='unauthenticated management HTTP port; isolated test network only')
    args = parser.parse_args()
    CONTEXT = ssl.create_default_context(cafile=args.ca)
    CONTEXT.set_alpn_protocols(['http/1.1'])
    http.server.ThreadingHTTPServer(('0.0.0.0', args.port), API).serve_forever()
