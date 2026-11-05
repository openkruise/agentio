#!/usr/bin/env python3
"""Run one scale against an installed kind scene; retain all resources and evidence."""
import argparse
import concurrent.futures
from datetime import datetime
import json
import os
from pathlib import Path
import subprocess
import threading
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--root', type=Path, required=True)
parser.add_argument('--count', type=int, choices=[10000, 50000, 100000, 200000, 300000], required=True)
parser.add_argument('--node', default='agentio-sidecar-auto-control-plane')
parser.add_argument('--namespace', default='sandbox-scale-system')
parser.add_argument('--seconds', type=int, default=300)
parser.add_argument('--watch-per-pod', action='store_true')
args = parser.parse_args()
root = args.root.resolve()
root.mkdir(parents=True, exist_ok=True)
os.environ['KUBECONFIG'] = str(root / 'kubeconfig')
run_dir = root / f'{args.count}-run'
run_dir.mkdir(exist_ok=False)
stop = threading.Event()
phase = 'setup'
revision = int(time.time()) % 50000


def command(argv, **kwargs):
    return subprocess.run(argv, check=True, text=True, **kwargs)


def kubectl(*argv):
    return command(['kubectl', *argv], capture_output=True).stdout


def event(event_name, **data):
    value = {'time': time.time(), 'event': event_name, **data}
    print(json.dumps(value), flush=True)
    with (run_dir / 'events.jsonl').open('a') as out:
        out.write(json.dumps(value) + '\n')


backend_pods = json.loads(kubectl('get', 'pods', '-n', args.namespace, '-l', 'app=backend', '-o', 'json'))
traffic_targets = ','.join(p['status']['podIP']+':8080' for p in backend_pods['items'])
if not traffic_targets:
    raise RuntimeError('no backend Pods found')
services = json.loads(kubectl('get', 'services', '-n', args.namespace, '-o', 'json'))
ips = {item['metadata']['name']: item['spec']['clusterIP'] for item in services['items']}
network = ['docker', 'run', '--rm', '--user', '0', '--network', f'container:{args.node}',
           '-v', f'{root}:/work', '--entrypoint', '/work/sandbox-bench', 'agentio-sandbox-bench:1018']
common = ['--kubeconfig=/work/kubeconfig-internal', f'--system={args.namespace}',
          f'--ca={ips["agentiod"]}:15012', f'--gateway={ips["egress-gateway"]}:15008',
          f'--target={ips["backend"]}:8080']


def bench(name, action, *options, background=False, required=True):
    target = run_dir / f'{name}.json'
    argv = network + common + [f'--action={action}', f'--count={args.count}',
                              f'--output=/work/{target.relative_to(root)}', *options]
    if action == 'traffic':
        argv.append(f'--target={traffic_targets}')
    log = (run_dir / f'{name}.log').open('w')
    event('start', name=name, action=action)
    proc = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT)
    log.close()
    if background:
        return proc
    code = proc.wait()
    event('finish', name=name, code=code)
    if code and required:
        raise RuntimeError(f'{name} failed; inspect {target.with_suffix(".log")}')
    return json.loads(target.read_text())


def monitor():
    while not stop.is_set():
        try:
            data = json.loads(kubectl('get', '--raw', f'/api/v1/nodes/{args.node}/proxy/stats/summary'))
            with (run_dir / 'resources.jsonl').open('a') as out:
                out.write(json.dumps({'time': time.time(), 'phase': phase, 'stats': data}) + '\n')
            with (run_dir / 'host.jsonl').open('a') as out:
                out.write(json.dumps({'time': time.time(), 'meminfo': Path('/proc/meminfo').read_text(),
                                      'loadavg': Path('/proc/loadavg').read_text()}) + '\n')
        except (subprocess.CalledProcessError, json.JSONDecodeError) as err:
            event('monitor_error', error=str(err))
        stop.wait(5)


def capture(name):
    pods = json.loads(kubectl('get', 'pods', '-n', args.namespace, '-o', 'json'))
    (run_dir / f'{name}-pods.json').write_text(json.dumps(pods))
    targets = []
    for pod in pods['items']:
        if pod['spec']['nodeName'] != args.node:
            continue
        ip = pod['status'].get('podIP')
        pod_name = pod['metadata']['name']
        ports = [15014] if pod_name.startswith('agentiod-') else [9004, 15020] if pod_name.startswith('egress-gateway-') else [9090] if pod_name.startswith('agentio-epe-') else []
        for port in ports:
            targets.append((pod_name, ip, port))
    def scrape(target):
        pod_name, ip, port = target
        path = 'stats/prometheus' if port == 15020 else 'metrics'
        result = command(['docker', 'exec', args.node, 'curl', '-fsS', '--max-time', '10', f'http://{ip}:{port}/{path}'], capture_output=True)
        (run_dir / f'{name}-{pod_name}-{port}.prom').write_text(result.stdout)
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        for future in [pool.submit(scrape, target) for target in targets]:
            try:
                future.result()
            except subprocess.CalledProcessError as err:
                event('scrape_error', error=str(err))
    (run_dir / f'{name}-apiserver.prom').write_text(kubectl('get', '--raw', '/metrics'))
    (run_dir / f'{name}-cadvisor.prom').write_text(
        kubectl('get', '--raw', f'/api/v1/nodes/{args.node}/proxy/metrics/cadvisor'))
    etcd = command(['docker', 'exec', args.node, 'curl', '-fsS', 'http://127.0.0.1:2381/metrics'], capture_output=True)
    (run_dir / f'{name}-etcd.prom').write_text(etcd.stdout)


def watch_snapshot():
    return json.loads((root / f'{args.count}-watch.json.live').read_text())


def convergence(previous=None):
    started = time.time()
    expected = args.count if args.watch_per_pod else args.count // 100
    while time.time() - started < 120:
        current = watch_snapshot()
        versions = current.get('policy_versions', {})
        if (datetime.fromisoformat(current['time'].replace('Z', '+00:00')).timestamp() >= started and
            current['ready'] == expected and
            current['resources'].get('type.googleapis.com/agentio.sandbox.Sandbox') == args.count and
            len(versions) == 1 and sum(versions.values()) == expected and
            (previous is None or set(versions) != set(previous))):
            event('wds_converged', seconds=time.time()-started, snapshot=current)
            return current
        time.sleep(1)
    raise RuntimeError('WDS did not converge within 120 seconds')


def wait_control_plane_replacement(victim, replicas):
    started = time.time()
    while time.time() - started < 180:
        pods = json.loads(kubectl('get', 'pods', '-n', args.namespace,
                                 '-l', 'app=agentiod', '-o', 'json'))['items']
        ready = [pod for pod in pods if not pod['metadata'].get('deletionTimestamp') and
                 any(condition['type'] == 'Ready' and condition['status'] == 'True'
                     for condition in pod.get('status', {}).get('conditions', []))]
        if (all(pod['metadata']['name'] != victim for pod in pods) and
            len(ready) == replicas):
            event('control_plane_replaced', seconds=time.time()-started,
                  pods=[pod['metadata']['name'] for pod in ready])
            return
        time.sleep(1)
    raise RuntimeError('control-plane Pod replacement did not complete within 180 seconds')


thread = threading.Thread(target=monitor)
thread.start()
traffic = []
try:
    convergence()
    (run_dir / 'deployments.yaml').write_text(kubectl('get', 'deployments', '-n', args.namespace, '-o', 'yaml'))
    capture('before')
    phase = 'steady-and-mutations'
    # Last 1,000 identities are reserved for destructive lifecycle operations.
    cold = min(args.count - 1000, 20000)
    traffic.append(bench('hot', 'traffic', f'--count={args.count-1000}', '--active=128',
                         '--workers=128', '--rate=375', f'--requests={args.seconds*375}',
                         f'--duration={args.seconds+30}s', f'--start-file=/work/{run_dir.relative_to(root)}/start', background=True))
    traffic.append(bench('cold', 'traffic', f'--count={args.count-1000}', f'--active={cold}',
                         '--workers=128', '--rate=125', f'--requests={args.seconds*125}',
                         f'--duration={args.seconds+30}s', f'--start-file=/work/{run_dir.relative_to(root)}/start', background=True))
    # Wait for both clients to finish actual Pod-bound certificate preparation.
    deadline = time.time() + 600
    while not all('TRAFFIC_READY' in (run_dir / f'{name}.log').read_text() for name in ['hot', 'cold']):
        if any(p.poll() is not None and p.returncode != 0 for p in traffic):
            raise RuntimeError('traffic preparation failed')
        if time.time() > deadline:
            raise RuntimeError('traffic preparation timed out')
        time.sleep(1)
    (run_dir / 'start').touch()
    event('both_clients_ready')
    time.sleep(30)
    bench('labels', 'labels', f'--count={args.count//10}', f'--revision={revision}')
    before = convergence()['policy_versions']
    changed = time.time()
    bench('traffic-policy', 'traffic-policy', f'--revision={revision}')
    convergence(before)
    event('policy_end_to_end_complete', seconds=time.time()-changed)
    pods = json.loads(kubectl('get', 'pods', '-n', args.namespace, '-l', 'gateway.networking.k8s.io/gateway-name=egress-gateway', '-o', 'json'))
    gateways = ','.join(p['status']['podIP']+':15008' for p in pods['items'])
    if not gateways:
        raise RuntimeError('no gateway Pods found')
    bench('policy', 'policy', '--count=1', f'--revision={revision}', f'--gateway={gateways}')
    bench('recreate', 'recreate', f'--offset={args.count-1000}', '--count=1000')
    # Preserve a failed identity assertion and finish independent scenarios if
    # the full inventory converges again; the final result still fails.
    bench('lifecycle', 'lifecycle', f'--offset={args.count-1}', '--count=1', required=False)
    convergence()
    for name, proc in zip(['hot', 'cold'], traffic):
        code = proc.wait()
        event('finish', name=name, code=code)
    capture('after-mutations')
    phase = 'control-plane-replacement'
    proc = bench('failover', 'traffic', f'--count={args.count-1000}', '--active=1000',
                 '--rate=250', '--workers=128', '--requests=30000', '--duration=150s', background=True)
    traffic.append(proc)
    while 'TRAFFIC_READY' not in (run_dir / 'failover.log').read_text():
        if proc.poll() is not None:
            raise RuntimeError('failover traffic exited before readiness')
        time.sleep(1)
    time.sleep(10)
    cp = json.loads(kubectl('get', 'pods', '-n', args.namespace, '-l', 'app=agentiod', '-o', 'json'))
    deployment = json.loads(kubectl('get', 'deployment', 'agentiod', '-n', args.namespace, '-o', 'json'))
    victim = cp['items'][0]['metadata']['name']
    event('delete_control_plane', pod=victim)
    kubectl('delete', 'pod', '-n', args.namespace, victim, '--wait=false')
    wait_control_plane_replacement(victim, deployment['spec']['replicas'])
    convergence()
    event('finish', name='failover', code=proc.wait())
    capture('after-control-plane')
    phase = 'gateway-rollout'
    proc = bench('gateway-rollout', 'traffic', f'--count={args.count-1000}', '--active=1000',
                 '--rate=250', '--workers=128', '--requests=30000', '--duration=150s', background=True)
    traffic.append(proc)
    while 'TRAFFIC_READY' not in (run_dir / 'gateway-rollout.log').read_text():
        if proc.poll() is not None:
            raise RuntimeError('gateway traffic exited before readiness')
        time.sleep(1)
    time.sleep(10)
    event('restart_gateway_deployment')
    kubectl('rollout', 'restart', 'deployment/egress-gateway', '-n', args.namespace)
    kubectl('rollout', 'status', 'deployment/egress-gateway', '-n', args.namespace, '--timeout=180s')
    event('finish', name='gateway-rollout', code=proc.wait())
    capture('after')
    failed = [p.name for p in run_dir.glob('*.json') if json.loads(p.read_text()).get('error')]
    phase = 'complete'
    event('complete', failed_results=failed)
    if failed:
        raise RuntimeError(f'completed with failed phases: {failed}')
finally:
    for proc in traffic:
        if proc.poll() is None:
            proc.terminate()
            proc.wait()
    stop.set()
    thread.join()
