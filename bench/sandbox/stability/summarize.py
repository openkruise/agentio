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
import collections, gzip, json, math, pathlib, statistics
import argparse
parser = argparse.ArgumentParser(description='Summarize saved stability snapshots; no cluster access.')
parser.add_argument('--evidence', type=pathlib.Path, required=True)
parser.add_argument('--output', type=pathlib.Path, required=True)
parser.add_argument('--system', default='sandbox-scale-system')
parser.add_argument('--sandbox-namespace', default='sandbox-stability-real')
args = parser.parse_args()
R = args.evidence
OUT = args.output
OUT.mkdir(parents=True, exist_ok=True)
read = lambda p: json.load(gzip.open(p, 'rt'))
last = {}
minutes = []
phases = {}
samples = []
bounds = None
for p in sorted(R.glob('probes-*.json.gz')):
    x = read(p)
    delta = collections.Counter()
    errors = collections.Counter()
    statuses = collections.Counter()
    hist = {}
    qhist = {}
    hasmissing = []
    for row in x['items']:
        if 'data' not in row:
            hasmissing.append(row)
            continue
        data = row['data']
        bounds = data['bounds_ms']
        uid = row['uid']
        prior = last.get(uid, {}).get('data', {}).get('groups', {})
        for (group, s) in data['groups'].items():
            old = prior.get(group, {})
            n = s['requests'] - old.get('requests', 0)
            e = s['errors'] - old.get('errors', 0)
            delta[group + ':requests'] += n
            delta[group + ':errors'] += e
            for (k, v) in s['error_types'].items():
                errors[group + ':' + k] += v - old.get('error_types', {}).get(k, 0)
            for (k, v) in s['statuses'].items():
                statuses[group + ':' + k] += v - old.get('statuses', {}).get(k, 0)
            hist.setdefault(group, [0] * len(s['histogram']))
            qhist.setdefault(group, [0] * len(s['queue_histogram']))
            for (key, target) in [('histogram', hist[group]), ('queue_histogram', qhist[group])]:
                for (i, v) in enumerate(s[key]):
                    target[i] += v - old.get(key, [0] * len(s[key]))[i]
        for event in data['samples']:
            if 'error' in event and event['time'] >= x['time'] - 90:
                samples.append({'pod': row['name'], 'phase': x['phase'], **event})
        last[uid] = row
    minutes.append({'time': x['time'], 'phase': x['phase'], 'delta': dict(delta), 'errors': dict(errors), 'statuses': dict(statuses), 'histograms': hist, 'queue_histograms': qhist, 'missing': hasmissing})

    def quantile(h, q):
        total = sum(h)
        if total == 0:
            return None
        target = math.ceil(total * q)
        acc = 0
        for (i, n) in enumerate(h):
            acc += n
            if acc >= target:
                return bounds[i] if i < len(bounds) else float('inf')
    for (group, h) in hist.items():
        minutes[-1].setdefault('p99_ms', {})[group] = quantile(h, 0.99)
        minutes[-1].setdefault('queue_p99_ms', {})[group] = quantile(qhist[group], 0.99)
for p in R.glob('retired-*.json.gz'):
    x = read(p)
    if isinstance(x, dict) and 'pod' in x:
        last[x['pod']['uid']] = {'name': x['pod']['name'], 'uid': x['pod']['uid'], 'group': x['pod']['group'], 'data': x['final']}
for row in minutes:
    a = phases.setdefault(row['phase'], {'samples': 0, 'delta': collections.Counter(), 'errors': collections.Counter(), 'statuses': collections.Counter()})
    a['samples'] += 1
    for k in ['delta', 'errors', 'statuses']:
        a[k].update(row[k])
groups = {}
violations = 0
for row in last.values():
    for (group, s) in row['data']['groups'].items():
        a = groups.setdefault(group, {'requests': 0, 'errors': 0, 'error_types': collections.Counter(), 'statuses': collections.Counter()})
        a['requests'] += s['requests']
        a['errors'] += s['errors']
        a['error_types'].update(s['error_types'])
        a['statuses'].update(s['statuses'])
        violations += s['error_types'].get('PolicyViolation', 0)
resource = []
for p in sorted(R.glob('nodes-*.json.gz')):
    try:
        x = read(p)
    except (gzip.BadGzipFile, EOFError, json.JSONDecodeError) as e:
        print('CORRUPT_RESOURCE_SAMPLE', p.name, str(e), file=__import__('sys').stderr)
        continue
    groupsres = {}
    zt = []
    for node in x['items']:
        for pod in node.get('pods', []):
            ns = pod['podRef']['namespace']
            name = pod['podRef']['name']
            if ns == args.system:
                kind = next((label for (prefix, label) in [('agentiod-policy-', 'policy'), ('agentiod-', 'main'), ('agentio-epe-', 'epe'), ('egress-gateway-', 'gateway')] if name.startswith(prefix)), None)
                if not kind:
                    continue
                for c in pod.get('containers', []):
                    k = kind + '/' + c['name']
                    a = groupsres.setdefault(k, {'rss': 0, 'working_set': 0, 'cpu_nano': 0, 'containers': 0})
                    a['rss'] += c.get('memory', {}).get('rssBytes', 0)
                    a['working_set'] += c.get('memory', {}).get('workingSetBytes', 0)
                    a['cpu_nano'] += c.get('cpu', {}).get('usageNanoCores', 0)
                    a['containers'] += 1
            elif ns == args.sandbox_namespace:
                zt.extend(({'rss': c.get('memory', {}).get('rssBytes', 0), 'cpu_nano': c.get('cpu', {}).get('usageNanoCores', 0)} for c in pod.get('containers', []) if c['name'] == 'traffic-proxy'))
    resource.append({'time': x['time'], 'phase': x['phase'], 'components': groupsres, 'ztunnel_count': len(zt), 'ztunnel_rss_sum': sum((v['rss'] for v in zt)), 'ztunnel_rss_median': statistics.median((v['rss'] for v in zt)) if zt else None})
certs = collections.defaultdict(list)
for p in sorted(R.glob('workload-certificates-*.json.gz')):
    for row in read(p):
        for identity in row.get('certificates', []):
            for c in identity['certificates']:
                certs[row['name']].append(c)
certsummary = {pod: {'samples': len(cs), 'unique_serials': len({c['serialNumber'] for c in cs}), 'earliest_valid_from': min((c['validFrom'] for c in cs)), 'latest_valid_from': max((c['validFrom'] for c in cs)), 'latest_expiration': max((c['expirationTime'] for c in cs))} for (pod, cs) in certs.items()}
result = {'last_time': minutes[-1]['time'], 'minute_samples': len(minutes), 'identities_seen': len(last), 'groups': groups, 'policy_violations': violations, 'phases': phases, 'workload_certificates': certsummary}
for (name, data) in [('summary', result), ('minutes', minutes), ('resources', resource), ('error-samples', samples)]:
    with gzip.open(OUT / (name + '.json.gz'), 'wt') as f:
        json.dump(data, f)
print(json.dumps(result))
