#!/usr/bin/env python3
"""Render production chart resources without registering a second global injector."""
import argparse
import subprocess
from pathlib import Path

import yaml

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--chart', default='manifests/charts/agentio')
parser.add_argument('--values', action='append', help='Helm values file; repeat for overrides')
parser.add_argument('--backend', default='bench/sandbox/backend.yaml')
parser.add_argument('--namespace', default='sandbox-scale-system')
parser.add_argument('--real-node')
parser.add_argument('--output', required=True)
args = parser.parse_args()
helm = ['helm', 'template', 'sandbox-scale', args.chart, '-n', args.namespace]
for values in args.values or ['bench/sandbox/values.yaml']:
    helm.extend(['-f', values])
rendered = subprocess.check_output(helm, text=True)
resources = []
for resource in [*yaml.safe_load_all(rendered), *yaml.safe_load_all(Path(args.backend).read_text())]:
    if not resource or resource['kind'] == 'MutatingWebhookConfiguration':
        continue
    if resource['kind'] == 'Deployment':
        pod = resource['spec']['template']['spec']
        if args.real_node:
            pod['nodeSelector'] = {'kubernetes.io/hostname': args.real_node}
        for container in pod.get('containers', []):
            if 'env' in container:
                container['env'] = list({env['name']: env for env in container['env']}.values())
    resources.append(resource)
Path(args.output).write_text(yaml.safe_dump_all(resources))
