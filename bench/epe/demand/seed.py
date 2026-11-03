#!/usr/bin/env python3
"""Create synthetic Pod inventory through kubectl proxy in an isolated test cluster."""
import argparse
import concurrent.futures
import json
import ipaddress
import urllib.request

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--api", default="http://127.0.0.1:18049")
parser.add_argument("--namespace", default="epe-demand-workloads")
parser.add_argument("--count", type=int, default=1024)
parser.add_argument("--offset", type=int, default=0)
parser.add_argument("--labels", type=int, default=20)
args = parser.parse_args()
if args.count <= 0 or args.offset < 0 or args.offset + args.count > 100000:
    parser.error("require count > 0, offset >= 0, and offset + count <= 100000")
if args.labels < 0:
    parser.error("labels must not be negative")


def send(method, path, body, content_type="application/json"):
    request = urllib.request.Request(
        args.api + path,
        json.dumps(body).encode(),
        {"Content-Type": content_type},
        method=method,
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def seed(index):
    name = f"workload-{index:05d}"
    path = f"/api/v1/namespaces/{args.namespace}/pods"
    labels = {f"load.example/label-{i:03d}": f"value-{index % 16:02d}-abcdefghijklmnopqrstuvwx" for i in range(args.labels)}
    labels["app"] = "epe-demand"
    send("POST", path, {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "labels": labels},
        # No kubelet owns this node: inventory consumes no running containers.
        "spec": {"nodeName": "epe-demand-inventory", "tolerations": [{"operator": "Exists"}], "containers": [
            {"name": "fixture", "image": "registry.k8s.io/pause:3.10"}
        ]},
    })
    ip = str(ipaddress.IPv4Address("10.200.0.1") + index)
    send("PATCH", path + f"/{name}/status", {"status": {
        "phase": "Running", "podIP": ip, "podIPs": [{"ip": ip}],
        "conditions": [{"type": "Ready", "status": "True"}],
    }}, "application/merge-patch+json")


with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
    for completed, _ in enumerate(executor.map(seed, range(args.offset, args.offset + args.count)), 1):
        if completed % 1000 == 0:
            print(json.dumps({"completed": completed, "target": args.count}), flush=True)
print(json.dumps({"seeded": args.count, "offset": args.offset}))
