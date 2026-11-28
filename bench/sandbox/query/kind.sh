#!/usr/bin/env bash
# Copyright 2026 The Kruise Authors
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

cluster=${1:?usage: kind.sh CLUSTER LINUX_BIN_DIRECTORY BACKEND TTL}
bin=$(cd "${2:?missing binary directory}" && pwd)
backend=${3:?use db or snapshot}
ttl=${4:?set the server TTL}
cd "$(dirname "$0")"
for name in backend epe.test porter.test; do test -x "$bin/$name"; done
work=$(mktemp -d)
ns=
export KUBECONFIG="$work/kubeconfig"
k() { kubectl -n "$ns" "$@"; }
cleanup() {
  if [[ -n "$ns" ]]; then
    kubectl delete namespace "$ns" --wait --timeout=120s
    test -z "$(kubectl get namespace "$ns" --ignore-not-found -o name)"
  fi
  rm -rf "$work"
}
trap cleanup EXIT
umask 077
kind get kubeconfig --name "$cluster" > "$KUBECONFIG"
ns=$(kubectl create -f - -o jsonpath='{.metadata.name}' <<'YAML'
apiVersion: v1
kind: Namespace
metadata: {generateName: sandbox-query-bench-}
YAML
)
openssl rand -hex 24 | tr -d '\n' | k create secret generic db-password --from-file=password=/dev/stdin
pg_image=postgres@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15
for name in pg api driver; do
  image=alpine:3.22
  cmd='command: ["sleep","3600"]'
  if [[ "$name" == pg ]]; then
    image=$pg_image
    cmd='readinessProbe: {exec: {command: [pg_isready, -h, 127.0.0.1, -U, postgres, -d, policyrpc]}, periodSeconds: 2}'
  fi
  k create -f - <<YAML
apiVersion: v1
kind: Pod
metadata: {name: $name, labels: {app: $name}}
spec:
  automountServiceAccountToken: false
  containers:
  - name: bench
    image: $image
    $cmd
    resources: {requests: {cpu: 500m, memory: 128Mi}, limits: {cpu: "2", memory: 2Gi}}
    env:
    - {name: GOMAXPROCS, value: "2"}
    - {name: POSTGRES_DB, value: policyrpc}
    - {name: POSTGRES_PASSWORD, valueFrom: {secretKeyRef: {name: db-password, key: password}}}
    - {name: BENCH_PASSWORD, valueFrom: {secretKeyRef: {name: db-password, key: password}}}
YAML
done
k expose pod pg --port=5432
k expose pod api --port=9000
k expose pod api --name=qstats --port=9001
k wait --for=condition=Ready pods --all --timeout=180s
k exec -i pg -- psql -U postgres -d policyrpc < seed.sql

openssl req -x509 -newkey rsa:2048 -nodes -subj '/CN=Sandbox Bench CA' -days 1 -keyout "$work/ca.key" -out "$work/ca.crt" 2>/dev/null
openssl req -new -newkey rsa:2048 -nodes -subj '/CN=api' -keyout "$work/bench.key" -out "$work/leaf.csr" 2>/dev/null
printf '%s\n' 'subjectAltName=DNS:api' 'basicConstraints=CA:FALSE' 'extendedKeyUsage=serverAuth' > "$work/ext"
openssl x509 -req -in "$work/leaf.csr" -CA "$work/ca.crt" -CAkey "$work/ca.key" -CAcreateserial -days 1 -extfile "$work/ext" -out "$work/bench.crt" 2>/dev/null
echo token > "$work/token"
for f in bench.crt bench.key; do k cp "$work/$f" "api:/tmp/$f"; done
for f in ca.crt token; do k cp "$work/$f" "driver:/tmp/$f"; done
k cp "$bin/backend" api:/tmp/backend
k cp "$bin/epe.test" driver:/tmp/epe.test
k cp "$bin/porter.test" driver:/tmp/porter.test
k cp probe.sh driver:/tmp/probe
k exec driver -- chmod 755 /tmp/probe
# The Rust release binary was linked on the Linux build host. Alpine uses musl.
mkdir "$work/glibc"
libs=$(ldd "$bin/porter.test")
while read -r lib; do cp -L "$lib" "$work/glibc/"; done < <(awk '$2=="=>" && $3 ~ /^\// {print $3} $1 ~ /^\// {print $1}' <<<"$libs")
loader=$(awk '$1 ~ /^\// {print $1}' <<<"$libs")
k cp "$work/glibc" driver:/tmp/glibc
k exec api -- sh -ec '/tmp/backend -backend="$1" -ttl="$2" -inventory="$3" </dev/null >/tmp/query.log 2>&1 &' sh "$backend" "$ttl" "${QUERY_BENCH_INVENTORY:-50000}"
if ! k exec api -- sh -ec 'for i in $(seq 1 60); do if wget -qO /dev/null http://localhost:9001/stats; then exit 0; fi; sleep 1; done; exit 1'; then
  k exec api -- cat /tmp/query.log
  exit 1
fi
default='{"Mode":"rpc","Address":"api:9000","Root":"/tmp/ca.crt","Token":"/tmp/token","Keys":10000,"Warm":10000,"Requests":100000,"Workers":64,"Rate":0,"PauseMS":0}'
envs=(env "AGENTIO_SANDBOX_BENCH=${AGENTIO_SANDBOX_BENCH:-$default}" AGENTIO_QUERY_BENCH_PROBE=/tmp/probe)
k exec driver -- "${envs[@]}" /tmp/epe.test -test.v -test.run '^TestSandboxPolicyLoad$'
k exec driver -- "${envs[@]}" "/tmp/glibc/${loader##*/}" --library-path /tmp/glibc /tmp/porter.test --exact sandbox_policy_load --ignored --nocapture
