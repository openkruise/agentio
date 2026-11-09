#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cluster=${KIND_CLUSTER_NAME:-agentio-proxy-init}
image=${1:-agentio-proxy-init:standalone-test}
artifacts=${ARTIFACT_DIR:-$(mktemp -d /tmp/agentio-proxy-init-kind.XXXXXX)}
mkdir -p "$artifacts"
artifacts=$(cd "$artifacts" && pwd)
export KUBECONFIG="$artifacts/kubeconfig"
if kind get clusters | grep -Fxq "$cluster"; then
  echo "Test cluster already exists: $cluster" >&2
  exit 1
fi

cd "$root"
if [[ -n ${PROXY_INIT_TEST_BINARY:-} ]]; then
  install -m 755 "$PROXY_INIT_TEST_BINARY" "$artifacts/proxy-init-network.test"
else
  GOOS=linux GOARCH=$(docker version --format '{{.Server.Arch}}') CGO_ENABLED=0 \
    go test -tags=proxyinit_integration -c -o "$artifacts/proxy-init-network.test" ./pkg/proxyinit
fi
docker build -f test/proxyinit/Dockerfile --build-arg "PROXY_INIT_IMAGE=$image" \
  -t agentio-proxy-init:network-test "$artifacts"

cleanup() {
  kubectl -n proxy-init-test get pods -o yaml > "$artifacts/pods.yaml" 2>&1 || true
  if [[ -n ${pod:-} ]]; then
    kubectl -n proxy-init-test describe pod "$pod" > "$artifacts/$pod-describe.txt" 2>&1 || true
    kubectl -n proxy-init-test logs "$pod" -c proxy-init > "$artifacts/$pod-init.log" 2>&1 || true
  fi
  kind export logs --name "$cluster" "$artifacts/kind-logs" >/dev/null 2>&1 || true
  kind delete cluster --name "$cluster"
}
trap cleanup EXIT
kind create cluster --name "$cluster" --image kindest/node:v1.32.2 \
  --config test/proxyinit/kind.yaml --kubeconfig "$KUBECONFIG" --wait 120s
kind load docker-image agentio-proxy-init:network-test --name "$cluster"
kubectl -n kube-system rollout status deployment/coredns --timeout=120s
kubectl -n kube-system get configmap kube-proxy -o jsonpath='{.data.config\.conf}' > "$artifacts/kube-proxy-config.yaml"
grep -Eq '^mode: "?nftables"?$' "$artifacts/kube-proxy-config.yaml"
docker exec "$cluster-worker" nft list chain ip kube-proxy nat-output > "$artifacts/kube-proxy-output.txt"
kubectl create namespace proxy-init-test
dns=$(kubectl -n kube-system get service kube-dns -o jsonpath='{.spec.clusterIP}')
service=$(kubectl get service kubernetes -o jsonpath='{.spec.clusterIP}')

for mode in pod-nft pod-iptables-nft pod-legacy host; do
  host=false
  policy=ClusterFirst
  backend='"--native-nftables"'
  priority=-101
  if [[ $mode == pod-iptables-nft ]]; then backend='"--force-iptables-binary=nft"'; fi
  if [[ $mode == pod-legacy ]]; then backend='"--force-iptables-binary=legacy"'; fi
  if [[ $mode == pod-iptables-nft || $mode == pod-legacy ]]; then priority=-100; fi
  if [[ $mode == host ]]; then
    host=true
    policy=ClusterFirstWithHostNet
  fi
  pod="proxy-init-$mode"
  kubectl -n proxy-init-test apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $pod
spec:
  nodeName: $cluster-worker
  hostNetwork: $host
  dnsPolicy: $policy
  terminationGracePeriodSeconds: 2
  initContainers:
  - name: proxy-init
    image: agentio-proxy-init:network-test
    imagePullPolicy: Never
    args: ["-u", "1337", "-g", "1337", $backend, "-o", "53", "-c", "eth0"]
    env:
    - {name: AGENTIO_NATIVE_NFTABLES_OUTPUT_PRIORITY, value: '$priority'}
    - {name: AGENTIO_REJECT_NON_TCP, value: 'true'}
    securityContext:
      runAsUser: 0
      capabilities:
        add: [NET_ADMIN, NET_RAW]
        drop: [ALL]
  containers:
  - name: dns-proxy
    image: agentio-proxy-init:network-test
    imagePullPolicy: Never
    command: [/usr/local/bin/proxy-init-network.test, '-test.run=^TestDNSProxyHelper$']
    env:
    - {name: AGENTIO_INIT_TEST_DNS_PROXY, value: '1'}
    - {name: DNS_TEST_SERVICE_IP, value: '$dns'}
    securityContext:
      runAsUser: 1337
      runAsGroup: 1337
      capabilities: {drop: [ALL]}
  - name: client
    image: agentio-proxy-init:network-test
    imagePullPolicy: Never
    command: [sleep, '3600']
    env:
    - {name: DNS_TEST_SERVICE_IP, value: '$dns'}
    - {name: DNS_TEST_EXPECT_IP, value: '$service'}
    securityContext:
      runAsUser: 2000
      runAsGroup: 2000
      capabilities: {drop: [ALL]}
EOF
  kubectl -n proxy-init-test wait --for=condition=Ready "pod/$pod" --timeout=90s
  kubectl -n proxy-init-test exec "$pod" -c client -- \
    /usr/local/bin/proxy-init-network.test '-test.run=^TestKindDNSClient$' -test.v -test.timeout=30s | tee "$artifacts/$mode-client.log"
  kubectl -n proxy-init-test logs "$pod" -c dns-proxy > "$artifacts/$mode-proxy.log"
  grep -q 'forwarded DNS over udp' "$artifacts/$mode-proxy.log"
  grep -q 'forwarded DNS over tcp' "$artifacts/$mode-proxy.log"
done
docker exec "$cluster-worker" nft list ruleset > "$artifacts/worker-ruleset.txt"
echo "Proxy-init kind tests passed; evidence: $artifacts"
