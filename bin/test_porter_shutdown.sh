#!/usr/bin/env bash
# Copyright 2026 The Kruise Authors
# SPDX-License-Identifier: Apache-2.0
# Borrow one existing KinD node; the test owns only its disposable namespace.
set -euo pipefail
cluster=${1:?usage: test_porter_shutdown.sh KIND_CLUSTER GATEWAY_IMAGE PORTER_IMAGE}
gateway_image=${2:?gateway image required}
porter_image=${3:?Porter image required}
artifacts=$(mktemp -d)
node_dir="/opt/agentio-porter-shutdown-$(basename "$artifacts")"
node=$(kind get nodes --name "$cluster" | head -n 1)
: "${node:?existing KinD cluster has no nodes}"
cleanup() {
  docker exec "$node" rm -rf "$node_dir"
  rm -rf "$artifacts"
}
trap cleanup EXIT
kind load docker-image --name "$cluster" "$gateway_image" "$porter_image"
helm template porter-shutdown manifests/charts/agentio --namespace porter-shutdown \
  --set egressGateway.mode=static --show-only templates/gateway/deployment.yaml \
  > "$artifacts/deployment.yaml"
arch=$(docker exec "$node" uname -m)
case "$arch" in
  x86_64) arch=amd64 ;;
  aarch64) arch=arm64 ;;
  *) echo "unsupported node architecture: $arch" >&2; exit 1 ;;
esac
CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go test -c -o "$artifacts/gatewayagent.test" ./pkg/gatewayagent
cp pkg/networking/testdata/agentio-egress-gateway.json "$artifacts/gateway.json"
docker exec "$node" mkdir -p "$node_dir"
# Use an executable path (KinD may mount /tmp noexec), and copy through the
# node mount namespace shared by the test and kubelet.
tar -C "$artifacts" -cf - . | docker exec -i "$node" tar -xf - -C "$node_dir"
docker exec \
  -e AGENTIO_TEST_KUBECONFIG=/etc/kubernetes/admin.conf \
  -e AGENTIO_TEST_NODE_NAME="$node" \
  -e AGENTIO_TEST_GATEWAY_IMAGE="$gateway_image" \
  -e AGENTIO_TEST_PORTER_IMAGE="$porter_image" \
  -e AGENTIO_TEST_GATEWAY_DEPLOYMENT="$node_dir/deployment.yaml" \
  -e AGENTIO_TEST_GATEWAY_FIXTURE="$node_dir/gateway.json" \
  "$node" "$node_dir/gatewayagent.test" \
  -test.run='^TestPorterPodTermination$' -test.v -test.timeout=3m
