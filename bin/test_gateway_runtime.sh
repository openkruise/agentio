#!/usr/bin/env bash
# Test ADS recovery and Wasm/ECDS using community Envoy or an explicit gateway image.
set -euo pipefail
# Reuse the Dockerfile's pin so unit CI and the packaged runtime stay aligned.
image=${1:-}
mode=${2:-community}
case "$mode" in
  community) image_arg=ENVOY_IMAGE; legacy_binary= ;;
  legacy) image_arg=LEGACY_ENVOY_IMAGE; legacy_binary=/usr/local/bin/envoy ;;
  *) echo "Unknown gateway runtime: $mode" >&2; exit 1 ;;
esac
if [[ -z "$image" ]]; then
  image=$(sed -n "s/^ARG ${image_arg}=//p" docker/Dockerfile.gateway)
fi
: "${image:?missing Envoy image pin in docker/Dockerfile.gateway}"
artifacts=$(mktemp -d)
trap 'rm -rf "$artifacts"' EXIT
chmod 755 "$artifacts"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -o "$artifacts/gatewayagent.test" ./pkg/gatewayagent
chmod 755 "$artifacts/gatewayagent.test"
docker run --rm --platform linux/amd64 --user 1337:1337 \
  --entrypoint /tests/gatewayagent.test \
  --mount "type=bind,src=$artifacts/gatewayagent.test,dst=/tests/gatewayagent.test,readonly" \
  -e AGENTIO_TEST_ENVOY_BINARY=/usr/local/bin/envoy \
  -e AGENTIO_TEST_NETWORK_FAULTS=1 \
  -e "AGENTIO_TEST_LEGACY_ENVOY_BINARY=$legacy_binary" \
  "$image" -test.v -test.timeout=90s \
  -test.run='TestCommunityEnvoyWasmECDS|TestADSDetectsSilentBlackhole|TestLegacyEnvoyBootstrap|TestEnvoyConfiguredBootstrap'
