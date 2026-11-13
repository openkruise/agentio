#!/usr/bin/env bash

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

set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
proto_files=(
  api/workload/v1/workload.proto
  api/security/v1/authorization.proto
  api/security/v1/trafficpolicy.proto
  api/security/v1/securityprofile.proto
  api/sandbox/v1/sandbox.proto
  api/extensions/v1/extensions.proto
  api/extensions/v1/egresspolicy.proto
  api/extensions/v1/snipolicy.proto
  api/security/v1/snipolicy.proto
  api/security/v1/tcppolicy.proto
  api/config/v1/epeconfig.proto
  api/config/v1/agentioconfig.proto
)

cd "$repo_root"

# Pin the complete generator toolchain; never use protoc/plugins from PATH.
protoc_version="36.0"
protoc_gen_go_version="v1.36.11"
case "$(uname -s)/$(uname -m)" in
  Linux/x86_64)
    protoc_platform="linux-x86_64"
    protoc_sha256="bc8211ce760bd43ee21ddc145d6d9dbaeeabae205267a79d9054a240e367d4b4"
    ;;
  Linux/aarch64|Linux/arm64)
    protoc_platform="linux-aarch_64"
    protoc_sha256="4a00ec5e256d20a3deadd9e77d56da0ac04c72367c3c959f6d08e110a368400a"
    ;;
  Darwin/x86_64|Darwin/arm64)
    protoc_platform="osx-universal_binary"
    protoc_sha256="c4d0f49ab3b0778eaef0c20871d21547d5fc982a1d6f1571d33ec2754ef180b6"
    ;;
  *)
    echo "unsupported protoc platform: $(uname -s)/$(uname -m)" >&2
    exit 1
    ;;
esac

temporary_dir="$(mktemp -d)"
trap 'rm -rf "$temporary_dir"' EXIT

archive="$temporary_dir/protoc.zip"
curl --fail --location --silent --show-error --retry 3 \
  "https://github.com/protocolbuffers/protobuf/releases/download/v${protoc_version}/protoc-${protoc_version}-${protoc_platform}.zip" \
  --output "$archive"
if command -v sha256sum >/dev/null 2>&1; then
  actual_sha256="$(sha256sum "$archive" | awk '{print $1}')"
else
  actual_sha256="$(shasum -a 256 "$archive" | awk '{print $1}')"
fi
if [[ "$actual_sha256" != "$protoc_sha256" ]]; then
  echo "protoc archive checksum mismatch" >&2
  exit 1
fi
unzip -q "$archive" -d "$temporary_dir/protoc"

GOBIN="$temporary_dir/bin" go install "google.golang.org/protobuf/cmd/protoc-gen-go@${protoc_gen_go_version}"

istio_api="$(go mod download -json istio.io/api | sed -n 's/^[[:space:]]*"Dir": "\(.*\)",$/\1/p')"
if [[ -z "$istio_api" ]]; then
  echo "failed to locate the istio.io/api module" >&2
  exit 1
fi

# Invoke protoc directly: no developer-installed buf or protoc is needed.
# Keep the module-pinned Istio imports first to preserve existing Go types.
# The pinned protoc archive supplies any remaining well-known types.
"$temporary_dir/protoc/bin/protoc" \
  -I. \
  -I"$istio_api" \
  -I"$istio_api/common-protos" \
  -I"$temporary_dir/protoc/include" \
  --plugin="protoc-gen-go=$temporary_dir/bin/protoc-gen-go" \
  --go_out=. \
  --go_opt=paths=source_relative \
  "${proto_files[@]}"
