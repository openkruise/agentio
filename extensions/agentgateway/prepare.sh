#!/usr/bin/env bash
# Copyright 2026 The Kruise Authors
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

patch_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source_dir=${1:?Usage: prepare.sh /path/to/fresh/agentgateway-checkout}
revision=$(cat "$patch_dir/source-revision")
if [[ $(git -C "$source_dir" rev-parse HEAD) != "$revision" ]]; then
  echo "Agentio requires agentgateway v1.7.0 ($revision)" >&2
  exit 1
fi
git -C "$source_dir" apply --check "$patch_dir/hbone-ext-proc.patch"
git -C "$source_dir" apply "$patch_dir/hbone-ext-proc.patch"
install -m 0644 "$patch_dir/src/hbone_ext_proc.rs" "$patch_dir/src/hbone_ext_proc_tests.rs" \
  "$source_dir/crates/agentgateway/src/proxy/"
install -m 0644 "$patch_dir/../envoy/sni-policy/src/policy.rs" \
  "$source_dir/crates/agentgateway/src/proxy/agentio_sni_policy.rs"
