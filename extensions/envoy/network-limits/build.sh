#!/usr/bin/env bash
# Linux prerequisites: Rust 1.93+, clang/libclang, curl and tar.
set -euo pipefail
case "$*" in
  ""|--build-only) ;;
  *) echo "Usage: $0 [--build-only]" >&2; exit 2 ;;
esac
cd "$(dirname "$0")"
export PATH="$HOME/.cargo/bin:$PATH"
sdk_rev=1.40.2
if [ ! -f .envoy-sdk/source/extensions/dynamic_modules/sdk/rust/Cargo.toml ]; then
  curl -fL "https://codeload.github.com/envoyproxy/envoy/tar.gz/v$sdk_rev" -o .envoy-sdk.tar.gz
  mkdir -p .envoy-sdk
  tar -xzf .envoy-sdk.tar.gz --strip-components=1 -C .envoy-sdk \
    "envoy-$sdk_rev/source/extensions/dynamic_modules"
fi
if [ "$#" -eq 0 ]; then
  cargo fmt --package agentio-envoy-network-limits --check
  cargo test --package agentio-envoy-network-limits --release --locked
fi
cargo build --package agentio-envoy-network-limits --release --locked
