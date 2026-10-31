#!/usr/bin/env bash
# Linux prerequisites: Rust 1.93+, gcc, clang/libclang-dev, curl, tar.
set -euo pipefail
cd "$(dirname "$0")"
export PATH="$HOME/.cargo/bin:$PATH"
sdk_rev=1.40.2
if [ ! -f .envoy-sdk/source/extensions/dynamic_modules/sdk/rust/Cargo.toml ]; then
  curl -fL "https://codeload.github.com/envoyproxy/envoy/tar.gz/v$sdk_rev" -o .envoy-sdk.tar.gz
  mkdir -p .envoy-sdk
  tar -xzf .envoy-sdk.tar.gz --strip-components=1 -C .envoy-sdk --wildcards \
    "envoy-$sdk_rev/source/extensions/dynamic_modules/*"
fi
cargo fmt --package agentio-envoy-sni-policy --check
cargo test --package agentio-envoy-sni-policy --release --locked
cargo build --package agentio-envoy-sni-policy --release --locked
