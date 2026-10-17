# Copyright 2026 The Kruise Authors
# SPDX-License-Identifier: Apache-2.0
FROM rust:1.93-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends protobuf-compiler libprotobuf-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY api/ api/
COPY extensions/porter/Cargo.toml extensions/porter/Cargo.lock extensions/porter/build.rs extensions/porter/
COPY extensions/porter/src/ extensions/porter/src/
COPY extensions/porter/proto/ extensions/porter/proto/
RUN cargo build --release --locked --manifest-path extensions/porter/Cargo.toml
FROM debian:bookworm-slim
COPY --from=builder /src/extensions/porter/target/release/agentio-porter /usr/local/bin/agentio-porter
USER 1337:1337
ENTRYPOINT ["/usr/local/bin/agentio-porter"]
