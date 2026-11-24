// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use criterion::{criterion_group, criterion_main};
use envoy_agentio_body_processing::body_processing_benchmarks;

criterion_group!(benches, body_processing_benchmarks);
criterion_main!(benches);
