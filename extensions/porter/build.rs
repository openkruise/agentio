// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let files = [
        "proto/discovery.proto",
        "proto/ext_proc.proto",
        "../../api/workload/v1/workload.proto",
        "../../api/sandbox/v1/sandbox.proto",
        "../../api/extensions/v1/extensions.proto",
        "../../api/extensions/v1/snipolicy.proto",
    ];
    tonic_prost_build::configure().compile_protos(&files, &["proto", "../.."])?;
    println!("cargo:rerun-if-changed=proto");
    println!("cargo:rerun-if-changed=../../api");
    Ok(())
}
