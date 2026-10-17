// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

pub mod discovery;
pub mod identity;
pub mod metrics;
pub mod processor;
pub mod view;

#[allow(clippy::large_enum_variant, clippy::module_inception)]
pub mod wire {
    pub mod ads {
        tonic::include_proto!("envoy.service.discovery.v3");
    }

    pub mod extproc {
        tonic::include_proto!("envoy.service.ext_proc.v3");
    }

    pub mod istio {
        pub mod workload {
            tonic::include_proto!("istio.workload");
        }
    }

    pub mod agentio {
        pub mod sandbox {
            tonic::include_proto!("agentio.sandbox");
        }

        pub mod security {
            tonic::include_proto!("agentio.security");
        }
    }

    pub mod kruise {
        pub mod networking {
            pub mod extensions {
                pub mod v1 {
                    tonic::include_proto!("kruise.networking.extensions.v1");
                }
            }
        }
    }
}
