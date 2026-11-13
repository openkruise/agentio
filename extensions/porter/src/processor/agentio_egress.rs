// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use std::{sync::Arc, time::Instant};

use tonic::Status;

use super::{
    ParsedRequest, ResolveRequest, Resolved, allowed, headers, identity, identity_metadata,
};
use crate::{
    metrics::{ConnectResult, Metrics, Protocol},
    view::{self, View},
    wire::extproc,
};

pub(super) fn parse<'a>(
    request_headers: Option<&extproc::HttpHeaders>,
    attributes: Option<&'a prost_types::Struct>,
) -> Result<ParsedRequest<'a>, Status> {
    let headers = headers(request_headers)?;
    if headers.method != "CONNECT" || headers.authority.is_empty() {
        return Err(Status::invalid_argument(
            "unexpected method or missing request authority",
        ));
    }
    let target: std::net::SocketAddr = headers
        .authority
        .parse()
        .map_err(|_| Status::invalid_argument("CONNECT target must be numeric IP:port"))?;
    if target.port() == 0 {
        return Err(Status::invalid_argument("invalid CONNECT port"));
    }
    Ok(ParsedRequest {
        resolution: ResolveRequest {
            identity: identity(attributes),
            connection_policy: true,
        },
    })
}

pub(super) fn encode(
    resolved: Resolved,
    enable_sni_traffic_policy: bool,
) -> extproc::ProcessingResponse {
    let mut metadata = identity_metadata(resolved.workload.as_ref(), resolved.instance);
    if let Some(sandbox) = &resolved.sandbox {
        let View::Sandbox(sandbox) = sandbox.as_ref() else {
            unreachable!("typed Sandbox watch")
        };
        metadata.insert(
            "sandbox".into(),
            view::object([("id".into(), view::string(&sandbox.uid))]),
        );
    }
    let mut profiles = Vec::new();
    for resource in &resolved.profiles {
        let View::SecurityProfile(profile) = resource.as_ref() else {
            unreachable!("typed SecurityProfile watch")
        };
        profiles.push(profile.project_connection(enable_sni_traffic_policy));
    }
    if let Some(sandbox) = &resolved.sandbox {
        let View::Sandbox(sandbox) = sandbox.as_ref() else {
            unreachable!("typed Sandbox watch")
        };
        if let Some(profile) = &sandbox.profile {
            profiles.push(profile.project_connection(enable_sni_traffic_policy));
        }
    }
    metadata.insert(
        "connection".into(),
        view::object([(
            "policy".into(),
            view::object([("profiles".into(), view::list(profiles))]),
        )]),
    );
    allowed(metadata)
}

pub(super) struct ConnectMeasurement {
    pub metrics: Arc<Metrics>,
    pub started: Instant,
    pub result: &'static str,
}

impl Drop for ConnectMeasurement {
    fn drop(&mut self) {
        self.metrics
            .connect_results
            .get_or_create(&ConnectResult {
                protocol: "tcp",
                result: self.result,
            })
            .inc();
        self.metrics
            .connect
            .get_or_create(&Protocol { protocol: "tcp" })
            .observe(self.started.elapsed().as_secs_f64());
    }
}
