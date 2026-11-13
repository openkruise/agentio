// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use tonic::Status;

use super::{
    ParsedRequest, ResolveRequest, Resolved, allowed, headers, identity, identity_metadata,
};
use crate::wire::extproc;

pub(super) fn parse<'a>(
    request_headers: Option<&extproc::HttpHeaders>,
    attributes: Option<&'a prost_types::Struct>,
) -> Result<ParsedRequest<'a>, Status> {
    let headers = headers(request_headers)?;
    if headers.method.is_empty() || headers.authority.is_empty() {
        return Err(Status::invalid_argument(
            "unexpected method or missing request authority",
        ));
    }
    let identity = identity(attributes);
    if !identity.requested_sandbox_id.is_empty() {
        return Err(Status::invalid_argument(
            "agentgateway does not support Sandbox identity",
        ));
    }
    Ok(ParsedRequest {
        resolution: ResolveRequest {
            identity,
            connection_policy: false,
        },
        protocol: "tcp",
    })
}

pub(super) fn encode(resolved: Resolved) -> Result<extproc::ProcessingResponse, Status> {
    if resolved.sandbox.is_some() {
        return Err(Status::invalid_argument(
            "agentgateway does not support Sandbox identity",
        ));
    }
    Ok(allowed(identity_metadata(
        resolved.workload.as_ref(),
        resolved.instance,
    )))
}
