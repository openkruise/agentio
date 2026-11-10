// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use std::net::{IpAddr, SocketAddr};

use prost_types::value::Kind;
use tonic::Status;

use super::{
    ParsedRequest, ResolveRequest, Resolved, allowed, attribute, headers, identity,
    identity_metadata,
};
use crate::{
    traffic::Target,
    wire::{agentio::security::traffic_policy, extproc},
};

pub(super) fn parse<'a>(
    request_headers: Option<&extproc::HttpHeaders>,
    attributes: Option<&'a prost_types::Struct>,
    enforce_policy: bool,
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
    let target = if enforce_policy {
        // Use the restored HBONE destination, never the application's Host.
        let ip = attribute(attributes, "destination.address")
            .parse::<IpAddr>()
            .map_err(|_| Status::invalid_argument("invalid destination.address"))?;
        let port = attributes
            .and_then(|attrs| attrs.fields.get("destination.port"))
            .and_then(|value| match value.kind.as_ref() {
                Some(Kind::NumberValue(port))
                    if (1.0..=65535.0).contains(port) && port.fract() == 0.0 =>
                {
                    Some(*port as u16)
                }
                _ => None,
            })
            .ok_or_else(|| Status::invalid_argument("invalid destination.port"))?;
        Some(Target {
            address: SocketAddr::new(ip.to_canonical(), port),
            protocol: traffic_policy::Protocol::Tcp,
        })
    } else {
        None
    };
    Ok(ParsedRequest {
        resolution: ResolveRequest { identity, target },
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
