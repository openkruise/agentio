// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::cel::{DestinationContext, Expression, SourceContext};
use crate::http::ext_proc::{
	BodySendMode, ExtProc, ExtProcDynamicMetadata, FailureMode, HeaderSendMode, ProcessingOptions,
	TrailerSendMode,
};
use crate::proxy::httpproxy::PolicyClient;
use crate::transport::stream::{Extension, TCPConnectionInfo, TLSConnectionInfo};
use crate::types::agent::SimpleBackendReferenceWithPolicies;
use crate::*;

#[allow(dead_code)] // Shared evaluator also contains Envoy's cleartext and byte helpers.
#[path = "agentio_sni_policy.rs"]
mod sni;

#[cfg(test)]
#[path = "hbone_ext_proc_tests.rs"]
mod tests;

#[apply(schema!)]
pub struct HboneExtProc {
	#[serde(flatten)]
	pub target: SimpleBackendReferenceWithPolicies,
	#[serde(default)]
	pub request_attributes: Option<HashMap<String, Arc<Expression>>>,
	#[serde(default)]
	pub tls_exclusions: Vec<String>,
	#[serde(default)]
	pub tls_inclusions: Vec<String>,
	#[serde(with = "crate::serdes::serde_dur", default = "default_timeout")]
	#[cfg_attr(feature = "schema", schemars(with = "String"))]
	pub timeout: Duration,
}

fn default_timeout() -> Duration {
	Duration::from_secs(5)
}

/// Belongs to one CONNECT stream, never to the shared HTTP/2 connection.
#[derive(Clone, Debug)]
pub struct HboneContext {
	pub source: SourceContext,
	sni: Option<Arc<sni::Policy>>,
}

#[derive(Clone, Debug)]
pub(crate) struct ActiveProcessor(pub Arc<()>);

#[derive(Clone, Debug)]
pub(crate) struct AuthorizedTargetOwner(Arc<()>);

/// Bind an EPE decision to the actual dial target, before later header mutations.
pub(crate) fn pin_authorized_target(
	request: &mut http::Request,
	metadata: &prost_wkt_types::Struct,
) -> Result<(), crate::http::ext_proc::Error> {
	use crate::http::ext_proc::Error;
	use crate::proxy::httpproxy::DynamicBackendOverride;
	use crate::types::agent::Target;

	let Some(route) = metadata.fields.get("agentio.route") else {
		return Ok(());
	};
	let route = http::envoy_proto_common::prost_value_to_json(route)
		.map_err(|error| Error::MetadataConversion(error.to_string()))?;
	let target: std::net::SocketAddr = route
		.pointer("/upstream/address")
		.and_then(serde_json::Value::as_str)
		.ok_or_else(|| Error::MetadataConversion("EPE upstream address missing".into()))?
		.parse()
		.map_err(|error: std::net::AddrParseError| Error::MetadataConversion(error.to_string()))?;
	if target.port() == 0 {
		return Err(Error::MetadataConversion(
			"EPE upstream port must be nonzero".into(),
		));
	}
	let processor = request
		.extensions()
		.get::<ActiveProcessor>()
		.expect("ext_proc request owner")
		.0
		.clone();
	if let Some(owner) = request.extensions().get::<AuthorizedTargetOwner>()
		&& !Arc::ptr_eq(&owner.0, &processor)
	{
		return Err(Error::MetadataConversion(
			"another processor cannot replace EPE's authorized target".into(),
		));
	}
	request
		.extensions_mut()
		.insert(AuthorizedTargetOwner(processor));
	request
		.extensions_mut()
		.insert(DynamicBackendOverride(Target::Address(target)));
	Ok(())
}

pub async fn authorize(
	inputs: Arc<ProxyInputs>,
	uri: &http::Uri,
	headers: &http::HeaderMap,
	connection: &Extension,
	policy: &HboneExtProc,
) -> Result<HboneContext, http::StatusCode> {
	let tcp = connection
		.get::<TCPConnectionInfo>()
		.expect("HBONE TCP context");
	let mut source = SourceContext::from_tcp_connection(
		tcp,
		connection
			.get::<TLSConnectionInfo>()
			.and_then(|tls| tls.src_identity.clone()),
		None,
	);
	source.connect_headers = headers.clone();
	// CONNECT can carry credentials; HeaderMap's Debug must redact their values.
	for value in source.connect_headers.values_mut() {
		value.set_sensitive(true);
	}
	let mut request = ::http::Request::builder()
		.method(::http::Method::CONNECT)
		.uri(uri.clone())
		.version(::http::Version::HTTP_2)
		.body(http::Body::empty())
		.expect("validated HBONE CONNECT");
	*request.headers_mut() = source.connect_headers.clone();
	request.extensions_mut().insert(source.clone());
	let mut destination = DestinationContext::from_tcp_connection(tcp);
	let target = uri.authority().expect("validated CONNECT authority");
	destination.address = target
		.host()
		.trim_matches(['[', ']'])
		.parse()
		.map_err(|_| http::StatusCode::BAD_REQUEST)?;
	destination.port = target.port_u16().ok_or(http::StatusCode::BAD_REQUEST)?;
	request.extensions_mut().insert(destination);

	let processor = ExtProc {
		target: policy.target.clone(),
		failure_mode: FailureMode::FailClosed,
		metadata_context: None,
		request_attributes: policy.request_attributes.clone(),
		response_attributes: None,
		processing_options: ProcessingOptions {
			request_body_mode: BodySendMode::None,
			response_body_mode: BodySendMode::None,
			request_header_mode: HeaderSendMode::Send,
			response_header_mode: HeaderSendMode::Skip,
			request_trailer_mode: TrailerSendMode::Skip,
			response_trailer_mode: TrailerSendMode::Skip,
			allow_mode_override: false,
		},
	};
	let mut processor = processor.build(PolicyClient::new(inputs));
	let result = tokio::time::timeout(policy.timeout, processor.mutate_request(&mut request))
		.await
		.map_err(|_| http::StatusCode::GATEWAY_TIMEOUT)?
		.map_err(|error| {
			tracing::warn!(%error, "HBONE external processing failed");
			http::StatusCode::SERVICE_UNAVAILABLE
		})?;
	// Any local response rejects CONNECT, including an accidental successful status.
	if let Some(response) = result.direct_response {
		return Err(if response.status().is_success() {
			http::StatusCode::FORBIDDEN
		} else {
			response.status()
		});
	}
	let metadata = request
		.extensions_mut()
		.remove::<ExtProcDynamicMetadata>()
		.ok_or(http::StatusCode::FORBIDDEN)?;
	let sni = metadata.0.get("agentio").map(|agentio| {
        let mut value = agentio["sni"]["policy"].clone();
        let fields = value.as_object_mut().ok_or(http::StatusCode::FORBIDDEN)?;
        let rules = fields.entry("rules").or_insert(serde_json::json!([]))
            .as_array_mut().ok_or(http::StatusCode::FORBIDDEN)?;
        if !policy.tls_exclusions.is_empty() {
            rules.insert(0, serde_json::json!({"match": {"sni": policy.tls_exclusions}, "action": "SNI_ACTION_PASSTHROUGH"}));
        }
        if !policy.tls_inclusions.is_empty() {
            rules.push(serde_json::json!({"match": {"sni": policy.tls_inclusions}, "action": "SNI_ACTION_TLS_TERMINATION"}));
        }
        serde_json::from_value::<sni::Policy>(value)
            .map(Arc::new)
            .map_err(|_| http::StatusCode::FORBIDDEN)
    }).transpose()?;
	source.connect_metadata = Some(Arc::new(metadata));
	Ok(HboneContext { source, sni })
}

/// true selects HTTPS termination; false selects untouched TLS passthrough.
pub fn tls_termination(connection: &Extension, server_name: &str) -> anyhow::Result<Option<bool>> {
	let Some(policy) = connection
		.get::<HboneContext>()
		.and_then(|ctx| ctx.sni.as_ref())
	else {
		return Ok(None);
	};
	match policy.evaluate(Some(server_name)) {
		sni::Action::Terminate => Ok(Some(true)),
		sni::Action::Passthrough => Ok(Some(false)),
		sni::Action::Deny | sni::Action::Cleartext => anyhow::bail!("Porter SNI policy denied TLS"),
	}
}
