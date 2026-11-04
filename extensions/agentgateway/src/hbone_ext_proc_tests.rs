// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::http::ext_proc::proto::{self, HttpHeaders, ProcessingRequest, ProcessingResponse};
use crate::proxy::httpproxy::DynamicBackendOverride;
use crate::test_helpers::extprocmock::{
	ExtProcMock, Handler, immediate_response, request_header_response_with_dynamic_metadata,
};
use crate::test_helpers::proxymock::setup_proxy_test;
use serde_json::json;
use tokio::sync::mpsc;
use tonic::Status;

struct Porter {
	uid: String,
}

#[async_trait::async_trait]
impl Handler for Porter {
	async fn on_request(&mut self, request: &ProcessingRequest) {
		let attributes = &request.attributes["envoy.filters.http.ext_proc"];
		let value =
			|name: &str| http::envoy_proto_common::prost_value_to_json(&attributes.fields[name]).unwrap();
		assert_eq!(value("certificate"), "verified-certificate");
		assert_eq!(value("principal"), "spiffe://mesh.test/ns/demo/sa/client");
		assert_eq!(value("peer"), "10.0.0.1");
		self.uid = value("sandbox").as_str().unwrap().to_owned();
	}

	async fn handle_request_headers(
		&mut self,
		headers: &HttpHeaders,
		sender: &mpsc::Sender<Result<ProcessingResponse, Status>>,
	) -> Result<(), Status> {
		assert!(
			headers
				.headers
				.as_ref()
				.unwrap()
				.headers
				.iter()
				.any(|h| h.key == ":method" && h.value == "CONNECT")
		);
		if self.uid == "deny" {
			sender
				.send(immediate_response(proto::ImmediateResponse {
					status: Some(proto::HttpStatus { code: 403 }),
					..Default::default()
				}))
				.await
				.unwrap();
			return Ok(());
		}
		if self.uid == "timeout" {
			tokio::time::sleep(Duration::from_secs(1)).await;
			return Ok(());
		}
		let metadata = serde_json::from_value(json!({"agentio": {
				"workload": {"uid": self.uid, "name": "pod", "namespace": "demo"},
				"sni": {"policy": {"rules": [
						{"match": {"sni": ["blocked.example"]}, "action": "SNI_ACTION_DENY"},
						{"match": {"sni": ["*.example"]}, "action": "SNI_ACTION_TLS_TERMINATION"}
				]}}
		}}))
		.unwrap();
		sender
			.send(request_header_response_with_dynamic_metadata(
				None, metadata,
			))
			.await
			.unwrap();
		Ok(())
	}
}

#[tokio::test]
async fn hbone_processor_identity_is_per_tunnel_and_fail_closed() {
	let porter = ExtProcMock::new(|| Porter { uid: String::new() })
		.spawn()
		.await;
	let proxy = setup_proxy_test("{}").unwrap().with_backend(porter.address);
	let policy: HboneExtProc = serde_json::from_value(json!({
			"host": porter.address,
			"timeout": "100ms",
			"tlsExclusions": ["skip.example"],
			"tlsInclusions": ["static.test"],
			"requestAttributes": {
					"certificate": "source.certificate",
					"principal": "source.spiffeId",
					"peer": "string(source.rawAddress)",
					"sandbox": "source.connectHeaders['x-agentio-sandbox-uid']"
			}
	}))
	.unwrap();
	let mut connection = Extension::new();
	connection.insert(TCPConnectionInfo {
		peer_addr: "10.0.0.1:1234".parse().unwrap(),
		local_addr: "10.0.0.2:15008".parse().unwrap(),
		start: std::time::Instant::now(),
		raw_peer_addr: None,
	});
	connection.insert(TLSConnectionInfo {
		src_identity: Some(crate::transport::tls::TlsInfo {
			spiffe_id: Some("spiffe://mesh.test/ns/demo/sa/client".into()),
			certificate: Some("verified-certificate".into()),
			..Default::default()
		}),
		..Default::default()
	});
	let mut contexts = Vec::new();
	for uid in ["sandbox-a", "sandbox-b", "deny", "timeout"] {
		let mut headers = http::HeaderMap::new();
		headers.insert("x-agentio-sandbox-uid", uid.parse().unwrap());
		headers.insert("x-agentio-workload-name", "forged-pod".parse().unwrap());
		headers.insert("x-agentio-sandbox-token", "secret-token".parse().unwrap());
		let result = authorize(
			proxy.inputs(),
			&"203.0.113.1:443".parse().unwrap(),
			&headers,
			&connection,
			&policy,
		)
		.await;
		match uid {
			"deny" => assert_eq!(result.unwrap_err(), http::StatusCode::FORBIDDEN),
			"timeout" => assert_eq!(result.unwrap_err(), http::StatusCode::GATEWAY_TIMEOUT),
			_ => {
				let context = result.unwrap();
				assert!(!format!("{context:?}").contains("secret-token"));
				assert_eq!(
					context.source.connect_metadata.as_ref().unwrap().0["agentio"]["workload"]["uid"],
					uid
				);
				contexts.push(context);
			},
		}
	}
	assert!(connection.get::<HboneContext>().is_none());
	assert_ne!(
		contexts[0].source.connect_metadata.as_ref().unwrap().0,
		contexts[1].source.connect_metadata.as_ref().unwrap().0
	);
	let mut stream = Extension::wrap(Arc::new(connection));
	stream.insert(contexts.remove(0));
	assert_eq!(tls_termination(&stream, "api.example").unwrap(), Some(true));
	assert_eq!(
		tls_termination(&stream, "skip.example").unwrap(),
		Some(false)
	);
	assert_eq!(tls_termination(&stream, "static.test").unwrap(), Some(true));
	assert_eq!(tls_termination(&stream, "other.test").unwrap(), Some(false));
	assert!(tls_termination(&stream, "blocked.example").is_err());
	let context = stream.get::<HboneContext>().unwrap();
	let executor = crate::cel::Executor::new_source(&context.source);
	assert!(executor.eval_bool(
		&Expression::new_strict("source.connectMetadata.agentio.workload.uid == 'sandbox-a'").unwrap()
	));
}

#[test]
fn epe_target_updates_are_owned_by_the_authorizing_processor() {
	let owner = Arc::new(());
	let mut request = ::http::Request::new(http::Body::empty());
	request.extensions_mut().insert(ActiveProcessor(owner));
	for target in ["192.0.2.1:443", "[2001:db8::1]:8443"] {
		let metadata =
			serde_json::from_value(json!({"agentio.route": {"upstream": {"address": target}}})).unwrap();
		pin_authorized_target(&mut request, &metadata).unwrap();
		assert_eq!(
			request
				.extensions()
				.get::<DynamicBackendOverride>()
				.unwrap()
				.0
				.to_string(),
			target
		);
	}
	request
		.extensions_mut()
		.insert(ActiveProcessor(Arc::new(())));
	let metadata =
		serde_json::from_value(json!({"agentio.route": {"upstream": {"address": "192.0.2.2:80"}}}))
			.unwrap();
	assert!(pin_authorized_target(&mut request, &metadata).is_err());
	assert_eq!(
		request
			.extensions()
			.get::<DynamicBackendOverride>()
			.unwrap()
			.0
			.to_string(),
		"[2001:db8::1]:8443"
	);
	for target in ["evil.example:443", "unix:/admin.sock", "192.0.2.1:0"] {
		let metadata =
			serde_json::from_value(json!({"agentio.route": {"upstream": {"address": target}}})).unwrap();
		assert!(pin_authorized_target(&mut request, &metadata).is_err());
	}
}

struct EpeTarget {
	address: String,
}

#[async_trait::async_trait]
impl Handler for EpeTarget {
	async fn handle_request_headers(
		&mut self,
		_: &HttpHeaders,
		sender: &mpsc::Sender<Result<ProcessingResponse, Status>>,
	) -> Result<(), Status> {
		let metadata =
			serde_json::from_value(json!({"agentio.route": {"upstream": {"address": self.address}}}))
				.unwrap();
		sender
			.send(request_header_response_with_dynamic_metadata(
				None, metadata,
			))
			.await
			.unwrap();
		Ok(())
	}
}

#[tokio::test]
async fn epe_metadata_controls_the_connection_without_a_routing_expression() {
	use crate::test_helpers::proxymock::{basic_named_route, simple_bind, simple_mock};
	use crate::types::agent::{Backend, ResourceName};

	let origin = simple_mock().await;
	let address = origin.address().to_string();
	let processor = ExtProcMock::new(move || EpeTarget {
		address: address.clone(),
	})
	.spawn()
	.await;
	let backend = Backend::Dynamic(
		ResourceName::new("authorized-target".into(), "".into()),
		None,
	);
	let route = basic_named_route(backend.name());
	let proxy = setup_proxy_test("{}")
		.unwrap()
		.with_raw_backend(backend.into())
		.with_backend(processor.address)
		.with_bind(simple_bind())
		.with_route(route)
		.attach_route_policy_builder(
			json!({"extProc": {"host": processor.address, "failureMode": "failClosed"}}),
		)
		.await;
	let response = crate::proxy::request_builder::RequestBuilder::new(
		::http::Method::GET,
		"http://must-not-resolve.invalid/",
	)
	.send(proxy.serve_http("bind".into()))
	.await
	.unwrap();
	assert_eq!(response.status(), 200);
}
