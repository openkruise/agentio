// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::wire::agentio::sandbox::{
    GetSandboxRequest, GetSandboxResponse, Sandbox,
    sandbox_query_service_server::{SandboxQueryService, SandboxQueryServiceServer},
};
use std::sync::atomic::AtomicUsize;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{
    Code, Status,
    transport::{Channel, Endpoint, Server},
};

#[derive(Default)]
struct Service {
    values: Mutex<HashMap<String, Sandbox>>,
    ttl: Mutex<Duration>,
    calls: AtomicUsize,
}

#[tonic::async_trait]
impl SandboxQueryService for Arc<Service> {
    async fn get_sandbox(
        &self,
        req: tonic::Request<GetSandboxRequest>,
    ) -> Result<tonic::Response<GetSandboxResponse>, Status> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if req
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            != Some("Bearer token")
            || req.get_ref().node_id != "porter"
        {
            return Err(Status::unauthenticated("invalid identity"));
        }
        let reply = GetSandboxResponse {
            sandbox: self
                .values
                .lock()
                .unwrap()
                .get(&req.get_ref().name)
                .cloned(),
            cache_ttl: Some((*self.ttl.lock().unwrap()).try_into().unwrap()),
        };
        Ok(tonic::Response::new(reply))
    }
}

pub(super) struct QueryFixture {
    service: Arc<Service>,
    transport: TransportConfig,
    channel: Channel,
    _dir: tempfile::TempDir,
    server: tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
}

impl Drop for QueryFixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl QueryFixture {
    pub(super) async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let token = dir.path().join("token");
        std::fs::write(&token, "token").unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let service = Arc::new(Service::default());
        *service.ttl.lock().unwrap() = Duration::from_secs(60);
        let server = tokio::spawn(
            Server::builder()
                .add_service(SandboxQueryServiceServer::new(service.clone()))
                .serve_with_incoming(TcpListenerStream::new(listener)),
        );
        let channel = Endpoint::from_shared(format!("http://{address}"))
            .unwrap()
            .connect()
            .await
            .unwrap();
        let transport = TransportConfig {
            address,
            root_path: String::new(),
            token_path: token.to_str().unwrap().into(),
            node: Node {
                id: "porter".into(),
                ..Default::default()
            },
        };
        Self {
            service,
            transport,
            channel,
            _dir: dir,
            server,
        }
    }

    pub(super) fn client(&self) -> Arc<Client> {
        let c = Client::new_with_query(
            CacheConfig::default(),
            Metrics::new(),
            true,
            Some(self.transport.clone()),
        );
        c.query.as_ref().unwrap().connected(self.channel.clone());
        c
    }
    pub(super) fn put(&self, name: &str, sandbox: Sandbox) {
        self.service
            .values
            .lock()
            .unwrap()
            .insert(name.into(), sandbox);
    }
    pub(super) fn clear(&self) {
        self.service.values.lock().unwrap().clear();
    }
    pub(super) fn calls(&self) -> usize {
        self.service.calls.load(Ordering::Relaxed)
    }
}

#[tokio::test]
async fn sandbox_query_uses_server_ttl_coalesces_and_retries_errors() {
    let f = QueryFixture::new().await;
    let c = f.client();
    let name = "ns/host";
    let kind = ResourceKind::Sandbox;
    let fetch = || c.demand(kind, name, None);
    let sandbox = Sandbox {
        uid: "uid".into(),
        ..Default::default()
    };
    f.put(name, sandbox.clone());
    let initial = c.initial(&Node::default(), &mut Default::default());
    assert!(initial.iter().all(|r| r.type_url != kind.type_url()));
    let all = try_join_all((0..32).map(|_| fetch())).await.unwrap();
    assert!(
        all.iter()
            .all(|v| matches!(v.as_ref(), View::Sandbox(s) if s.uid=="uid"))
    );
    assert_eq!(f.calls(), 1);
    std::fs::write(&f.transport.token_path, "rotated").unwrap();
    assert!(fetch().await.is_ok());
    assert_eq!(
        c.demand(kind, "missing", None).await.unwrap_err(),
        DemandError::Query(Code::Unauthenticated)
    );
    std::fs::write(&f.transport.token_path, "token").unwrap();
    *f.service.ttl.lock().unwrap() = Duration::from_millis(100);
    for _ in 0..2 {
        assert_eq!(
            c.demand(kind, "missing", None).await.unwrap_err(),
            DemandError::NotFound
        );
    }
    assert_eq!(f.calls(), 3);
    f.put("missing", sandbox);
    *f.service.ttl.lock().unwrap() = Duration::ZERO;
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(c.demand(kind, "missing", None).await.is_ok());
    f.clear();
    assert_eq!(
        c.demand(kind, "missing", None).await.unwrap_err(),
        DemandError::NotFound
    );
    assert_eq!(f.calls(), 5);
    assert!(c.outgoing(&mut Default::default()).is_empty());
}
