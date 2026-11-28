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
    raw: Mutex<HashMap<String, GetSandboxResponse>>,
    ttl: Mutex<Duration>,
    delay: Mutex<Duration>,
    error: Mutex<Option<Code>>,
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
        let error = *self.error.lock().unwrap();
        if let Some(code) = error {
            return Err(Status::new(code, "injected failure"));
        }
        let delay = *self.delay.lock().unwrap();
        tokio::time::sleep(delay).await;
        if let Some(reply) = self.raw.lock().unwrap().get(&req.get_ref().name) {
            return Ok(tonic::Response::new(reply.clone()));
        }
        let reply = GetSandboxResponse {
            sandbox: self
                .values
                .lock()
                .unwrap()
                .get(&req.get_ref().name)
                .cloned(),
            cache_ttl: Some((*self.ttl.lock().unwrap()).try_into().unwrap()),
            ..Default::default()
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
    pub(super) fn put_raw(&self, name: &str, response: GetSandboxResponse) {
        self.service
            .raw
            .lock()
            .unwrap()
            .insert(name.into(), response);
    }
    pub(super) fn clear(&self) {
        self.service.values.lock().unwrap().clear();
    }
    pub(super) fn calls(&self) -> usize {
        self.service.calls.load(Ordering::Relaxed)
    }
    pub(super) fn set_ttl(&self, ttl: Duration) {
        *self.service.ttl.lock().unwrap() = ttl;
    }
    pub(super) fn set_delay(&self, delay: Duration) {
        *self.service.delay.lock().unwrap() = delay;
    }
    pub(super) fn set_error(&self, code: Option<Code>) {
        *self.service.error.lock().unwrap() = code;
    }
}

fn sandbox(uid: &str) -> Sandbox {
    Sandbox {
        uid: uid.into(),
        ..Default::default()
    }
}

fn assert_query_metric(metrics: &Metrics, result: &str, count: u64) {
    let encoded = metrics.encode().unwrap();
    let line = format!("agentio_porter_sandbox_query_total{{result=\"{result}\"}} {count}");
    assert!(
        encoded.lines().any(|l| l == line),
        "missing {line} in:\n{encoded}"
    );
}

#[tokio::test]
async fn sandbox_query_uses_server_ttl_coalesces_and_retries_errors() {
    let f = QueryFixture::new().await;
    let c = f.client();
    let name = "ns/host";
    let kind = ResourceKind::Sandbox;
    let fetch = || c.demand(kind, name, None);
    f.put(name, sandbox("uid"));
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
    // Outlast the failure backoff before probing the restored credential.
    tokio::time::sleep(Duration::from_millis(400)).await;
    f.set_ttl(Duration::from_millis(100));
    for _ in 0..2 {
        assert_eq!(
            c.demand(kind, "missing", None).await.unwrap_err(),
            DemandError::NotFound
        );
    }
    assert_eq!(f.calls(), 3);
    f.put("missing", sandbox("uid"));
    f.set_ttl(Duration::ZERO);
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

#[tokio::test]
async fn initiator_cancellation_keeps_shared_fetch_alive() {
    let f = QueryFixture::new().await;
    f.set_delay(Duration::from_millis(300));
    let name = "ns/host";
    f.put(name, sandbox("uid"));
    let c = f.client();
    let kind = ResourceKind::Sandbox;
    let first = tokio::spawn({
        let c = c.clone();
        async move { c.demand(kind, name, None).await }
    });
    // Let the initiator start the shared RPC before canceling its wait.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(f.calls(), 1);
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    let value = c.demand(kind, name, None).await.unwrap();
    assert!(matches!(value.as_ref(), View::Sandbox(s) if s.uid == "uid"));
    assert_eq!(f.calls(), 1);
}

#[tokio::test]
async fn concurrent_gets_coalesce_into_one_rpc() {
    let f = QueryFixture::new().await;
    f.set_delay(Duration::from_millis(100));
    let name = "ns/host";
    f.put(name, sandbox("uid"));
    let c = f.client();
    let kind = ResourceKind::Sandbox;
    let all = try_join_all((0..16).map(|_| c.demand(kind, name, None)))
        .await
        .unwrap();
    assert_eq!(all.len(), 16);
    assert!(
        all.iter()
            .all(|v| matches!(v.as_ref(), View::Sandbox(s) if s.uid == "uid"))
    );
    assert_eq!(f.calls(), 1);
}

#[tokio::test]
async fn absent_is_negative_cached_within_ttl() {
    let f = QueryFixture::new().await;
    let c = f.client();
    let kind = ResourceKind::Sandbox;
    for _ in 0..3 {
        assert_eq!(
            c.demand(kind, "missing", None).await.unwrap_err(),
            DemandError::NotFound
        );
    }
    assert_eq!(f.calls(), 1);
}

#[tokio::test]
async fn backend_error_backs_off_without_new_rpc() {
    let f = QueryFixture::new().await;
    f.set_error(Some(Code::Unavailable));
    let c = f.client();
    let kind = ResourceKind::Sandbox;
    assert_eq!(
        c.demand(kind, "ns/host", None).await.unwrap_err(),
        DemandError::Query(Code::Unavailable)
    );
    assert_eq!(f.calls(), 1);
    // An immediate retry fast-fails from backoff without contacting the backend.
    assert_eq!(
        c.demand(kind, "ns/host", None).await.unwrap_err(),
        DemandError::Query(Code::Unavailable)
    );
    assert_eq!(f.calls(), 1);
    // After the backoff window the query reaches the backend again.
    tokio::time::sleep(Duration::from_millis(400)).await;
    f.set_error(None);
    f.put("ns/host", sandbox("uid"));
    assert!(c.demand(kind, "ns/host", None).await.is_ok());
    assert_eq!(f.calls(), 2);
}

#[tokio::test]
async fn stale_served_after_failure_and_ttl_expiry() {
    let f = QueryFixture::new().await;
    f.set_ttl(Duration::from_millis(100));
    let name = "ns/host";
    f.put(name, sandbox("uid"));
    let c = f.client();
    let kind = ResourceKind::Sandbox;
    assert!(c.demand(kind, name, None).await.is_ok());
    assert_eq!(f.calls(), 1);
    // Outlast the jittered TTL so the next call must refresh from the backend.
    tokio::time::sleep(Duration::from_millis(150)).await;
    f.set_error(Some(Code::Unavailable));
    let value = c.demand(kind, name, None).await.unwrap();
    assert!(matches!(value.as_ref(), View::Sandbox(s) if s.uid == "uid"));
    assert_eq!(f.calls(), 2);
    // The backoff fast-fail path still serves the retained stale view.
    let value = c.demand(kind, name, None).await.unwrap();
    assert!(matches!(value.as_ref(), View::Sandbox(s) if s.uid == "uid"));
    assert_eq!(f.calls(), 2);
}

#[tokio::test]
async fn ttl_expiry_refreshes_from_backend() {
    let f = QueryFixture::new().await;
    f.set_ttl(Duration::from_millis(100));
    let name = "ns/host";
    f.put(name, sandbox("old"));
    let c = f.client();
    let kind = ResourceKind::Sandbox;
    let value = c.demand(kind, name, None).await.unwrap();
    assert!(matches!(value.as_ref(), View::Sandbox(s) if s.uid == "old"));
    f.put(name, sandbox("new"));
    tokio::time::sleep(Duration::from_millis(150)).await;
    let value = c.demand(kind, name, None).await.unwrap();
    assert!(matches!(value.as_ref(), View::Sandbox(s) if s.uid == "new"));
    assert_eq!(f.calls(), 2);
}

#[tokio::test]
async fn metrics_count_each_query_outcome() {
    let f = QueryFixture::new().await;
    f.set_ttl(Duration::from_millis(100));
    let name = "ns/host";
    f.put(name, sandbox("uid"));
    let c = f.client();
    let kind = ResourceKind::Sandbox;
    assert!(c.demand(kind, name, None).await.is_ok());
    assert!(c.demand(kind, name, None).await.is_ok());
    assert_eq!(
        c.demand(kind, "missing", None).await.unwrap_err(),
        DemandError::NotFound
    );
    tokio::time::sleep(Duration::from_millis(150)).await;
    f.set_error(Some(Code::Unavailable));
    assert!(c.demand(kind, name, None).await.is_ok());
    assert_eq!(
        c.demand(kind, "other", None).await.unwrap_err(),
        DemandError::Query(Code::Unavailable)
    );
    assert_eq!(
        c.demand(kind, "other", None).await.unwrap_err(),
        DemandError::Query(Code::Unavailable)
    );
    for (result, count) in [
        ("miss", 1),
        ("hit", 1),
        ("not_found", 1),
        ("stale", 1),
        ("error", 1),
        ("backoff", 1),
    ] {
        assert_query_metric(&c.metrics, result, count);
    }
}
