// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use moka::{Expiry, future::Cache};
use tonic::{Code, Request, transport::Channel};

use super::{DemandError, TransportConfig};
use crate::{
    view::{self, View},
    wire::agentio::sandbox::{
        GetSandboxRequest, sandbox_query_service_client::SandboxQueryServiceClient,
    },
};

#[derive(Clone)]
struct Cached {
    value: Option<Arc<View>>,
    ttl: Duration,
}

struct PolicyExpiry;
impl Expiry<String, Cached> for PolicyExpiry {
    fn expire_after_create(&self, _: &String, value: &Cached, _: Instant) -> Option<Duration> {
        Some(value.ttl)
    }
}

pub(super) struct SandboxQuery {
    transport: TransportConfig,
    channel: Mutex<Option<Channel>>,
    cache: Cache<String, Cached>,
}

impl SandboxQuery {
    pub(super) fn new(transport: TransportConfig, max_entries: usize) -> Self {
        let mut builder = Cache::builder().expire_after(PolicyExpiry);
        if max_entries != 0 {
            builder = builder.max_capacity(max_entries as u64);
        }
        Self {
            transport,
            channel: Mutex::new(None),
            cache: builder.build(),
        }
    }

    pub(super) fn connected(&self, channel: Channel) {
        *self.channel.lock().unwrap() = Some(channel);
    }

    pub(super) async fn get(&self, name: &str) -> Result<Arc<View>, DemandError> {
        let entry = self
            .cache
            .try_get_with_by_ref(name, async {
                let channel = self
                    .channel
                    .lock()
                    .unwrap()
                    .clone()
                    .ok_or(DemandError::Closed)?;
                let node = &self.transport.node;
                let mut req = Request::new(GetSandboxRequest {
                    name: name.to_owned(),
                    node_id: node.id.clone(),
                    node_metadata: node.metadata.clone(),
                });
                let token = self.transport.bearer().await.map_err(|err| {
                    tracing::warn!(error=%err, "read Sandbox query credential");
                    DemandError::Query(Code::Unauthenticated)
                })?;
                req.metadata_mut().insert("authorization", token);
                // The caller's CONNECT budget bounds its own wait on this shared lookup.
                req.set_timeout(Duration::from_secs(4));
                let reply = SandboxQueryServiceClient::new(channel)
                    .max_decoding_message_size(i32::MAX as usize)
                    .get_sandbox(req)
                    .await
                    .map_err(|s| DemandError::Query(s.code()))?
                    .into_inner();
                let ttl: Duration = reply
                    .cache_ttl
                    .filter(|t| {
                        (0..=315_576_000_000).contains(&t.seconds)
                            && (0..1_000_000_000).contains(&t.nanos)
                    })
                    .ok_or(DemandError::Query(Code::DataLoss))?
                    .try_into()
                    .map_err(|_| DemandError::Query(Code::DataLoss))?;
                let value = reply
                    .sandbox
                    .map(|s| {
                        if s.uid.is_empty() {
                            return Err(DemandError::Query(Code::DataLoss));
                        }
                        view::sandbox_view(s).map(Arc::new).map_err(|err| {
                            tracing::warn!(error=%err, "invalid Sandbox query response");
                            DemandError::Query(Code::DataLoss)
                        })
                    })
                    .transpose()?;
                Ok::<_, DemandError>(Cached { value, ttl })
            })
            .await
            .map_err(|e| *e)?;
        entry.value.ok_or(DemandError::NotFound)
    }
}
