// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use prometheus_client::{
    encoding::{EncodeLabelSet, text::encode},
    metrics::{counter::Counter, family::Family, gauge::Gauge, histogram::Histogram},
    registry::Registry,
};
use std::sync::Arc;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct Protocol {
    pub protocol: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ResourceType {
    pub resource_type: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct DemandResult {
    pub resource_type: &'static str,
    pub result: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ConnectResult {
    pub protocol: &'static str,
    pub result: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct Eviction {
    pub resource_type: &'static str,
    pub reason: &'static str,
}

fn histogram() -> Histogram {
    Histogram::new([
        0.0005, 0.001, 0.002, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 4.0, 8.0,
    ])
}

pub struct Metrics {
    pub cache: Gauge,
    pub connected: Gauge,
    pub connect: Family<Protocol, Histogram, fn() -> Histogram>,
    pub waiters: Family<ResourceType, Gauge>,
    pub wait: Family<DemandResult, Histogram, fn() -> Histogram>,
    pub connect_results: Family<ConnectResult, Counter>,
    pub cache_lookups: Family<DemandResult, Counter>,
    pub cache_evictions: Family<Eviction, Counter>,
    pub reconnects: Counter,
    pub nacks: Family<ResourceType, Counter>,
    registry: Registry,
}

impl Metrics {
    pub fn new() -> Arc<Self> {
        let cache = Gauge::default();
        let connected = Gauge::default();
        let connect = Family::new_with_constructor(histogram as fn() -> Histogram);
        let wait = Family::new_with_constructor(histogram as fn() -> Histogram);
        let waiters = Family::default();
        let connect_results = Family::default();
        let cache_lookups = Family::default();
        let cache_evictions = Family::default();
        let reconnects = Counter::default();
        let nacks = Family::default();
        let mut registry = Registry::default();
        registry.register(
            "agentio_porter_connect_requests",
            "Valid CONNECT attempts completed by handler outcome, excluding response transmission",
            connect_results.clone(),
        );
        registry.register(
            "agentio_porter_demand_cache_lookups",
            "Demand calls with a ready cached value (hit) or without one (miss), counted once per call",
            cache_lookups.clone(),
        );
        registry.register(
            "agentio_porter_demand_cache_evictions",
            "Idle retained subscriptions evicted by TTL or capacity; excludes deletion and failed lookups",
            cache_evictions.clone(),
        );
        registry.register(
            "agentio_xds_client_reconnects",
            "ADS connection retry attempts, excluding the initial attempt",
            reconnects.clone(),
        );
        registry.register(
            "agentio_xds_client_nacks",
            "Rejected ADS responses generating NACKs; pending responses may be coalesced",
            nacks.clone(),
        );
        registry.register(
            "agentio_porter_demand_cache_entries",
            "Retained demand subscriptions",
            cache.clone(),
        );
        registry.register(
            "agentio_xds_client_connected",
            "ADS stream connected",
            connected.clone(),
        );
        registry.register(
            "agentio_porter_connect_duration_seconds",
            "CONNECT processing duration",
            connect.clone(),
        );
        registry.register(
            "agentio_xds_client_demand_wait_duration_seconds",
            "Demand waiting duration",
            wait.clone(),
        );
        registry.register(
            "agentio_xds_client_demand_waiters",
            "Waiting demand calls",
            waiters.clone(),
        );
        Arc::new(Self {
            cache,
            connected,
            connect,
            wait,
            waiters,
            connect_results,
            cache_lookups,
            cache_evictions,
            reconnects,
            nacks,
            registry,
        })
    }

    pub fn encode(&self) -> Result<String, std::fmt::Error> {
        let mut s = String::new();
        encode(&mut s, &self.registry)?;
        Ok(s)
    }
}
