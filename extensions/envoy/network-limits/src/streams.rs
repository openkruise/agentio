// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use envoy_proxy_dynamic_modules_rust_sdk::EnvoyHttpFilterScheduler;
use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

#[derive(Default)]
pub struct Streams {
    pub generation: u64,
    pub handles: HashMap<u64, Arc<dyn EnvoyHttpFilterScheduler>>,
    pub pending: HashSet<u64>,
}

impl Streams {
    pub fn id() -> u64 {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        NEXT.fetch_add(1, Ordering::Relaxed)
    }
    pub fn changed(&mut self) {
        self.generation += 1;
        self.pending = self.handles.keys().copied().collect();
        self.notify();
    }
    pub fn notify(&self) {
        for scheduler in self.handles.values() {
            scheduler.commit(self.generation);
        }
    }
    pub fn ready(&mut self, id: u64) {
        if self.pending.remove(&id) && self.pending.is_empty() {
            self.notify();
        }
    }
    pub fn remove(&mut self, id: u64) {
        self.handles.remove(&id);
        self.ready(id);
    }
}
