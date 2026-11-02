// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::budget::Ledger;
use envoy_proxy_dynamic_modules_rust_sdk::EnvoyHttpFilterScheduler;
use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::Instant,
};

enum Task {
    Resume(Arc<dyn EnvoyHttpFilterScheduler>),
    Reap(Arc<Mutex<Ledger>>),
}

#[derive(Default)]
struct Queue {
    deadlines: BTreeMap<(Instant, u64), Task>,
    pending: HashMap<u64, Instant>,
    stop: bool,
}

impl Queue {
    // Only an earlier deadline needs to interrupt the timer thread's current wait.
    fn insert(&mut self, id: u64, due: Instant, task: Task) -> bool {
        if self.pending.get(&id) == Some(&due) {
            return false;
        }
        let wake = self
            .deadlines
            .first_key_value()
            .is_none_or(|((first, _), _)| due < *first);
        if let Some(old) = self.pending.insert(id, due) {
            self.deadlines.remove(&(old, id));
        }
        self.deadlines.insert((due, id), task);
        wake
    }

    fn reap_at(&mut self, id: u64, due: Instant, ledger: Arc<Mutex<Ledger>>) -> bool {
        // An earlier alarm safely rechecks the ledger; stale updates must not postpone cleanup.
        if self.pending.get(&id).is_none_or(|old| due < *old) {
            return self.insert(id, due, Task::Reap(ledger));
        }
        false
    }
}

pub struct Timer {
    inner: Arc<(Mutex<Queue>, Condvar)>,
    thread: Option<JoinHandle<()>>,
}

impl Timer {
    pub fn shared() -> std::io::Result<Arc<Self>> {
        // Cleanup must outlive filter configurations without leaving one idle thread per retired budget.
        static TIMER: Mutex<Option<Arc<Timer>>> = Mutex::new(None);
        let mut timer = TIMER.lock().unwrap();
        if timer.is_none() {
            *timer = Some(Arc::new(Self::new()?));
        }
        Ok(timer.as_ref().unwrap().clone())
    }

    fn new() -> std::io::Result<Self> {
        let inner = Arc::new((Mutex::new(Queue::default()), Condvar::new()));
        let shared = inner.clone();
        let thread = thread::Builder::new()
            .name("bandwidth-timer".into())
            .spawn(move || {
                let (mutex, changed) = &*shared;
                let mut queue = mutex.lock().unwrap();
                loop {
                    if queue.stop {
                        break;
                    }
                    let Some((&(due, id), _)) = queue.deadlines.first_key_value() else {
                        queue = changed.wait(queue).unwrap();
                        continue;
                    };
                    let now = Instant::now();
                    if due > now {
                        queue = changed.wait_timeout(queue, due - now).unwrap().0;
                        continue;
                    }
                    let (_, task) = queue.deadlines.pop_first().unwrap();
                    queue.pending.remove(&id);
                    match task {
                        Task::Resume(scheduler) => {
                            // cancel() must quiesce commits before stream teardown.
                            scheduler.commit(0);
                        }
                        Task::Reap(ledger) => {
                            drop(queue);
                            let next = ledger.lock().unwrap().reap(now);
                            queue = mutex.lock().unwrap();
                            if let Some(next) = next {
                                // Give already-due stream callbacks a turn between cleanup batches.
                                queue.reap_at(id, next.max(Instant::now()), ledger);
                            }
                        }
                    }
                }
            })?;
        Ok(Self {
            inner,
            thread: Some(thread),
        })
    }

    pub fn id(&self) -> u64 {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    }

    pub fn reap_at(&self, id: u64, due: Instant, ledger: Arc<Mutex<Ledger>>) {
        let wake = self.inner.0.lock().unwrap().reap_at(id, due, ledger);
        if wake {
            self.inner.1.notify_one();
        }
    }

    pub fn schedule(&self, id: u64, due: Instant, scheduler: Arc<dyn EnvoyHttpFilterScheduler>) {
        let wake = self
            .inner
            .0
            .lock()
            .unwrap()
            .insert(id, due, Task::Resume(scheduler));
        if wake {
            self.inner.1.notify_one();
        }
    }

    pub fn cancel(&self, id: u64) {
        let mut queue = self.inner.0.lock().unwrap();
        if let Some(due) = queue.pending.remove(&id) {
            queue.deadlines.remove(&(due, id));
        }
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        self.inner.0.lock().unwrap().stop = true;
        self.inner.1.notify_one();
        self.thread.take().unwrap().join().unwrap();
    }
}
