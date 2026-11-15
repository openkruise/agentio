// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use crate::connection::Policy;
use std::{
    cell::{OnceCell, RefCell},
    collections::{HashMap, hash_map::DefaultHasher},
    hash::Hasher,
    rc::Rc,
};

pub const JSON_KEY: &[u8] = b"agentio.connection.policy_json";
pub const HASH_KEY: &[u8] = b"agentio.connection.policy_hash";

thread_local! {
    static POLICIES: RefCell<HashMap<u64, Rc<Entry>>> = RefCell::new(HashMap::new());
}

struct Entry {
    hash: u64,
    json: Box<[u8]>,
    policy: OnceCell<Result<Policy, String>>,
}

// Each long-lived consumer owns a handle, including while TCP waits for DNS.
#[derive(Clone)]
pub struct SharedPolicy(Rc<Entry>);

impl SharedPolicy {
    pub fn intern(json: &[u8]) -> Result<Self, &'static str> {
        let mut hasher = DefaultHasher::new();
        hasher.write(json);
        Self::insert(hasher.finish(), json)
    }

    fn insert(hash: u64, json: &[u8]) -> Result<Self, &'static str> {
        POLICIES.with(|policies| {
            let mut policies = policies.borrow_mut();
            if let Some(entry) = policies.get(&hash) {
                if entry.json.as_ref() != json {
                    return Err("connection policy hash collision");
                }
                return Ok(Self(entry.clone()));
            }
            let entry = Rc::new(Entry {
                hash,
                json: json.into(),
                policy: OnceCell::new(),
            });
            policies.insert(hash, entry.clone());
            Ok(Self(entry))
        })
    }

    pub fn lookup(hash: &[u8]) -> Option<Self> {
        let hash = std::str::from_utf8(hash).ok()?.parse::<u64>().ok()?;
        POLICIES.with(|policies| policies.borrow().get(&hash).cloned().map(Self))
    }

    pub fn hash(&self) -> u64 {
        self.0.hash
    }

    pub fn policy(&self) -> Result<&Policy, &str> {
        self.0
            .policy
            .get_or_init(|| Policy::parse(&self.0.json))
            .as_ref()
            .map_err(String::as_str)
    }
}

// A connection borrows a prefix of its immutable snapshot without copying profiles.
pub struct TcpPolicyView {
    shared: SharedPolicy,
    end: usize,
}

impl SharedPolicy {
    pub fn tcp_view(self, end_before: Option<&[u8]>) -> Result<TcpPolicyView, String> {
        let policy = self.policy().map_err(str::to_owned)?;
        let end = match end_before {
            Some(uid) => {
                let uid = std::str::from_utf8(uid).map_err(|_| "invalid TCP policy range")?;
                policy
                    .start(uid)
                    .map_err(|_| "TCP policy range is unavailable")?
            }
            None => policy.profiles.len(),
        };
        Ok(TcpPolicyView { shared: self, end })
    }
}

impl TcpPolicyView {
    pub fn permits(&self, target: std::net::SocketAddr) -> bool {
        self.shared
            .policy()
            .expect("validated TCP policy view")
            .permits(target, self.end)
    }
}

impl Drop for SharedPolicy {
    fn drop(&mut self) {
        // The final consumer and the table are the only remaining owners.
        if Rc::strong_count(&self.0) == 2 {
            POLICIES.with(|policies| policies.borrow_mut().remove(&self.0.hash));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Action;

    #[test]
    fn shares_lazy_policy_and_reclaims_after_the_last_consumer() {
        let outer = SharedPolicy::intern(br#"{"profiles":[]}"#).unwrap();
        assert!(outer.0.policy.get().is_none());
        let hash = outer.hash().to_string();
        let sni = SharedPolicy::lookup(hash.as_bytes()).unwrap();
        let tcp = SharedPolicy::intern(br#"{"profiles":[]}"#).unwrap();
        assert!(Rc::ptr_eq(&outer.0, &tcp.0));
        assert!(std::ptr::eq(sni.policy().unwrap(), tcp.policy().unwrap()));
        drop(outer);
        drop(sni);
        assert!(SharedPolicy::lookup(hash.as_bytes()).is_some());
        drop(tcp);
        assert!(SharedPolicy::lookup(hash.as_bytes()).is_none());
    }

    #[test]
    fn policy_updates_keep_old_connections_on_their_original_snapshot() {
        let old = SharedPolicy::intern(br#"{"profiles":[{"uid":"a","sniPolicy":{"rules":[{"match":{"sni":["*"]},"action":"SNI_ACTION_PASSTHROUGH"}]}}]}"#).unwrap();
        let new = SharedPolicy::intern(br#"{"profiles":[{"uid":"a","sniPolicy":{"rules":[{"match":{"sni":["*"]},"action":"SNI_ACTION_DENY"}]}}]}"#).unwrap();
        assert_ne!(old.hash(), new.hash());
        let target = "203.0.113.1:443".parse().unwrap();
        assert_eq!(
            old.policy()
                .unwrap()
                .evaluate_sni(Some("api.test"), target)
                .unwrap()
                .0,
            Action::Passthrough
        );
        assert_eq!(
            new.policy().unwrap().evaluate_sni(Some("api.test"), target),
            Err("sni_policy_denied")
        );
        let hash = old.hash().to_string();
        drop(new);
        assert!(SharedPolicy::lookup(hash.as_bytes()).is_some());
    }

    #[test]
    fn invalid_policy_is_cached_as_an_error_and_never_an_allow() {
        let policy = SharedPolicy::intern(b"invalid").unwrap();
        assert!(policy.policy().is_err());
        let first = policy.0.policy.get().unwrap();
        assert!(policy.policy().is_err());
        assert!(std::ptr::eq(first, policy.0.policy.get().unwrap()));
        assert!(SharedPolicy::lookup(b"invalid").is_none());
        assert!(SharedPolicy::lookup(b"18446744073709551616").is_none());
    }

    #[test]
    fn collisions_fail_closed_without_replacing_the_existing_policy() {
        let old = SharedPolicy::insert(1, br#"{"profiles":[]}"#).unwrap();
        assert!(SharedPolicy::insert(1, b"different").is_err());
        let found = SharedPolicy::lookup(b"1").unwrap();
        assert!(Rc::ptr_eq(&old.0, &found.0));
    }

    #[test]
    fn tcp_views_retain_the_snapshot_and_validate_their_range() {
        let owner = SharedPolicy::intern(br#"{"profiles":[{"uid":"first"},{"uid":"matched","tcpPolicy":{"rules":[{"name":"deny","match":[{}],"action":"TCP_ACTION_DENY"}]}}]}"#).unwrap();
        let hash = owner.hash().to_string();
        let prefix = owner.clone().tcp_view(Some(b"matched")).unwrap();
        let full = owner.clone().tcp_view(None).unwrap();
        assert!(owner.clone().tcp_view(Some(b"missing")).is_err());
        assert!(owner.clone().tcp_view(Some(b"\xff")).is_err());
        drop(owner);
        let target = "203.0.113.8:443".parse().unwrap();
        assert!(prefix.permits(target));
        assert!(!full.permits(target));
        drop(full);
        assert!(SharedPolicy::lookup(hash.as_bytes()).is_some());
        drop(prefix);
        assert!(SharedPolicy::lookup(hash.as_bytes()).is_none());
    }

    #[test]
    fn stores_are_worker_local() {
        let policy = SharedPolicy::intern(br#"{"profiles":[]}"#).unwrap();
        let hash = policy.hash().to_string();
        std::thread::spawn(move || assert!(SharedPolicy::lookup(hash.as_bytes()).is_none()))
            .join()
            .unwrap();
    }
}
