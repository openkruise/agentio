// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use crate::tcp::Prefix;
use std::net::SocketAddr;

pub const UPSTREAM_KEY: &[u8] = b"agentio.route.upstream";
pub const PIN_KEY: &[u8] = b"envoy.network.transport_socket.original_dst_address";

pub fn select(
    candidates: Vec<SocketAddr>,
    denied: &[Prefix],
    permits: impl Fn(SocketAddr) -> bool,
) -> Option<SocketAddr> {
    candidates.into_iter().find(|target| {
        !denied.iter().any(|prefix| prefix.contains(target.ip())) && permits(*target)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exclusions_and_connection_policy_both_apply() {
        let denied =
            serde_json::from_str::<Vec<Prefix>>(r#"["127.0.0.0/8", "2001:db8::/32"]"#).unwrap();
        let addresses = [
            "127.0.0.1:80",
            "[::ffff:127.0.0.1]:80",
            "[2001:db8::1]:80",
            "192.0.2.1:80",
            "192.0.2.2:80",
        ]
        .map(|s| s.parse().unwrap())
        .to_vec();
        assert_eq!(
            select(addresses.clone(), &denied, |_| true),
            Some("192.0.2.1:80".parse().unwrap())
        );
        assert_eq!(
            select(addresses.clone(), &denied, |a| a.ip().to_string()
                != "192.0.2.1"),
            Some("192.0.2.2:80".parse().unwrap())
        );
        assert_eq!(select(addresses, &denied, |_| false), None);
    }
}
