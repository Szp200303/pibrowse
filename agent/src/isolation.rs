// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Bogdan Shapovalov and the Fury authors

//! Account-isolation policy for this machine.
//!
//! The browser already has one data directory and one relay per profile.  This
//! policy turns the remaining operational rules into launch-time invariants:
//! a profile must have a proxy, its real exit must be known, no other profile
//! may own that proxy or exit, and only a bounded number may run at once.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// Canonicalise an address returned by the exit checker and reject addresses
/// that cannot be a public proxy exit.
pub fn public_ip(raw: &str) -> Option<String> {
    let ip: std::net::IpAddr = raw.trim().parse().ok()?;
    let public = match ip {
        std::net::IpAddr::V4(ip) => {
            let [a, b, _, _] = ip.octets();
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_broadcast()
                && !ip.is_documentation()
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && !(a == 100 && (64..=127).contains(&b))
                && !(a == 198 && matches!(b, 18 | 19))
                && a < 224
        }
        std::net::IpAddr::V6(ip) => {
            !ip.is_loopback()
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && !ip.is_unique_local()
                && !ip.is_unicast_link_local()
                && ip.segments()[0..2] != [0x2001, 0x0db8]
        }
    };
    public.then(|| ip.to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    /// When false, PiBrowse keeps its original permissive behaviour.
    pub strict: bool,
    /// Active and currently-launching browsers both count towards this limit.
    pub max_concurrent_profiles: usize,
    /// Ignore a profile's `allow_no_proxy` escape hatch in strict mode.
    pub require_proxy: bool,
    /// Ask through the proxy on every launch instead of trusting a cached IP.
    pub check_exit_on_every_launch: bool,
    /// A saved proxy may belong to only one profile.
    pub unique_proxy_per_profile: bool,
    /// Two proxy records that terminate at the same public IP still conflict.
    pub unique_exit_ip: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            strict: true,
            max_concurrent_profiles: 5,
            require_proxy: true,
            check_exit_on_every_launch: true,
            unique_proxy_per_profile: true,
            unique_exit_ip: true,
        }
    }
}

impl Policy {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            let policy = Self::default();
            let bytes = serde_json::to_vec_pretty(&policy)?;
            std::fs::write(path, bytes)?;
            return Ok(policy);
        }

        let policy: Self = serde_json::from_slice(&std::fs::read(path)?)?;
        policy.validate()?;
        Ok(policy)
    }

    fn validate(&self) -> anyhow::Result<()> {
        if !(1..=100).contains(&self.max_concurrent_profiles) {
            anyhow::bail!("max_concurrent_profiles must be between 1 and 100");
        }
        if self.strict
            && (!self.require_proxy
                || !self.check_exit_on_every_launch
                || !self.unique_proxy_per_profile
                || !self.unique_exit_ip)
        {
            anyhow::bail!(
                "strict isolation requires require_proxy, check_exit_on_every_launch, unique_proxy_per_profile and unique_exit_ip"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_the_ten_profile_windows_policy() {
        let p = Policy::default();
        assert!(p.strict && p.require_proxy && p.unique_proxy_per_profile && p.unique_exit_ip);
        assert_eq!(p.max_concurrent_profiles, 5);
    }

    #[test]
    fn an_exit_cannot_be_unique_if_launches_do_not_check_it() {
        let p = Policy {
            check_exit_on_every_launch: false,
            ..Policy::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn only_public_exit_addresses_are_accepted() {
        assert_eq!(public_ip("8.8.8.8").as_deref(), Some("8.8.8.8"));
        assert_eq!(
            public_ip("2606:4700:4700::1111").as_deref(),
            Some("2606:4700:4700::1111")
        );
        for local in [
            "127.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "192.168.1.2",
            "::1",
            "fd00::1",
            "fe80::1",
        ] {
            assert!(public_ip(local).is_none(), "accepted {local}");
        }
    }
}
