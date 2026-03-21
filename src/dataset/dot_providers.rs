// snf_core/src/dataset/dot_providers.rs

use std::collections::HashSet;

pub fn builtin_dot_providers() -> HashSet<String> {
    const PROVIDERS: &[&str] = &[
        // =========================================================
        // Tier 1 — Major Public DoT Providers (Standard Port 853)
        // =========================================================
        "dns.google",
        "cloudflare-dns.com",
        "dns.quad9.net",
        "dns11.quad9.net",
        "dns.adguard.com",
        "dns.nextdns.io",
        "dns.cleanbrowsing.org",
        "dns0.eu",
        "dns.switch.ch",
        "dns.sb",
        "doh.mullvad.net",
        "dns.controld.com",
        "dns.digitale-gesellschaft.ch",
        "unicast.censurfridns.dk",
        "anycast.censurfridns.dk",
        "dns.fdn.fr",
        "doh.li",
        "dns.nlnetlabs.nl",
        "resolver.freedns.zone",
    ];

    let mut set = HashSet::with_capacity(PROVIDERS.len());
    for provider in PROVIDERS {
        set.insert(provider.trim().to_lowercase());
    }

    set
}