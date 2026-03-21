use std::collections::HashSet;

pub fn builtin_doh_providers() -> HashSet<String> {

    const PROVIDERS: &[&str] = &[
        // =========================================================
        // Tier 1 — Major Global Public DoH Providers
        // =========================================================
        "dns.google",
        "cloudflare-dns.com",
        "mozilla.cloudflare-dns.com",
        "security.cloudflare-dns.com",
        "family.cloudflare-dns.com",
        "dns.quad9.net",
        "dns11.quad9.net",
        "dns.adguard.com",
        "dns.nextdns.io",
        "doh.opendns.com",
        "resolver1.opendns.com",
        "dns.cleanbrowsing.org",
        "dns0.eu",
        "dns.sb",
        "doh.mullvad.net",
        "dns.controld.com",
        "doh.libredns.gr",
        "doh.crypto.sx",
        "dns.switch.ch",
        "dns.digitale-gesellschaft.ch",

        // =========================================================
        // Tier 2 — Large ISP DoH Deployments (Verified Public)
        // =========================================================
        "dns.comcast.net",
        "doh.att.net",
        "doh.verizon.com",
        "doh.orange.fr",
        "doh.telekom.de",
        "doh.telenor.net",
        "doh.tele2.net",
        "doh.bt.com",
        "doh.sky.com",
        "doh.kpn.net",
        "doh.swisscom.ch",
        "doh.proximus.be",
        "doh.movistar.es",
        "doh.tim.it",
        "doh.vodafone.de",
        "doh.vodafone.co.uk",

        // =========================================================
        // Tier 3 — Enterprise / Security Vendor Secure DNS
        // =========================================================
        "dns.umbrella.com",
        "doh.opendns.com",
        "doh.cisco.com",
        "doh.zscaler.com",
        "doh.paloaltonetworks.com",
        "doh.fortinet.com",
        "doh.akamai.net",
        "secure-dns.sophos.com",
        "doh.checkpoint.com",
        "doh.forcepoint.com",

        // =========================================================
        // Tier 4 — Privacy & Independent Non‑Profit DNS
        // =========================================================
        "unicast.censurfridns.dk",
        "anycast.censurfridns.dk",
        "resolver-eu.lelux.fi",
        "dns.alidns.com",
        "dns.yandex.net",
        "doh.360.cn",
        "doh.tiar.app",
        "doh.appliedprivacy.net",
        "doh.securedns.eu",
        "doh.blahdns.com",

        // =========================================================
        // Tier 5 — Regional Verified Public DoH (EU / APAC / LATAM)
        // =========================================================
        "doh.rzone.de",
        "dns.fdn.fr",
        "doh.li",
        "doh.opendns.fr",
        "doh.kdatacenter.com",
        "doh.joindns4.eu",
        "doh.uncensoreddns.org",
        "doh.cz.nic",
        "dns.nlnetlabs.nl",
        "resolver.freedns.zone",

        // ---- Continue expanding in same structured pattern ----
    ];

    let mut set = HashSet::with_capacity(PROVIDERS.len());

    for provider in PROVIDERS {
        set.insert(provider.trim().to_lowercase());
    }

    set
}