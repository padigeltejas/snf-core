use std::net::IpAddr;
use crate::core::analyzer_manager::RdnsCache;
use crate::discovery::dns_cache::DnsCache;
#[derive(Debug)]
pub enum DomainSource {
    TlsSni,
    HttpHost,
    DnsCache,
    ReverseDns,
    Unknown,
}

pub struct FlowDomainBinder;

impl FlowDomainBinder {
   pub fn resolve_domain(
    dst_ip: IpAddr,
    tls_sni: Option<String>,
    http_host: Option<String>,
    dns_cache: &DnsCache,
    rdns_cache: &RdnsCache,
) -> (Option<String>, DomainSource) {

    // 1️⃣ HTTP Host (highest accuracy)
    if let Some(domain) = http_host {
        return (Some(domain), DomainSource::HttpHost);
    }

    // 2️⃣ TLS SNI
    if let Some(domain) = tls_sni {
        return (Some(domain), DomainSource::TlsSni);
    }

    // 3️⃣ DNS Cache
    if let Some(domain) = dns_cache.lookup(dst_ip) {
        return (Some(domain.clone()), DomainSource::DnsCache);
    }
    if let Some(entry) = rdns_cache.lookup(dst_ip) {
    return (Some(entry.clone()), DomainSource::ReverseDns);
}
    // 4️⃣ Unknown
    (None, DomainSource::Unknown)
}
}
