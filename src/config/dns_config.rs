#[derive(Clone)]
pub struct DnsConfig {
    pub enable_dns_cache: bool,
    pub dns_cache_size: usize,
    pub dns_cache_ttl: u64,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enable_dns_cache: true,
            dns_cache_size: 5000,
            dns_cache_ttl: 300,
        }
    }
}
