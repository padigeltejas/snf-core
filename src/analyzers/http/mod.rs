pub mod http_analyzer;
pub mod http2_analyzer;
use crate::core::packet_context::PacketContext;
use crate::config::engine_config::EngineConfig;
use crate::discovery::dns_cache::DnsCache;
use http_analyzer::HttpAnalyzer;

pub fn analyze(
    ctx: &mut PacketContext,
    payload: &[u8],
    dns_cache: &mut DnsCache,
    config: &EngineConfig,
) {
    let _ = HttpAnalyzer::analyze(ctx, payload, dns_cache, config);
}