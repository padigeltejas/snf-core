// src/analyzers/quic/mod.rs

pub mod quic_sni;

use crate::core::packet_context::PacketContext;
use crate::config::engine_config::EngineConfig;
use crate::discovery::dns_cache::DnsCache;
use crate::core::parse_error::ParseResult;

pub fn analyze(
    ctx: &mut PacketContext,
    payload: &[u8],
    _dns_cache: &mut DnsCache,
    config: &EngineConfig,
) -> ParseResult {
    quic_sni::analyze(ctx, payload, config)
}