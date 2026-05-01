// src/core/analyzer_manager/mod.rs
use crate::core::packet_context::PacketContext;
use crate::config::engine_config::EngineConfig;
use crate::discovery::dns_cache::DnsCache;
use crate::flow::flow_struct::Flow;
use crate::core::parse_error::SnfParseError;
use crate::analyzers::{dns, tls, quic, dhcp, icmp, smb, mdns};
use crate::analyzers::http::http_analyzer::HttpAnalyzer;
use crate::analyzers::doh::{DohAnalyzer, DohConfig, DohIndicators};
use crate::analyzers::dot::{DotAnalyzer, DotConfig, DotIndicators};
use crate::analyzers::{enterprise, discovery};

// Stub RdnsCache for open source build — full implementation in commercial edition
pub struct RdnsCache;
impl RdnsCache {
    pub fn new(_path: &str, _learning: bool) -> Self { Self }
    pub fn learn(&mut self, _ip: std::net::IpAddr, _domain: String) {}
    pub fn lookup(&self, _ip: std::net::IpAddr) -> Option<String> { None }
}

pub struct AnalyzerManager {
    pub rdns_cache: RdnsCache,
    doh:            DohAnalyzer,
    dot:            DotAnalyzer,
}

impl AnalyzerManager {
    pub fn new(config: &EngineConfig) -> Self {
        let doh = DohAnalyzer::new(DohConfig {
            learned_path:         config.doh_learned_path().to_string(),
            learning_enabled:     config.doh_learning_enabled(),
            min_confidence_score: config.doh_min_confidence_score(),
        });
        let dot = DotAnalyzer::new(DotConfig {
            learned_path:         config.dot_learned_path().to_string(),
            learning_enabled:     config.dot_learning_enabled(),
            min_confidence_score: config.dot_min_confidence_score(),
        });
        Self { rdns_cache: RdnsCache::new("", false), doh, dot }
    }

    pub fn run(
        &mut self,
        ctx:       &mut PacketContext,
        payload:   &[u8],
        flow:      &mut Flow,
        dns_cache: &mut DnsCache,
        config:    &EngineConfig,
    ) -> Vec<SnfParseError> {
        let mut errors: Vec<SnfParseError> = Vec::new();

        if config.protocol.enable_dns
            && let Err(e) = dns::analyze(ctx, payload, dns_cache, config) { errors.push(e); }
        if config.protocol.enable_tls
            && let Err(e) = tls::analyze(ctx, payload, flow, dns_cache, config) { errors.push(e); }
        if config.protocol.enable_quic
            && let Err(e) = quic::analyze(ctx, payload, dns_cache, config) { errors.push(e); }
        if config.protocol.enable_http
            && let Err(e) = HttpAnalyzer::analyze(ctx, payload, dns_cache, config) { errors.push(e); }
        if (config.protocol.enable_dhcp || config.protocol.enable_dhcpv6)
            && let Err(e) = dhcp::analyze(ctx, payload, config) { errors.push(e); }
        if config.protocol.enable_icmp
            && let Err(e) = icmp::analyze(ctx, payload, config) { errors.push(e); }
        if config.protocol.enable_smb
            && let Err(e) = smb::analyze(ctx, payload, config) { errors.push(e); }
        if config.protocol.enable_mdns
            && let Err(e) = mdns::analyze(ctx, payload, config) { errors.push(e); }
        if let Some(domain) = &flow.domain {
            let indicators = DohIndicators {
                domain,
                alpn:         flow.alpn.as_deref(),
                http_path:    flow.http_path.as_deref(),
                content_type: flow.http_content_type.as_deref(),
            };
            self.doh.analyze(indicators);
        }
        if config.protocol.enable_tls {
            let indicators = DotIndicators {
                domain:       flow.domain.as_deref(),
                dst_port:     ctx.dst_port,
                tls_detected: flow.tls_detected,
            };
            self.dot.analyze(indicators);
        }
        if let (Some(domain), Some(resolved_ip)) = (&ctx.dns_query_name, &ctx.dns_resolved_ip) {
            self.rdns_cache.learn(*resolved_ip, domain.clone());
        }
        if (config.protocol.enable_kerberos || config.protocol.enable_ldap || config.protocol.enable_rdp)
            && let Err(e) = enterprise::analyze(ctx, payload, config) { errors.push(e); }
        if (config.protocol.enable_ssdp || config.protocol.enable_ftp)
            && let Err(e) = discovery::analyze(ctx, payload, config) { errors.push(e); }
        errors
    }
}
