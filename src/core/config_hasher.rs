use sha2::{Sha256, Digest};
use crate::config::engine_config::EngineConfig;

/// Compute a deterministic SHA-256 hash of the engine config.
///
/// The hash covers every user-controllable parameter that affects analysis output.
/// Two configs that produce the same hash are guaranteed to produce identical
/// SNF output given the same input PCAP - this is the determinism contract.
///
/// Fields excluded from the hash:
/// - ja3_db, ja4_db (these are dataset files hashed separately)
/// - output paths (these don't affect analysis logic)
///
/// The serialization format is canonical: fields are written in declaration order,
/// key=value pairs separated by \n. Do not reorder without bumping SNF_VERSION.
pub fn hash_config(config: &EngineConfig) -> String {
    let mut hasher = Sha256::new();

    // --- Capture ---
    hasher.update(format!("capture.interface_index={}\n", config.capture.interface_index));
    hasher.update(format!("capture.packet_limit={}\n", config.capture.packet_limit));
    hasher.update(format!("capture.promiscuous_mode={}\n", config.capture.promiscuous_mode));
    hasher.update(format!("capture.snaplen={}\n", config.capture.snaplen));

    // --- Flow ---
    hasher.update(format!("flow.flow_timeout={}\n", config.flow.flow_timeout));
    hasher.update(format!("output.suppress_flow_updates={}\n", config.output.suppress_flow_updates));
    hasher.update(format!("output.suppress_parse_errors={}\n", config.output.suppress_parse_errors));

    // --- Protocol ---
    hasher.update(format!("protocol.enable_dns={}\n", config.protocol.enable_dns));
    hasher.update(format!("protocol.enable_tls={}\n", config.protocol.enable_tls));
    hasher.update(format!("protocol.enable_quic={}\n", config.protocol.enable_quic));
    hasher.update(format!("protocol.enable_http={}\n", config.protocol.enable_http));
    hasher.update(format!("protocol.enable_icmp={}\n", config.protocol.enable_icmp));
    hasher.update(format!("protocol.tls_intelligence_enabled={}\n", config.protocol.tls_intelligence_enabled));
    hasher.update(format!("protocol.ja3_enabled={}\n", config.protocol.ja3_enabled));
    hasher.update(format!("protocol.ja3s_enabled={}\n", config.protocol.ja3s_enabled));
    hasher.update(format!("protocol.ja4_enabled={}\n", config.protocol.ja4_enabled));
    hasher.update(format!("protocol.dns_port={}\n", config.protocol.dns_port));
    hasher.update(format!("protocol.http_ports={:?}\n", config.protocol.http_ports));

    // --- Filter ---
    hasher.update(format!("filter.domain_filter={:?}\n", config.domain_filter));

    // --- Intelligence ---
hasher.update(format!("intel.enable_asn_mapping={}\n", config.enable_asn_mapping()));
hasher.update(format!("intel.enable_geoip_mapping={}\n", config.enable_geoip_mapping()));
hasher.update(format!("intel.enable_reverse_dns={}\n", config.enable_reverse_dns()));
hasher.update(format!("intel.rdns_learning_enabled={}\n", config.rdns_learning_enabled()));
hasher.update(format!("intel.doh_learning_enabled={}\n", config.doh_learning_enabled()));
hasher.update(format!("intel.doh_min_confidence_score={}\n", config.doh_min_confidence_score()));
hasher.update(format!("intel.dot_learning_enabled={}\n", config.dot_learning_enabled()));
hasher.update(format!("intel.dot_min_confidence_score={}\n", config.dot_min_confidence_score()));
// --- TLS Risk Weights ---
hasher.update(format!("tls_risk.deprecated_version={}\n", config.tls_risk_weights().deprecated_version));
hasher.update(format!("tls_risk.version_downgrade={}\n", config.tls_risk_weights().version_downgrade));
hasher.update(format!("tls_risk.weak_cipher={}\n", config.tls_risk_weights().weak_cipher));
hasher.update(format!("tls_risk.no_forward_secrecy={}\n", config.tls_risk_weights().no_forward_secrecy));
hasher.update(format!("tls_risk.self_signed_cert={}\n", config.tls_risk_weights().self_signed_cert));
hasher.update(format!("tls_risk.expired_cert={}\n", config.tls_risk_weights().expired_cert));
hasher.update(format!("tls_risk.rare_ja3={}\n", config.tls_risk_weights().rare_ja3));
hasher.update(format!("tls_risk.ja3_ja3s_mismatch={}\n", config.tls_risk_weights().ja3_ja3s_mismatch));
hasher.update(format!("tls_risk.geo_asn_mismatch={}\n", config.tls_risk_weights().geo_asn_mismatch));
hasher.update(format!("tls_risk.suspicious_resumption={}\n", config.tls_risk_weights().suspicious_resumption));
hasher.update(format!("tls_risk.zero_rtt_usage={}\n", config.tls_risk_weights().zero_rtt_usage));

    // Finalize and return lowercase hex string.
    format!("{:x}", hasher.finalize())
}