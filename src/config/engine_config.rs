// src/config/engine_config.rs
//
// Top-level SNF engine configuration.
//
// Phase 4:  IntelligenceConfig added as a proper layer.
//           Fields previously scattered as loose fields on EngineConfig
//           (DoH, DoT, attribution, TLS risk) are now in IntelligenceConfig.
//           Backward-compatible accessors are provided where needed.
//
// Phase 13A: operation_mode: OperationMode field added.
//            ConfigBuilder::validate_and_build() writes the selected mode here
//            so every downstream consumer (capture, pipeline, reporting) can
//            branch on mode without passing it as a separate parameter.

use super::capture_config::CaptureConfig;
use super::dataset_config::DatasetConfig;
use super::debug_config::DebugConfig;
use super::device_config::DeviceConfig;
use super::dns_config::DnsConfig;
use super::filter_config::FilterConfig;
use super::flow_config::FlowConfig;
use super::intelligence_config::IntelligenceConfig;
pub use super::intelligence_config::TlsRiskWeights;
use super::mode::OperationMode;
use super::output_config::OutputConfig;
use super::performance_config::PerformanceConfig;
use super::protocol_config::ProtocolConfig;
use std::collections::HashMap;

#[derive(Clone)]
pub struct EngineConfig {
    pub capture:     CaptureConfig,
    pub flow:        FlowConfig,
    pub protocol:    ProtocolConfig,
    pub dns:         DnsConfig,
    pub device:      DeviceConfig,
    pub output:      OutputConfig,
    pub performance: PerformanceConfig,
    pub filter:      FilterConfig,
    pub dataset:     DatasetConfig,
    pub debug:       DebugConfig,
    pub intelligence: IntelligenceConfig,

    /// JA3 fingerprint database — loaded once at startup from datasets/ja3.csv.
    pub ja3_db: HashMap<String, String>,

    /// JA4 fingerprint database — loaded once at startup from datasets/ja4.csv.
    pub ja4_db: HashMap<String, String>,

    /// Domain investigation filter — only emit events for flows matching this domain.
    /// None = no filter (all flows reported).
    pub domain_filter: Option<String>,

    /// Active operation mode for this session.
    ///
    /// Phase 13A: written by ConfigBuilder::validate_and_build() so every
    /// downstream consumer can branch on mode without a separate parameter.
    ///
    /// Forensic : maximum depth, all analyzers, full output.
    /// Monitor  : lightweight continuous, reduced noise.
    /// Stealth  : minimal footprint, no banners, passive only.
    /// Replay   : deterministic PCAP replay, single-threaded.
    pub operation_mode: OperationMode,
}

// ----------------------------------------------------------------
// BACKWARD-COMPATIBLE ACCESSORS
// ----------------------------------------------------------------
// These delegate to sub-config structs so existing code that
// references config.enable_asn_mapping etc. continues to compile.

impl EngineConfig {
    pub fn enable_asn_mapping(&self) -> bool          { self.intelligence.enable_asn_mapping }
    pub fn enable_geoip_mapping(&self) -> bool        { self.intelligence.enable_geoip_mapping }
    pub fn enable_reverse_dns(&self) -> bool          { self.intelligence.enable_reverse_dns }
    pub fn asn_db_path(&self) -> &str                 { &self.intelligence.asn_db_path }
    pub fn geo_db_path(&self) -> &str                 { &self.intelligence.geo_db_path }
    pub fn rdns_cache_path(&self) -> &str             { &self.intelligence.rdns_cache_path }
    pub fn rdns_learning_enabled(&self) -> bool       { self.intelligence.rdns_learning_enabled }
    pub fn doh_learning_enabled(&self) -> bool        { self.intelligence.doh_learning_enabled }
    pub fn doh_learned_path(&self) -> &str            { &self.intelligence.doh_learned_path }
    pub fn doh_min_confidence_score(&self) -> u8      { self.intelligence.doh_min_confidence_score }
    pub fn dot_learning_enabled(&self) -> bool        { self.intelligence.dot_learning_enabled }
    pub fn dot_learned_path(&self) -> &str            { &self.intelligence.dot_learned_path }
    pub fn dot_min_confidence_score(&self) -> u8      { self.intelligence.dot_min_confidence_score }
    pub fn tls_risk_weights(&self) -> &TlsRiskWeights { &self.intelligence.tls_risk_weights }

    // ---- Phase 13A: mode-check helpers ----
    // Convenience predicates so callers can write config.is_stealth()
    // instead of config.operation_mode == OperationMode::Stealth everywhere.

    /// True in Stealth mode — suppresses startup banners and console output.
    pub fn is_stealth(&self) -> bool {
        self.operation_mode == OperationMode::Stealth
    }

    /// True in Forensic mode — maximum depth, all analyzers enabled.
    pub fn is_forensic(&self) -> bool {
        self.operation_mode == OperationMode::Forensic
    }

    /// True in Monitor mode — lightweight continuous SOC deployment.
    pub fn is_monitor(&self) -> bool {
        self.operation_mode == OperationMode::Monitor
    }

    /// True in Replay mode — deterministic PCAP analysis, single-threaded.
    pub fn is_replay(&self) -> bool {
        self.operation_mode == OperationMode::Replay
    }
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            capture:        CaptureConfig::default(),
            flow:           FlowConfig::default(),
            protocol:       ProtocolConfig::default(),
            dns:            DnsConfig::default(),
            device:         DeviceConfig::default(),
            output:         OutputConfig::default(),
            performance:    PerformanceConfig::default(),
            filter:         FilterConfig::default(),
            dataset:        DatasetConfig::default(),
            debug:          DebugConfig::default(),
            intelligence:   IntelligenceConfig::default(),
            ja3_db:         HashMap::new(),
            ja4_db:         HashMap::new(),
            domain_filter:  None,
            // Default mode is Forensic — the safest/most informative choice
            // when no explicit mode is specified.
            operation_mode: OperationMode::Forensic,
        }
    }
}