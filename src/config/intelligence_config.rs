// src/config/intelligence_config.rs
//
// Intelligence layer configuration — controls threat scoring, fingerprinting
// databases, entropy analysis, beacon detection, and network attribution.
//
// Phase 4: new file — fields previously scattered in EngineConfig as loose
// fields are consolidated here for clean single-responsibility architecture.
// Phase 7: behavior engine gates and thresholds added.

#[derive(Clone)]
pub struct IntelligenceConfig {
    // ---------------- NETWORK ATTRIBUTION ----------------
    pub enable_asn_mapping: bool,
    pub enable_geoip_mapping: bool,
    pub enable_reverse_dns: bool,
    pub asn_db_path: String,
    pub geo_db_path: String,
    pub rdns_cache_path: String,
    pub rdns_learning_enabled: bool,
    pub rdns_max_entries: usize,
    pub rdns_ttl_seconds: u64,
    pub asn_cache_size: usize,
    pub geo_cache_size: usize,

    // ---------------- DoH DETECTION ----------------
    pub doh_learning_enabled: bool,
    pub doh_learned_path: String,
    pub doh_min_confidence_score: u8,

    // ---------------- DoT DETECTION ----------------
    pub dot_learning_enabled: bool,
    pub dot_learned_path: String,
    pub dot_min_confidence_score: u8,

    // ---------------- TLS RISK SCORING ----------------
    pub tls_risk_threshold: u8,
    pub tls_risk_alert_on_score: bool,
    pub tls_risk_weights: TlsRiskWeights,

    // ---------------- FINGERPRINT DATABASES ----------------
    pub ja3_db_path: String,
    pub ja4_db_path: String,
    pub ja3_blocklist_path: String,
    pub known_bad_certs_path: String,

    // ---------------- ENTROPY / DGA ----------------
    pub entropy_analysis_enabled: bool,
    pub dga_detection_enabled: bool,
    pub dga_threshold: f32,

    // ---------------- LEGACY BEACON CONFIG ----------------
    pub beacon_detection_enabled: bool,
    pub beacon_interval_tolerance_ms: u64,

    // ---------------- BEHAVIOR ENGINE GATES (Phase 7) ----------------
    pub beacon_detection: bool,
    pub dga_detection: bool,
    pub icmp_track_flood: bool,
    pub smb_track_auth: bool,

    // ---------------- BEACON DETECTOR THRESHOLDS ----------------
    pub beacon_min_packets: u64,
    pub beacon_cv_threshold_pct: u64,
    pub beacon_score_threshold: u8,

    // ---------------- ICMP FLOOD/SWEEP THRESHOLDS ----------------
    pub icmp_flood_window_us: u64,
    pub icmp_flood_threshold: u32,
    pub icmp_sweep_window_us: u64,
    pub icmp_sweep_dst_threshold: u32,

    // ---------------- SMB LATERAL MOVEMENT THRESHOLDS ----------------
    pub smb_fanout_window_us: u64,
    pub smb_fanout_threshold: u32,
    pub smb_auth_fail_window_us: u64,
    pub smb_auth_fail_threshold: u32,
}

// ----------------------------------------------------------------
// TLS RISK WEIGHTS
// ----------------------------------------------------------------

#[derive(Clone)]
pub struct TlsRiskWeights {
    pub deprecated_version:    u8,
    pub version_downgrade:     u8,
    pub weak_cipher:           u8,
    pub no_forward_secrecy:    u8,
    pub self_signed_cert:      u8,
    pub expired_cert:          u8,
    pub rare_ja3:              u8,
    pub ja3_ja3s_mismatch:     u8,
    pub geo_asn_mismatch:      u8,
    pub suspicious_resumption: u8,
    pub zero_rtt_usage:        u8,
}

// ----------------------------------------------------------------
// DEFAULTS
// ----------------------------------------------------------------

impl Default for IntelligenceConfig {
    fn default() -> Self {
        Self {
            enable_asn_mapping:    false,
            enable_geoip_mapping:  false,
            enable_reverse_dns:    true,
            asn_db_path:           "datasets/asn_ipv4.mmdb".to_string(),
            geo_db_path:           "datasets/geo_ipv4.mmdb".to_string(),
            rdns_cache_path:       "datasets/rdns_cache.txt".to_string(),
            rdns_learning_enabled: true,
            rdns_max_entries:      100_000,
            rdns_ttl_seconds:      3600,
            asn_cache_size:        10_000,
            geo_cache_size:        10_000,

            doh_learning_enabled:     true,
            doh_learned_path:         "datasets/learned_doh.txt".to_string(),
            doh_min_confidence_score: 3,

            dot_learning_enabled:     true,
            dot_learned_path:         "datasets/learned_dot.txt".to_string(),
            dot_min_confidence_score: 2,

            tls_risk_threshold:      50,
            tls_risk_alert_on_score: true,
            tls_risk_weights: TlsRiskWeights {
                deprecated_version:    20,
                version_downgrade:     25,
                weak_cipher:           20,
                no_forward_secrecy:    15,
                self_signed_cert:      30,
                expired_cert:          25,
                rare_ja3:              10,
                ja3_ja3s_mismatch:     15,
                geo_asn_mismatch:      20,
                suspicious_resumption: 15,
                zero_rtt_usage:        10,
            },

            ja3_db_path:          "datasets/ja3_fingerprints.csv".to_string(),
            ja4_db_path:          "datasets/ja4_fingerprints.csv".to_string(),
            ja3_blocklist_path:   "datasets/ja3_blocklist.txt".to_string(),
            known_bad_certs_path: "datasets/bad_certs.txt".to_string(),

            entropy_analysis_enabled: true,
            dga_detection_enabled:    true,
            dga_threshold:            0.75,

            beacon_detection_enabled:     false,
            beacon_interval_tolerance_ms: 500,

            beacon_detection: true,
            dga_detection:    true,
            icmp_track_flood: true,
            smb_track_auth:   true,

            beacon_min_packets:      6,
            beacon_cv_threshold_pct: 30,
            beacon_score_threshold:  60,

            icmp_flood_window_us:     10_000_000,
            icmp_flood_threshold:     100,
            icmp_sweep_window_us:     60_000_000,
            icmp_sweep_dst_threshold: 20,

            smb_fanout_window_us:    300_000_000,
            smb_fanout_threshold:    10,
            smb_auth_fail_window_us: 120_000_000,
            smb_auth_fail_threshold: 15,
        }
    }
}
