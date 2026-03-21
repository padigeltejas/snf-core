// src/flow/flow_struct.rs
//
// Core flow state structure.
//
// Phase 2 changes:
//   - TLS_BUFFER_MAX_BYTES: hard cap on tls_buffer growth (P2-1)
//     Prevents unbounded allocation on long-lived or adversarially crafted TLS flows.
//   - enforce_tls_buffer_cap(): call before every tls_buffer.extend_from_slice()
//     Returns false if cap was exceeded — caller must emit engine.parse_error and skip.

use std::net::IpAddr;

// ---------------- BUFFER CAPS ----------------

/// Hard cap on per-flow TLS reassembly buffer.
/// 64KB is sufficient for any single TLS record (max TLS record = 16KB + overhead).
/// A flow exceeding this is either broken, looping, or adversarial.
/// When hit: buffer is cleared, parse error is emitted, TLS analysis is skipped for
/// remaining packets in that flow.
pub const TLS_BUFFER_MAX_BYTES: usize = 65_536; // 64KB

pub struct Flow {
    // ---------------- Identity ----------------
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub protocol: String,

    // ---------------- Domain ----------------
    pub domain: Option<String>,
    pub domain_source: Option<String>,

    // ---------------- Traffic Stats ----------------
    pub packets: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,

    // ---------------- Timing (F16: packet timestamps, never wall-clock) ----------------
    /// Timestamp of the first packet in this flow, in microseconds since Unix epoch.
    /// Sourced from pcap packet header — deterministic across replay runs.
    pub first_seen_us: u64,
    /// Timestamp of the most recent packet in this flow, in microseconds since Unix epoch.
    /// Used by expire_flows() for deterministic timeout — no Instant, no wall-clock.
    pub last_seen_us: u64,

    // ---------------- Protocol State ----------------
    /// TLS record reassembly buffer.
    /// Hard-capped at TLS_BUFFER_MAX_BYTES (64KB). Enforced via enforce_tls_buffer_cap().
    /// If the cap is exceeded, the buffer is cleared and the caller emits an error event.
    pub tls_buffer: Vec<u8>,

    /// Set to true if tls_buffer was ever cleared due to cap overflow.
    /// Signals to the TLS analyzer that stream state is lost — skip further parsing.
    pub tls_buffer_overflow: bool,

    pub is_doh: bool,
    pub alpn: Option<String>,
    pub http_path: Option<String>,
    pub http_content_type: Option<String>,
    pub tls_detected: bool,
    pub tls_version: Option<String>,

    // ---------------- TLS Intelligence (Behavior Layer) ----------------
    pub tls_risk_score: u8,
    pub tls_risk_flags: Vec<String>,
    pub tls_cipher_strength: Option<String>,
    pub tls_is_self_signed: bool,
    pub tls_version_downgrade: bool,
    pub tls_0rtt: bool,
    pub tls_session_resumed: bool,
    pub tls_cipher_suites: Vec<u16>,
}

impl Flow {
    pub fn new(
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
        protocol: String,
    ) -> Self {
        Self {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol,
            domain: None,
            domain_source: None,
            packets: 0,
            bytes_sent: 0,
            bytes_received: 0,
            // Seeded to 0 — overwritten immediately by update_flow_from_context()
            // on the first packet. Never read before being set.
            first_seen_us: 0,
            last_seen_us: 0,
            tls_buffer: Vec::new(),
            tls_buffer_overflow: false,
            is_doh: false,
            alpn: None,
            http_path: None,
            http_content_type: None,
            tls_detected: false,
            tls_version: None,
            tls_risk_score: 0,
            tls_risk_flags: Vec::new(),
            tls_cipher_strength: None,
            tls_is_self_signed: false,
            tls_version_downgrade: false,
            tls_0rtt: false,
            tls_session_resumed: false,
            tls_cipher_suites: Vec::new(),
        }
    }

    // ----------------------------------------------------------------
    // P2-1: TLS buffer cap enforcement
    // ----------------------------------------------------------------

    /// Check whether appending `incoming_len` bytes to tls_buffer would exceed the cap.
    ///
    /// If appending would exceed TLS_BUFFER_MAX_BYTES:
    ///   - Clears tls_buffer (frees memory immediately)
    ///   - Sets tls_buffer_overflow = true
    ///   - Returns false — caller must NOT call extend_from_slice and must emit
    ///     an engine.parse_error event with reason "tls_buffer_overflow"
    ///
    /// If within cap: returns true — caller may safely extend.
    ///
    /// Usage in tls.rs:
    ///   if !flow.check_tls_buffer_cap(payload.len()) {
    ///       return Err(SnfParseError::new("TLS", "tls_buffer_overflow", 0));
    ///   }
    ///   flow.tls_buffer.extend_from_slice(payload);
    pub fn check_tls_buffer_cap(&mut self, incoming_len: usize) -> bool {
        let projected = self.tls_buffer.len().saturating_add(incoming_len);
        if projected > TLS_BUFFER_MAX_BYTES {
            // Clear the buffer immediately — don't hold on to stale data.
            self.tls_buffer.clear();
            self.tls_buffer.shrink_to_fit();
            self.tls_buffer_overflow = true;
            return false;
        }
        true
    }
}
