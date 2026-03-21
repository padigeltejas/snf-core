// src/flow/flow_utils.rs
//
// Flow utility functions — deterministic flow identifier formatting.
//
// Phase 4 / v6.0 Section 19.4: format_flow_id() and flow_to_brief_string()
//
// ── Why these functions exist ────────────────────────────────────────────────
//
//   flow_id is SNF's canonical flow identifier — it appears in every SnfEvent,
//   graph edge, timeline entry, and evidence report. It must be deterministic:
//   the same 5-tuple always produces the same string, regardless of which
//   direction the first packet arrived from.
//
//   The pipeline currently inlines format!() directly in some places.
//   These functions are the canonical implementations for all code that
//   needs to construct or log a flow identifier.
//
// ── format_flow_id canonical form ────────────────────────────────────────────
//
//   Per v6.0 Section 19.4 and 04_flow_model_spec.md:
//     "{min_ip}:{min_port}-{max_ip}:{max_port}-{proto}"
//
//   "min" and "max" are determined by canonical ordering:
//     - Compare IpAddr first (V4 < V6, then numeric comparison)
//     - If IPs equal, compare ports numerically
//   This ensures src→dst and dst→src packets produce the same flow_id.
//
//   This matches FlowKey::normalize_flow() which uses the same min/max logic.

use std::net::IpAddr;
use crate::flow::flow_struct::Flow;

// ── format_flow_id ────────────────────────────────────────────────────────────

/// Build the canonical SNF flow identifier string from a 5-tuple.
///
/// Deterministic: smaller IP is always on the left regardless of packet direction.
/// Format: `{min_ip}:{min_port}-{max_ip}:{max_port}-{proto}`
///
/// Examples:
///   `192.168.1.5:54321-8.8.8.8:53-udp`
///   `10.0.0.1:445-10.0.0.7:49152-tcp`
///
/// This is the canonical form used in all SnfEvent.flow_id fields.
pub fn format_flow_id(
    src_ip:   IpAddr,
    src_port: u16,
    dst_ip:   IpAddr,
    dst_port: u16,
    protocol: &str,
) -> String {
    // Canonical ordering: put the lexicographically smaller (ip, port) pair first.
    // This ensures both directions of a flow produce the same flow_id.
    let (ip1, port1, ip2, port2) = if (src_ip, src_port) <= (dst_ip, dst_port) {
        (src_ip, src_port, dst_ip, dst_port)
    } else {
        (dst_ip, dst_port, src_ip, src_port)
    };

    format!("{}:{}-{}:{}-{}", ip1, port1, ip2, port2, protocol)
}

/// Build a canonical flow_id from a Flow struct.
///
/// Uses the same ordering logic as `format_flow_id()`.
pub fn flow_id_from_flow(flow: &Flow) -> String {
    format_flow_id(
        flow.src_ip,
        flow.src_port,
        flow.dst_ip,
        flow.dst_port,
        &flow.protocol,
    )
}

// ── flow_to_brief_string ──────────────────────────────────────────────────────

/// Format a Flow as a short human-readable string for logging and diagnostics.
///
/// Format: `{proto} {src_ip}:{src_port} → {dst_ip}:{dst_port} [pkts={n} bytes={b}]`
///
/// NOT used in NDJSON output (use format_flow_id for that).
/// Used only in debug/forensic mode console output and evidence reports.
pub fn flow_to_brief_string(flow: &Flow) -> String {
    let domain_str = match &flow.domain {
        Some(d) => format!(" ({})", d),
        None    => String::new(),
    };
    let tls_str = if flow.tls_detected {
        match flow.tls_version.as_deref() {
            Some(v) => format!(" TLS={}", v),
            None    => " TLS".to_string(),
        }
    } else {
        String::new()
    };

    format!(
        "{} {}:{} → {}:{}{}{} [pkts={} bytes={}]",
        flow.protocol,
        flow.src_ip, flow.src_port,
        flow.dst_ip, flow.dst_port,
        domain_str,
        tls_str,
        flow.packets,
        flow.bytes_sent.saturating_add(flow.bytes_received),
    )
}

// ── duration_us_to_string ─────────────────────────────────────────────────────

/// Format a microsecond duration as a human-readable string.
///
/// Examples: "42µs", "1.234ms", "3.7s", "1h 22m 5s"
/// Used in evidence reports and session summaries.
pub fn duration_us_to_string(us: u64) -> String {
    if us < 1_000 {
        format!("{}µs", us)
    } else if us < 1_000_000 {
        format!("{:.3}ms", us as f64 / 1_000.0)
    } else if us < 60_000_000 {
        format!("{:.1}s", us as f64 / 1_000_000.0)
    } else {
        let secs  = us / 1_000_000;
        let mins  = secs / 60;
        let hours = mins / 60;
        if hours > 0 {
            format!("{}h {}m {}s", hours, mins % 60, secs % 60)
        } else {
            format!("{}m {}s", mins, secs % 60)
        }
    }
}

// ── bytes_to_string ───────────────────────────────────────────────────────────

/// Format a byte count as a human-readable string.
///
/// Examples: "512 B", "1.5 KB", "234.7 MB", "1.07 GB"
/// Used in evidence reports and top-talker lists.
pub fn bytes_to_string(bytes: u64) -> String {
    const KB: u64 = 1_024;
    const MB: u64 = 1_024 * 1_024;
    const GB: u64 = 1_024 * 1_024 * 1_024;

    if bytes < KB {
        format!("{} B", bytes)
    } else if bytes < MB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else if bytes < GB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    }
}