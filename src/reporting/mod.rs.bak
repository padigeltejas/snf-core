// src/reporting/mod.rs
//
// In-session live reporting engine.
//
// ── Purpose ───────────────────────────────────────────────────────────────────
//
//   snf_report (src/bin/snf_report.rs) handles post-session reporting by
//   reading the completed NDJSON output file. That covers the common case.
//
//   This module handles IN-SESSION reporting: periodic status summaries
//   emitted at configurable intervals during a live capture. Useful for:
//     - Long-running captures (>1 hour) where operators want live visibility
//     - Monitor mode: brief stats-only output every N seconds
//     - Forensic mode: periodic checkpoint summaries for large PCAP files
//
// ── What SessionReporter emits ────────────────────────────────────────────────
//
//   Every report_interval_us microseconds, SessionReporter::maybe_report()
//   checks if a report is due and if so prints a structured summary to stdout.
//   In Stealth mode, all output is suppressed.
//
//   Summary contains:
//     - Session elapsed time
//     - Packets processed, events emitted, flows active
//     - Top 5 event types by count
//     - Top 5 source IPs by traffic
//     - Active anomaly/behavior finding counts
//     - Capture drop count (if non-zero)
//
//   This is stdout-only — not written to NDJSON (would pollute the forensic log).
//
// ── Integration ───────────────────────────────────────────────────────────────
//
//   CaptureEngine holds a SessionReporter.
//   Called from CaptureEngine::process_raw_packet() after each packet.
//   Only emits when the interval has elapsed — no overhead between reports.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::config::engine_config::EngineConfig;

// ── CONSTANTS ─────────────────────────────────────────────────────────────────

/// Default report interval: 30 seconds.
pub const DEFAULT_REPORT_INTERVAL_US: u64 = 30 * 1_000_000;

// ── SessionReporter ───────────────────────────────────────────────────────────

/// In-session periodic status reporter.
///
/// Tracks rolling statistics and prints a summary at configurable intervals.
/// Zero-overhead between reports — just a timestamp comparison on each packet.
pub struct SessionReporter {
    /// How often to emit a report (microseconds of packet-time).
    report_interval_us: u64,

    /// Packet-time timestamp of the last report.
    last_report_us: u64,

    /// Session start timestamp (first packet time).
    session_start_us: u64,

    /// Rolling packet counter.
    packets: u64,

    /// Rolling event counter.
    events: u64,

    /// Active flow count (approximation — updated on new flow).
    active_flows: u64,

    /// Event type counts for top-N display.
    event_type_counts: HashMap<String, u64>,

    /// Per-IP byte counts for top talkers.
    ip_bytes: HashMap<IpAddr, u64>,

    /// Behavior/anomaly finding counts.
    finding_counts: HashMap<String, u64>,

    /// Total capture drops since session start.
    capture_drops: u64,

    /// Report number (incremented each report, displayed to operator).
    report_number: u32,
}

impl SessionReporter {
    /// Create a new SessionReporter.
    pub fn new(report_interval_us: u64) -> Self {
        Self {
            report_interval_us,
            last_report_us:    0,
            session_start_us:  0,
            packets:           0,
            events:            0,
            active_flows:      0,
            event_type_counts: HashMap::new(),
            ip_bytes:          HashMap::with_capacity(256),
            finding_counts:    HashMap::new(),
            capture_drops:     0,
            report_number:     0,
        }
    }

    /// Default reporter using DEFAULT_REPORT_INTERVAL_US.
    pub fn default_interval() -> Self {
        Self::new(DEFAULT_REPORT_INTERVAL_US)
    }

    /// Record a packet observation.
    pub fn observe_packet(
        &mut self,
        timestamp_us: u64,
        src_ip:       IpAddr,
        packet_size:  u64,
        is_new_flow:  bool,
    ) {
        if self.session_start_us == 0 {
            self.session_start_us = timestamp_us;
        }
        self.packets = self.packets.saturating_add(1);
        if is_new_flow {
            self.active_flows = self.active_flows.saturating_add(1);
        }
        *self.ip_bytes.entry(src_ip).or_insert(0) += packet_size;
    }

    /// Record an event emission.
    pub fn observe_event(&mut self, event_type: &str) {
        self.events = self.events.saturating_add(1);
        *self.event_type_counts.entry(event_type.to_string()).or_insert(0) += 1;
    }

    /// Record a behavior or anomaly finding.
    pub fn observe_finding(&mut self, finding_type: &str) {
        *self.finding_counts.entry(finding_type.to_string()).or_insert(0) += 1;
    }

    /// Record a capture drop.
    pub fn observe_drop(&mut self, count: u64) {
        self.capture_drops = self.capture_drops.saturating_add(count);
    }

    /// Check if a report is due and print it if so.
    ///
    /// Returns true if a report was emitted.
    /// Call after every packet — overhead is a single u64 subtraction comparison.
    pub fn maybe_report(
        &mut self,
        current_timestamp_us: u64,
        config:               &EngineConfig,
    ) -> bool {
        // Stealth mode: never print anything.
        if config.is_stealth() { return false; }

        // Not enough time elapsed.
        if current_timestamp_us.saturating_sub(self.last_report_us)
            < self.report_interval_us
        {
            return false;
        }

        self.last_report_us = current_timestamp_us;
        self.report_number  = self.report_number.saturating_add(1);
        self.print_report(current_timestamp_us, config);
        true
    }

    fn print_report(&self, current_us: u64, config: &EngineConfig) {
        let elapsed_secs = current_us.saturating_sub(self.session_start_us) / 1_000_000;
        let pps = if elapsed_secs > 0 { self.packets / elapsed_secs } else { 0 };

        println!();
        println!("┌─ SNF Live Report #{} ─────────────────────────────────────────┐",
            self.report_number);
        println!("│  Session time  : {}s  │  Mode: {}",
            elapsed_secs,
            config.operation_mode.as_str()
        );
        println!("│  Packets       : {} ({} pps avg)", self.packets, pps);
        println!("│  Events        : {} emitted", self.events);
        println!("│  Flows         : {} new (session total)", self.active_flows);

        if self.capture_drops > 0 {
            println!("│  ⚠ Drops       : {} packets dropped (queue/ring full)",
                self.capture_drops);
        }

        // Top event types.
        if !self.event_type_counts.is_empty() {
            let mut types: Vec<(&String, &u64)> = self.event_type_counts.iter().collect();
            types.sort_by(|a, b| b.1.cmp(a.1));
            println!("│  Top events:");
            for (et, count) in types.iter().take(5) {
                println!("│    {:<35} {:>8}", et, count);
            }
        }

        // Top talkers.
        if !self.ip_bytes.is_empty() {
            let mut talkers: Vec<(IpAddr, u64)> = self.ip_bytes
                .iter().map(|(&ip, &b)| (ip, b)).collect();
            talkers.sort_by(|a, b| b.1.cmp(&a.1));
            println!("│  Top sources:");
            for (ip, bytes) in talkers.iter().take(5) {
                println!("│    {:<40} {:>10} bytes", ip, bytes);
            }
        }

        // Findings.
        if !self.finding_counts.is_empty() {
            println!("│  Findings:");
            let mut findings: Vec<(&String, &u64)> = self.finding_counts.iter().collect();
            findings.sort_by(|a, b| b.1.cmp(a.1));
            for (f, count) in findings.iter().take(5) {
                println!("│    {:<35} {:>8} alerts", f, count);
            }
        }

        println!("└───────────────────────────────────────────────────────────────┘");
    }
    /// Print a structured summary box at the END of a capture session.
    ///
    /// Called once from CaptureEngine::shutdown() after all packets are processed.
    /// Suppressed in Stealth mode (shutdown() never calls this in stealth).
    pub fn print_final_summary(&self, end_timestamp_us: u64, mode: &str, output_path: &str) {
        let elapsed_secs = end_timestamp_us
            .saturating_sub(self.session_start_us)
            .saturating_div(1_000_000);
        let pps = if elapsed_secs > 0 { self.packets / elapsed_secs } else { self.packets };

        let sep = "=".repeat(62);
        println!();
        println!("{}", sep);
        println!("  SNF-Core  |  Session Complete");
        println!("{}", sep);
        println!("  Mode      : {}", mode);
        println!("  Output    : {}", output_path);
        println!("{}", "-".repeat(62));
        println!("  Packets   : {}", self.packets);
        println!("  Events    : {}", self.events);
        println!("  Flows     : {}", self.active_flows);
        if elapsed_secs > 0 {
            println!("  Duration  : {}s  ({} pps avg)", elapsed_secs, pps);
        }
        if self.capture_drops > 0 {
            println!("  Drops     : {} (queue/ring full)", self.capture_drops);
        }

        // Protocol / event-type breakdown
        if !self.event_type_counts.is_empty() {
            println!("{}", "-".repeat(62));
            println!("  Protocol Breakdown (top 8):");
            let mut types: Vec<(&String, &u64)> = self.event_type_counts.iter().collect();
            types.sort_by(|a, b| b.1.cmp(a.1));
            for (et, count) in types.iter().take(8) {
                println!("    {:<38} {:>8}", et, count);
            }
        }

        // Top talkers
        if !self.ip_bytes.is_empty() {
            println!("{}", "-".repeat(62));
            println!("  Top Source IPs (by bytes):");
            let mut talkers: Vec<(std::net::IpAddr, u64)> =
                self.ip_bytes.iter().map(|(&ip, &b)| (ip, b)).collect();
            talkers.sort_by(|a, b| b.1.cmp(&a.1));
            for (ip, bytes) in talkers.iter().take(5) {
                let kb = bytes / 1024;
                if kb > 0 {
                    println!("    {:<38} {:>8} KB", ip, kb);
                } else {
                    println!("    {:<38} {:>8} B", ip, bytes);
                }
            }
        }

        // Behavior/anomaly findings
        if !self.finding_counts.is_empty() {
            println!("{}", "-".repeat(62));
            println!("  Findings:");
            let mut findings: Vec<(&String, &u64)> = self.finding_counts.iter().collect();
            findings.sort_by(|a, b| b.1.cmp(a.1));
            for (f, count) in findings.iter() {
                println!("    {:<38} {:>8} alerts", f, count);
            }
        }

        println!("{}", sep);
        println!();
    }

}
