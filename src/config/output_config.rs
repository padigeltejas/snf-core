// src/config/output_config.rs
//
// Output layer configuration — controls event emission, logging, and formatting.
//
// Phase 4: expanded from 8 to 25 parameters.

#[derive(Clone)]
pub struct OutputConfig {
    // ---------------- FORMAT ----------------
    /// Primary output format: "text" | "json" | "ndjson"
    /// text   = human-readable console output
    /// json   = pretty-printed JSON array (single file)
    /// ndjson = one JSON object per line (streaming, default for production)
    pub output_format: String,

    /// Pretty-print JSON output (adds indentation and newlines).
    /// Only applies when output_format = "json".
    /// Disabled in Stealth and Replay modes.
    pub pretty_print_json: bool,

    // ---------------- VERBOSITY ----------------
    /// Console verbosity level:
    ///   0 = silent (no console output)
    ///   1 = events only (one line per event)
    ///   2 = protocol findings (DNS/TLS/HTTP details)
    ///   3 = full packet debug (all fields, all layers)
    pub verbosity: u8,

    // ---------------- LOG FILES ----------------
    /// Write text/JSON log output to this file path.
    pub log_file: Option<String>,

    /// Write NDJSON event stream to this file path.
    /// Each line is a complete SnfEvent serialized as JSON.
    pub ndjson_output_path: Option<String>,

    /// Rotate the NDJSON output file after this many megabytes. 0 = no rotation.
    pub ndjson_rotate_mb: usize,

    /// NDJSON write buffer size in bytes.
    /// Larger buffers = fewer syscalls but more data lost on crash.
    pub ndjson_buffer_size: usize,

    /// Write CSV summary output to this file path.
    /// Contains one row per expired flow with key fields.
    pub csv_output_path: Option<String>,

    // ---------------- SYSLOG ----------------
    /// Enable syslog output (RFC 5424).
    pub syslog_enabled: bool,

    /// Syslog destination host. Only used when syslog_enabled = true.
    pub syslog_host: Option<String>,

    /// Syslog destination port. Default 514 (UDP syslog).
    pub syslog_port: u16,

    // ---------------- EVENT FILTERING ----------------
    /// Maximum events emitted per second. 0 = unlimited.
    /// When limit is exceeded, events are dropped and a counter is incremented.
    pub max_events_per_second: u32,

    /// Suppress flow.update events (only emit flow.new and flow.expired).
    /// Significantly reduces event volume in high-traffic deployments.
    pub suppress_flow_updates: bool,

    /// Suppress engine.parse_error events from appearing in output.
    /// Parse errors are still counted internally for diagnostics.
    pub suppress_parse_errors: bool,

    /// Include raw packet header bytes in events (hex-encoded).
    /// Significantly increases output size. Disabled by default.
    pub include_raw_headers: bool,

    // ---------------- TIMEZONE ----------------
    /// Timezone for human-readable timestamp output.
    /// Does not affect internal timestamp_us storage (always UTC microseconds).
    /// Examples: "UTC", "Asia/Kolkata", "America/New_York"
    pub output_timezone: String,

    // ---------------- GRANULAR PROTOCOL LOGS ----------------
    /// Show per-packet console output (method, URI, domain, ports, etc.)
    pub show_packet_logs: bool,
    pub show_dns_logs: bool,
    pub show_tls_logs: bool,
    pub show_device_logs: bool,
    pub show_flow_logs: bool,
    pub show_icmp_logs: bool,
    pub show_quic_logs: bool,
    pub show_http_logs: bool,
    pub show_smb_logs: bool,
    pub show_dhcp_logs: bool,
    pub show_mdns_logs: bool,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            output_format: "ndjson".to_string(),
            pretty_print_json: false,
            verbosity: 2,
            log_file: None,
           ndjson_output_path: None,
            ndjson_rotate_mb: 256,
            ndjson_buffer_size: 64 * 1024,
            csv_output_path: None,
            syslog_enabled: false,
            syslog_host: None,
            syslog_port: 514,
            max_events_per_second: 0,
            suppress_flow_updates: false,
            suppress_parse_errors: false,
            include_raw_headers: false,
            output_timezone: "UTC".to_string(),
            show_packet_logs: true,
            show_dns_logs: true,
            show_tls_logs: true,
            show_device_logs: true,
            show_flow_logs: false,
            show_icmp_logs: true,
            show_quic_logs: true,
            show_http_logs: true,
            show_smb_logs: true,
            show_dhcp_logs: true,
            show_mdns_logs: true,
        }
    }
}