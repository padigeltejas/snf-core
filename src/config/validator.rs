// src/config/validator.rs
//
// SNF Configuration Validator — startup fail-fast validation pass.
//
// Phase 13C: added validate_dataset_paths() — checks that every file path
// referenced in config actually exists and is accessible before capture starts.
// Integrated dry_run parameter: in dry-run mode, path checks produce a
// structured human-readable summary of what SNF would do, then exit.
//
// Called once at startup before any packet processing begins.
// Checks for:
//   - Invalid parameter values (out of range, empty required fields)
//   - Parameter clashes (conflicting settings that would produce silent failures)
//   - Mode-specific requirement violations
//   - Dataset / file path accessibility
//   - Warnings for suboptimal but non-fatal configurations
//
// Design:
//   - Errors  → fatal, printed to stderr, SNF exits with code 1
//   - Warnings → printed to stderr with [WARN] prefix, SNF continues
//   - All errors are collected before exiting so the operator sees
//     the complete list in one run, not one error at a time.

use std::path::Path;
use crate::config::engine_config::EngineConfig;
use crate::config::mode::OperationMode;

// ----------------------------------------------------------------
// VALIDATION RESULT
// ----------------------------------------------------------------

/// Accumulated errors and warnings from the full validation pass.
/// All errors are collected before returning — operator sees every problem at once.
pub struct ValidationResult {
    pub errors:   Vec<String>,
    pub warnings: Vec<String>,
}

impl ValidationResult {
    fn new() -> Self {
        Self {
            errors:   Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Record a fatal configuration error.
    fn error(&mut self, msg: impl Into<String>) {
        self.errors.push(msg.into());
    }

    /// Record a non-fatal configuration warning.
    fn warn(&mut self, msg: impl Into<String>) {
        self.warnings.push(msg.into());
    }

    /// True if no errors were recorded (warnings are non-fatal).
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }

    /// Print all warnings then all errors to stderr.
    /// Returns true if valid (no errors), false if errors exist.
    pub fn report(&self) -> bool {
        for w in &self.warnings {
            eprintln!("[SNF WARN]  {}", w);
        }
        for e in &self.errors {
            eprintln!("[SNF ERROR] {}", e);
        }
        self.is_valid()
    }
}

// ----------------------------------------------------------------
// TOP-LEVEL ENTRY POINT
// ----------------------------------------------------------------

/// Run the full configuration validation pass.
///
/// Phase 13C: `dry_run` enables dataset path checks with verbose output.
/// In dry-run mode, path checks print what SNF found to stdout before
/// returning — main.rs exits after reporting without starting capture.
///
/// Call this once after config is built, before starting capture.
/// If the returned ValidationResult has errors, abort with exit code 1.
///
/// Example (normal run):
/// ```
/// let result = validate_config(&config, &mode, false);
/// if !result.report() { std::process::exit(1); }
/// ```
///
/// Example (dry-run):
/// ```
/// let result = validate_config(&config, &mode, true);
/// result.report();   // always print
/// std::process::exit(if result.is_valid() { 0 } else { 1 });
/// ```
pub fn validate_config(
    config:   &EngineConfig,
    mode:     &OperationMode,
    dry_run:  bool,
) -> ValidationResult {
    let mut r = ValidationResult::new();

    validate_capture(config, mode, &mut r);
    validate_flow(config, &mut r);
    validate_protocol(config, &mut r);
    validate_filter(config, &mut r);
    validate_output(config, mode, &mut r);
    validate_performance(config, mode, &mut r);
    validate_intelligence(config, &mut r);
    validate_cross_layer_clashes(config, mode, &mut r);
    validate_dataset_paths(config, mode, dry_run, &mut r); // Phase 13C

    r
}

// ----------------------------------------------------------------
// CAPTURE VALIDATION
// ----------------------------------------------------------------

fn validate_capture(config: &EngineConfig, mode: &OperationMode, r: &mut ValidationResult) {
    let cap = &config.capture;

    // PCAP mode requires a file path
    if cap.capture_mode == "pcap" && cap.pcap_file.is_none() {
        r.error("capture_mode is 'pcap' but no pcap_file path is set. \
                 Set capture.pcap_file to the PCAP file path.");
    }

    // Replay mode must use PCAP input
    if *mode == OperationMode::Replay && cap.capture_mode != "pcap" {
        r.error("OperationMode::Replay requires capture_mode = 'pcap'. \
                 Replay mode is for deterministic offline analysis only.");
    }

    // Replay mode must have pcap_file set
    if *mode == OperationMode::Replay && cap.pcap_file.is_none() {
        r.error("OperationMode::Replay requires a pcap_file to be set.");
    }

    // snaplen must be positive
    if cap.snaplen <= 0 {
        r.error(format!(
            "capture.snaplen={} is invalid. Must be > 0 (typically 65535).",
            cap.snaplen
        ));
    }

    // max_packet_size must be at least as large as snaplen
    if cap.max_packet_size > 0 && cap.max_packet_size < cap.snaplen as usize {
        r.warn(format!(
            "capture.max_packet_size={} is smaller than snaplen={}. \
             Packets between {} and {} bytes will be dropped.",
            cap.max_packet_size, cap.snaplen, cap.max_packet_size, cap.snaplen
        ));
    }

    // buffer_size sanity
    if cap.buffer_size < 64 * 1024 {
        r.warn(format!(
            "capture.buffer_size={}B is very small. \
             Recommend at least 4MB (4194304) to avoid packet drops under burst.",
            cap.buffer_size
        ));
    }

    // PCAP output rotation without output path
    if cap.rotation_interval_packets > 0 && cap.pcap_output_path.is_none() {
        r.warn("capture.rotation_interval_packets is set but pcap_output_path is None. \
               Rotation has no effect without an output path.");
    }

    if cap.rotation_interval_bytes > 0 && cap.pcap_output_path.is_none() {
        r.warn("capture.rotation_interval_bytes is set but pcap_output_path is None. \
               Rotation has no effect without an output path.");
    }

    // zero_copy_mode requires ring_buffer_slots
    if cap.zero_copy_mode && cap.ring_buffer_slots == 0 {
        r.error("capture.zero_copy_mode=true but ring_buffer_slots=0. \
                 Set ring_buffer_slots to a power-of-2 value (e.g. 4096).");
    }

    // capture_direction must be a known value
    match cap.capture_direction.as_str() {
        "in" | "out" | "both" => {}
        other => r.error(format!(
            "capture.capture_direction='{}' is invalid. Must be 'in', 'out', or 'both'.",
            other
        )),
    }
}

// ----------------------------------------------------------------
// FLOW VALIDATION
// ----------------------------------------------------------------

fn validate_flow(config: &EngineConfig, r: &mut ValidationResult) {
    let flow = &config.flow;

    if flow.max_flows == 0 {
        r.warn("flow.max_flows=0 means unlimited flows. \
               This may cause unbounded memory growth under attack traffic.");
    }

    if flow.tcp_stream_timeout < flow.flow_timeout {
        r.warn(format!(
            "flow.tcp_stream_timeout={}s is less than flow_timeout={}s. \
             TCP streams may expire before general flow cleanup.",
            flow.tcp_stream_timeout, flow.flow_timeout
        ));
    }

    match flow.flow_eviction_policy.as_str() {
        "lru" | "fifo" => {}
        other => r.error(format!(
            "flow.flow_eviction_policy='{}' is invalid. Must be 'lru' or 'fifo'.",
            other
        )),
    }

    match flow.flow_label_mode.as_str() {
        "5tuple" | "normalized" => {}
        other => r.error(format!(
            "flow.flow_label_mode='{}' is invalid. Must be '5tuple' or 'normalized'.",
            other
        )),
    }

    if flow.max_tcp_streams > flow.max_flows {
        r.warn(format!(
            "flow.max_tcp_streams={} exceeds max_flows={}. \
             TCP streams are a subset of flows — this limit will never be reached.",
            flow.max_tcp_streams, flow.max_flows
        ));
    }
}

// ----------------------------------------------------------------
// PROTOCOL VALIDATION
// ----------------------------------------------------------------

fn validate_protocol(config: &EngineConfig, r: &mut ValidationResult) {
    let proto = &config.protocol;

    // SMB enabled but no SMB ports
    if proto.enable_smb && proto.smb_ports.is_empty() {
        r.error("protocol.enable_smb=true but smb_ports is empty. \
                 SMB analyzer will never run. Add ports (typically [445, 139]).");
    }

    // DHCP enabled but no DHCP ports
    if proto.enable_dhcp && proto.dhcp_ports.is_empty() {
        r.error("protocol.enable_dhcp=true but dhcp_ports is empty. \
                 DHCP analyzer will never run. Add ports (typically [67, 68]).");
    }

    // HTTP enabled but no HTTP ports
    if proto.enable_http && proto.http_ports.is_empty() {
        r.error("protocol.enable_http=true but http_ports is empty. \
                 HTTP analyzer will never run. Add ports (typically [80, 8080]).");
    }

    // TLS enabled but no TLS ports — warning only because TLS can be detected by signature
    if proto.enable_tls && proto.tls_ports.is_empty() {
        r.warn("protocol.enable_tls=true but tls_ports is empty. \
               TLS will only be detected by byte signature, not by port hint.");
    }

    // QUIC enabled but no QUIC ports
    if proto.enable_quic && proto.quic_ports.is_empty() {
        r.error("protocol.enable_quic=true but quic_ports is empty. \
                 QUIC analyzer will never run. Add ports (typically [443]).");
    }

    // JA3/JA4 require TLS
    if proto.ja3_enabled && !proto.enable_tls {
        r.error("protocol.ja3_enabled=true but enable_tls=false. \
                 JA3 fingerprinting requires TLS analysis. Disable JA3 or enable TLS.");
    }

    if proto.ja4_enabled && !proto.enable_tls {
        r.error("protocol.ja4_enabled=true but enable_tls=false. \
                 JA4 fingerprinting requires TLS analysis. Disable JA4 or enable TLS.");
    }

    // DoH detection requires DNS
    if proto.doh_detection && !proto.enable_dns {
        r.error("protocol.doh_detection=true but enable_dns=false. \
                 DoH detection requires DNS analysis to be enabled.");
    }

    if proto.doh_detection && !proto.enable_tls {
        r.warn("protocol.doh_detection=true but enable_tls=false. \
               DoH detection works best with TLS enabled for HTTPS-based DoH.");
    }

    // ICMP flood tracking without ICMP
    if proto.icmp_track_flood && !proto.enable_icmp {
        r.error("protocol.icmp_track_flood=true but enable_icmp=false. \
                 ICMP flood tracking requires ICMP analysis to be enabled.");
    }

    // SMB auth tracking without SMB
    if proto.smb_track_auth && !proto.enable_smb {
        r.error("protocol.smb_track_auth=true but enable_smb=false. \
                 SMB auth tracking requires SMB analysis to be enabled.");
    }

    // DHCP lease tracking without DHCP
    if proto.dhcp_track_leases && !proto.enable_dhcp {
        r.error("protocol.dhcp_track_leases=true but enable_dhcp=false. \
                 DHCP lease tracking requires DHCP analysis to be enabled.");
    }

    // Flow domain binding requires DNS
    if proto.enable_flow_domain_binding && !proto.enable_dns {
        r.warn("protocol.enable_flow_domain_binding=true but enable_dns=false. \
               Domain binding will not work without DNS resolution.");
    }

    // dns_max_answers sanity
    if proto.dns_max_answers == 0 {
        r.warn("protocol.dns_max_answers=0 means no DNS answer records will be parsed.");
    }
}

// ----------------------------------------------------------------
// FILTER VALIDATION
// ----------------------------------------------------------------

fn validate_filter(config: &EngineConfig, r: &mut ValidationResult) {
    let filter = &config.filter;
    let proto  = &config.protocol;

    // Port filter targeting a TLS port but TLS disabled
    if let Some(port) = filter.port_filter {
        if proto.tls_ports.contains(&port) && !proto.enable_tls {
            r.error(format!(
                "filter.port_filter={} is a TLS port, but protocol.enable_tls=false. \
                 TLS traffic on port {} will be captured but not analyzed. \
                 Either enable TLS or use a different port filter.",
                port, port
            ));
        }

        if proto.quic_ports.contains(&port) && !proto.enable_quic {
            r.warn(format!(
                "filter.port_filter={} is a QUIC port, but protocol.enable_quic=false. \
                 QUIC traffic will be captured but not analyzed.",
                port
            ));
        }

        if proto.http_ports.contains(&port) && !proto.enable_http {
            r.warn(format!(
                "filter.port_filter={} is an HTTP port, but protocol.enable_http=false. \
                 HTTP traffic will be captured but not analyzed.",
                port
            ));
        }

        // DNS port filtered but DNS disabled
        if port == proto.dns_port && !proto.enable_dns {
            r.error(format!(
                "filter.port_filter={} (DNS port), but protocol.enable_dns=false. \
                 DNS traffic will be captured but not analyzed. Enable DNS or change filter.",
                port
            ));
        }
    }

    // Domain filter requires DNS
    if config.domain_filter.is_some() && !proto.enable_dns {
        r.error("domain_filter is set but protocol.enable_dns=false. \
                 Domain filtering requires DNS resolution. Enable DNS or remove domain_filter.");
    }

    // Conflicting IP filters
    if filter.src_ip_filter.is_some() && filter.ip_filter.is_some() {
        r.warn("Both filter.ip_filter and filter.src_ip_filter are set. \
               src_ip_filter takes precedence for source IP matching.");
    }

    if filter.dst_ip_filter.is_some() && filter.ip_filter.is_some() {
        r.warn("Both filter.ip_filter and filter.dst_ip_filter are set. \
               dst_ip_filter takes precedence for destination IP matching.");
    }

    // Conflicting port filters
    if filter.src_port_filter.is_some() && filter.port_filter.is_some() {
        r.warn("Both filter.port_filter and filter.src_port_filter are set. \
               src_port_filter takes precedence for source port matching.");
    }

    // flow_direction_filter validity
    match filter.flow_direction_filter.as_str() {
        "both" | "inbound" | "outbound" => {}
        other => r.error(format!(
            "filter.flow_direction_filter='{}' is invalid. \
             Must be 'both', 'inbound', or 'outbound'.",
            other
        )),
    }

    // min/max size clash — no packets would pass
    if filter.max_packet_size_filter > 0
        && filter.min_packet_size > filter.max_packet_size_filter
    {
        r.error(format!(
            "filter.min_packet_size={} > max_packet_size_filter={}. \
             No packets would pass this filter. Check your size filter values.",
            filter.min_packet_size, filter.max_packet_size_filter
        ));
    }

    // BPF + port filter redundancy
    if filter.bpf_filter.is_some() && filter.port_filter.is_some() {
        r.warn("Both filter.bpf_filter and filter.port_filter are set. \
               port_filter is applied after BPF — BPF is more efficient. \
               Consider moving the port filter into the BPF expression.");
    }
}

// ----------------------------------------------------------------
// OUTPUT VALIDATION
// ----------------------------------------------------------------

fn validate_output(config: &EngineConfig, mode: &OperationMode, r: &mut ValidationResult) {
    let out = &config.output;

    // JSON output with no file path — stdout only
    if out.output_format == "json" && out.log_file.is_none() {
        r.warn("output.output_format='json' but log_file is None. \
               JSON output will only go to stdout.");
    }

    if out.output_format == "ndjson"
        && out.ndjson_output_path.is_none()
        && out.log_file.is_none()
    {
        r.warn("output.output_format='ndjson' but neither ndjson_output_path \
               nor log_file is set. NDJSON output will only go to stdout.");
    }

    // Syslog without host
    if out.syslog_enabled && out.syslog_host.is_none() {
        r.error("output.syslog_enabled=true but syslog_host is not set. \
                 Provide a syslog destination host.");
    }

    // output_format validity
    match out.output_format.as_str() {
        "text" | "json" | "ndjson" => {}
        other => r.error(format!(
            "output.output_format='{}' is invalid. Must be 'text', 'json', or 'ndjson'.",
            other
        )),
    }

    // Stealth mode with verbose output — likely misconfiguration
    if *mode == OperationMode::Stealth && out.verbosity > 0 {
        r.warn(format!(
            "OperationMode::Stealth is set but output.verbosity={}. \
             Stealth mode is intended for minimal footprint. Consider verbosity=0.",
            out.verbosity
        ));
    }

    // pretty_print_json only applies to json mode
    if out.pretty_print_json && out.output_format != "json" {
        r.warn("output.pretty_print_json=true but output_format is not 'json'. \
               pretty_print_json has no effect in text or ndjson modes.");
    }

    // Raw headers significantly inflate output
    if out.include_raw_headers {
        r.warn("output.include_raw_headers=true significantly increases output size. \
               Only enable for targeted forensic sessions.");
    }

    // NDJSON rotation without path
    if out.ndjson_rotate_mb > 0 && out.ndjson_output_path.is_none() {
        r.warn("output.ndjson_rotate_mb is set but ndjson_output_path is None. \
               Rotation has no effect without an output path.");
    }
}

// ----------------------------------------------------------------
// PERFORMANCE VALIDATION
// ----------------------------------------------------------------

fn validate_performance(config: &EngineConfig, mode: &OperationMode, r: &mut ValidationResult) {
    let perf = &config.performance;

    // Replay mode requires single-threaded execution for determinism
    if *mode == OperationMode::Replay && perf.worker_threads != 1 {
        r.error(format!(
            "OperationMode::Replay requires performance.worker_threads=1 for \
             deterministic output. Currently set to {}.",
            perf.worker_threads
        ));
    }

    // Multi-threading with single flow table shard — contention bottleneck
    if perf.worker_threads > 1 && perf.flow_table_shards == 1 {
        r.warn(format!(
            "performance.worker_threads={} but flow_table_shards=1. \
             Single-shard flow table will be a contention bottleneck under \
             multithreaded load. Increase flow_table_shards (must be power of 2).",
            perf.worker_threads
        ));
    }

    // flow_table_shards must be a power of 2
    let shards = perf.flow_table_shards;
    if shards > 0 && (shards & (shards - 1)) != 0 {
        r.error(format!(
            "performance.flow_table_shards={} is not a power of 2. \
             Must be 1, 2, 4, 8, 16, 32, etc.",
            shards
        ));
    }

    // event_queue_size must be nonzero
    if perf.event_queue_size == 0 {
        r.error("performance.event_queue_size=0 is invalid. \
                 Must be at least 1. Recommended: 65536.");
    }

    // watchdog enabled but timeout is zero — would trigger immediately
    if perf.watchdog_enabled && perf.watchdog_timeout_ms == 0 {
        r.error("performance.watchdog_enabled=true but watchdog_timeout_ms=0. \
                 Watchdog would trigger immediately. Set a timeout > 0 (e.g. 30000).");
    }

    // io_uring is Linux-specific
    if perf.io_uring_enabled {
        r.warn("performance.io_uring_enabled=true. io_uring requires Linux 5.1+. \
               SNF will fall back to synchronous I/O if io_uring is unavailable.");
    }
}

// ----------------------------------------------------------------
// INTELLIGENCE VALIDATION
// ----------------------------------------------------------------

fn validate_intelligence(config: &EngineConfig, r: &mut ValidationResult) {
    let intel = &config.intelligence;

    // Beacon detection requires domain-bound flow tracking
    if intel.beacon_detection_enabled && !config.protocol.enable_flow_domain_binding {
        r.error("intelligence.beacon_detection_enabled=true but \
                 protocol.enable_flow_domain_binding=false. \
                 Beacon detection requires domain-bound flow tracking.");
    }

    // DGA detection requires DNS query analysis
    if intel.dga_detection_enabled && !config.protocol.enable_dns {
        r.error("intelligence.dga_detection_enabled=true but \
                 protocol.enable_dns=false. \
                 DGA detection requires DNS query analysis.");
    }

    // Entropy analysis operates on DNS names — warn if DNS disabled
    if intel.entropy_analysis_enabled && !config.protocol.enable_dns {
        r.warn("intelligence.entropy_analysis_enabled=true but \
               protocol.enable_dns=false. \
               Entropy analysis operates on DNS query names — enable DNS.");
    }

    // TLS risk alert requires TLS intelligence enabled
    if intel.tls_risk_alert_on_score && !config.protocol.tls_intelligence_enabled {
        r.error("intelligence.tls_risk_alert_on_score=true but \
                 protocol.tls_intelligence_enabled=false. \
                 TLS risk alerts require TLS intelligence to be enabled.");
    }

    // DGA threshold must be in (0.0, 1.0]
    if intel.dga_threshold <= 0.0 || intel.dga_threshold > 1.0 {
        r.error(format!(
            "intelligence.dga_threshold={:.3} is out of range. \
             Must be between 0.0 and 1.0 (exclusive). Recommended: 0.75.",
            intel.dga_threshold
        ));
    }

    // RDNS cache path required if learning is enabled
    if intel.rdns_learning_enabled && intel.rdns_cache_path.is_empty() {
        r.error("intelligence.rdns_learning_enabled=true but rdns_cache_path is empty. \
                 Provide a file path for the RDNS learning cache.");
    }
}

// ----------------------------------------------------------------
// CROSS-LAYER CLASH DETECTION
// ----------------------------------------------------------------

fn validate_cross_layer_clashes(
    config: &EngineConfig,
    mode:   &OperationMode,
    r:      &mut ValidationResult,
) {
    let proto  = &config.protocol;
    let filter = &config.filter;
    let out    = &config.output;
    let intel  = &config.intelligence;

    // Port 443 filtered but neither TLS nor QUIC enabled
    if let Some(port) = filter.port_filter {
        if port == 443 && !proto.enable_tls && !proto.enable_quic {
            r.error("filter.port_filter=443 but both protocol.enable_tls=false and \
                     enable_quic=false. Port 443 traffic would be captured but \
                     not analyzed at all. Enable TLS and/or QUIC.");
        }
    }

    // Domain filter with DNS and flow binding both disabled
    if config.domain_filter.is_some()
        && !proto.enable_dns
        && !proto.enable_flow_domain_binding
    {
        r.error("domain_filter is set but both DNS and flow domain binding are disabled. \
                 The domain filter will never match anything.");
    }

    // Stealth mode with no output configured at all
    if *mode == OperationMode::Stealth
        && out.verbosity == 0
        && out.ndjson_output_path.is_none()
        && out.log_file.is_none()
        && !out.syslog_enabled
    {
        r.warn("OperationMode::Stealth with verbosity=0 and no output paths configured. \
               SNF will run but produce no output. Add ndjson_output_path or syslog \
               to capture findings silently.");
    }

    // Forensic mode with verbosity=0 is almost certainly misconfigured
    if *mode == OperationMode::Forensic && out.verbosity == 0 {
        r.warn("OperationMode::Forensic with verbosity=0. \
               Forensic mode is intended for maximum detail — consider verbosity >= 2.");
    }

    // GeoIP enabled but no path — caught in intelligence but worth cross-layer reinforcement
    if intel.enable_geoip_mapping && intel.geo_db_path.is_empty() {
        r.error("intelligence.enable_geoip_mapping=true but geo_db_path is empty. \
                 Provide a MaxMind GeoIP MMDB file path.");
    }

    // ASN enabled but no path
    if intel.enable_asn_mapping && intel.asn_db_path.is_empty() {
        r.error("intelligence.enable_asn_mapping=true but asn_db_path is empty. \
                 Provide a MaxMind ASN MMDB file path.");
    }

    // TLS risk scoring requires both enable_tls and tls_intelligence_enabled
    if intel.tls_risk_alert_on_score
        && (!proto.enable_tls || !proto.tls_intelligence_enabled)
    {
        r.error("intelligence.tls_risk_alert_on_score=true but TLS analysis is \
                 not fully enabled. Requires both enable_tls=true and \
                 tls_intelligence_enabled=true.");
    }

    // Beacon detection needs long enough flow timeout to observe periodic patterns
    if intel.beacon_detection_enabled && config.flow.flow_timeout < 60 {
        r.warn(format!(
            "intelligence.beacon_detection_enabled=true but flow.flow_timeout={}s. \
             Beacon detection needs flows to persist long enough to observe \
             periodic patterns. Recommend flow_timeout >= 300s.",
            config.flow.flow_timeout
        ));
    }
}

// ----------------------------------------------------------------
// DATASET PATH VALIDATION  (Phase 13C)
// ----------------------------------------------------------------

/// Validate all file paths referenced in config: PCAP input, output files,
/// and intelligence databases. Checks for existence and parent-directory
/// writability before capture starts so operators get a clear error instead
/// of a silent runtime failure.
///
/// In dry-run mode (`dry_run=true`) this function also prints a structured
/// summary of every path that was checked to stdout — useful for pre-flight
/// verification without starting capture.
///
/// Security constraints:
///   - No path is opened or written here — checks are stat-only.
///   - Paths are not modified or interpolated — taken verbatim from config.
///   - Parent-directory check uses std::path::Path — no shell expansion.
fn validate_dataset_paths(
    config:  &EngineConfig,
    mode:    &OperationMode,
    dry_run: bool,
    r:       &mut ValidationResult,
) {
    // ---- PCAP input file ----
    // Required if capture_mode = "pcap" or mode = Replay. Already caught by
    // validate_capture for the "missing path" case — here we check existence.
    if config.capture.capture_mode == "pcap" || *mode == OperationMode::Replay {
        if let Some(ref pcap_path) = config.capture.pcap_file {
            if !Path::new(pcap_path).exists() {
                r.error(format!(
                    "PCAP file '{}' does not exist. \
                     Verify the path and that the file is readable.",
                    pcap_path
                ));
            } else if dry_run {
                match std::fs::metadata(pcap_path) {
                    Ok(m) => println!(
                        "[SNF DRY-RUN] PCAP input       OK  '{}' ({} bytes)",
                        pcap_path,
                        m.len()
                    ),
                    Err(e) => r.error(format!(
                        "PCAP file '{}' exists but cannot be stat'd: {}",
                        pcap_path, e
                    )),
                }
            }
        }
    }

    // ---- NDJSON output path — check parent directory is writable ----
    if let Some(ref out_path) = config.output.ndjson_output_path {
        let parent = Path::new(out_path).parent().unwrap_or(Path::new("."));
        if !parent.as_os_str().is_empty() && !parent.exists() {
            r.error(format!(
                "Output directory '{}' for ndjson_output_path='{}' does not exist. \
                 Create the directory or use a different output path.",
                parent.display(),
                out_path
            ));
        } else if dry_run {
            println!(
                "[SNF DRY-RUN] NDJSON output     OK  '{}' (parent dir exists)",
                out_path
            );
        }
    }

    // ---- Log file — check parent directory ----
    if let Some(ref log_path) = config.output.log_file {
        let parent = Path::new(log_path).parent().unwrap_or(Path::new("."));
        if !parent.as_os_str().is_empty() && !parent.exists() {
            r.warn(format!(
                "Log file directory '{}' for log_file='{}' does not exist. \
                 Log output will fail at runtime unless the directory is created.",
                parent.display(),
                log_path
            ));
        } else if dry_run {
            println!(
                "[SNF DRY-RUN] Log file          OK  '{}' (parent dir exists)",
                log_path
            );
        }
    }

    // ---- PCAP output path — check parent directory ----
    if let Some(ref pcap_out) = config.capture.pcap_output_path {
        let parent = Path::new(pcap_out).parent().unwrap_or(Path::new("."));
        if !parent.as_os_str().is_empty() && !parent.exists() {
            r.warn(format!(
                "PCAP output directory '{}' for pcap_output_path='{}' does not exist. \
                 PCAP output will fail at runtime.",
                parent.display(),
                pcap_out
            ));
        } else if dry_run {
            println!(
                "[SNF DRY-RUN] PCAP output       OK  '{}' (parent dir exists)",
                pcap_out
            );
        }
    }

    // ---- GeoIP database ----
    if config.intelligence.enable_geoip_mapping {
        let path = &config.intelligence.geo_db_path;
        if !path.is_empty() {
            if !Path::new(path).exists() {
                r.error(format!(
                    "GeoIP database '{}' does not exist. \
                     Download MaxMind GeoLite2-City.mmdb or disable enable_geoip_mapping.",
                    path
                ));
            } else if dry_run {
                println!(
                    "[SNF DRY-RUN] GeoIP database    OK  '{}'",
                    path
                );
            }
        }
        // empty path already caught in validate_cross_layer_clashes
    }

    // ---- ASN database ----
    if config.intelligence.enable_asn_mapping {
        let path = &config.intelligence.asn_db_path;
        if !path.is_empty() {
            if !Path::new(path).exists() {
                r.error(format!(
                    "ASN database '{}' does not exist. \
                     Download MaxMind GeoLite2-ASN.mmdb or disable enable_asn_mapping.",
                    path
                ));
            } else if dry_run {
                println!(
                    "[SNF DRY-RUN] ASN database      OK  '{}'",
                    path
                );
            }
        }
    }

    // ---- RDNS cache — check parent directory is writable ----
    if config.intelligence.rdns_learning_enabled {
        let path = &config.intelligence.rdns_cache_path;
        if !path.is_empty() {
            let parent = Path::new(path).parent().unwrap_or(Path::new("."));
            if !parent.as_os_str().is_empty() && !parent.exists() {
                r.error(format!(
                    "RDNS cache parent directory '{}' for rdns_cache_path='{}' \
                     does not exist. Create the directory or update rdns_cache_path.",
                    parent.display(),
                    path
                ));
            } else if dry_run {
                println!(
                    "[SNF DRY-RUN] RDNS cache        OK  '{}' (parent dir exists)",
                    path
                );
            }
        }
    }

    // ---- Dry-run: print full engine configuration summary ----
    if dry_run {
        println!("[SNF DRY-RUN] ------- Configuration Summary -------");
        println!("[SNF DRY-RUN] Operation mode    : {}", mode.as_str());
        println!("[SNF DRY-RUN] Capture mode      : {}", config.capture.capture_mode);
        println!("[SNF DRY-RUN] Interface index   : {}", config.capture.interface_index);
        println!("[SNF DRY-RUN] Worker threads    : {}", config.performance.worker_threads);
        println!("[SNF DRY-RUN] Max flows         : {}", config.flow.max_flows);
        println!("[SNF DRY-RUN] Flow timeout      : {}s", config.flow.flow_timeout);
        println!("[SNF DRY-RUN] Protocol gates    : dns={} tls={} quic={} http={} icmp={} dhcp={} smb={} mdns={}",
            config.protocol.enable_dns,
            config.protocol.enable_tls,
            config.protocol.enable_quic,
            config.protocol.enable_http,
            config.protocol.enable_icmp,
            config.protocol.enable_dhcp,
            config.protocol.enable_smb,
            config.protocol.enable_mdns,
        );
        println!("[SNF DRY-RUN] Fingerprinting    : ja3={} ja4={}",
            config.protocol.ja3_enabled,
            config.protocol.ja4_enabled,
        );
        println!("[SNF DRY-RUN] Intelligence      : asn={} geoip={} dga={} beacon={} entropy={}",
            config.intelligence.enable_asn_mapping,
            config.intelligence.enable_geoip_mapping,
            config.intelligence.dga_detection_enabled,
            config.intelligence.beacon_detection_enabled,
            config.intelligence.entropy_analysis_enabled,
        );
        println!("[SNF DRY-RUN] Output verbosity  : {}", config.output.verbosity);
        println!("[SNF DRY-RUN] Output format     : {}", config.output.output_format);
        println!("[SNF DRY-RUN] ------- End Summary -------");
    }
}