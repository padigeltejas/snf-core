// src/config/builder.rs
//
// ConfigBuilder - fluent builder for EngineConfig.
//
// Phase 4:  four operation mode presets added (Forensic, Monitor, Stealth, Replay).
// Phase 13A: validate_and_build() stamps self.mode into config.operation_mode
//            before returning. This is the single point where the chosen
//            OperationMode becomes part of the EngineConfig that travels
//            through capture, pipeline, and reporting.
// Phase 13C: validate_and_build() accepts dry_run flag - passed through to
//            validate_config() for dataset path checks.
// Phase 14F: hardware probe auto-tuning added. threads_explicit and no_auto_scale
//            flags control whether hardware probe overrides config defaults.

use super::engine_config::EngineConfig;
use super::mode::OperationMode;
use super::validator::validate_config;

pub struct ConfigBuilder {
    pub config: EngineConfig,
    pub mode:   OperationMode,

    /// True when --threads was explicitly passed via CLI.
    /// Prevents hardware_probe from overriding the operator's worker thread choice.
    pub threads_explicit: bool,

    /// True when --no-auto-scale was passed via CLI.
    /// Disables ALL hardware probe auto-tuning — SNF uses conservative defaults.
    /// Replay and Stealth still enforce worker_threads=1 regardless.
    pub no_auto_scale: bool,
}

impl ConfigBuilder {
    // ----------------------------------------------------------------
    // CONSTRUCTORS
    // ----------------------------------------------------------------

    pub fn new() -> Self {
        Self {
            config:           EngineConfig::default(),
            mode:             OperationMode::default(),
            threads_explicit: false,
            no_auto_scale:    false,
        }
    }

    // ----------------------------------------------------------------
    // OPERATION MODE PRESETS
    // ----------------------------------------------------------------

    /// Forensic mode - maximum depth, all analyzers, all events.
    /// Use for DFIR, post-incident analysis, court-admissible output.
    pub fn forensic() -> Self {
        let mut config = EngineConfig::default();

        // Capture: full snaplen, promiscuous
        config.capture.snaplen           = 65535;
        config.capture.promiscuous_mode  = true;
        config.capture.stats_interval_ms = 5000;

        // Flow: long timeouts, export everything
        config.flow.flow_timeout         = 300;
        config.flow.tcp_stream_timeout   = 600;
        config.flow.udp_flow_timeout     = 60;
        config.flow.export_expired_flows = true;
        config.flow.min_flow_packets     = 1;

        // Protocol: all analyzers on
        config.protocol.enable_dns               = true;
        config.protocol.enable_tls               = true;
        config.protocol.enable_quic              = true;
        config.protocol.enable_icmp              = true;
        config.protocol.enable_http              = true;
        config.protocol.enable_dhcp              = true;
        config.protocol.enable_smb               = true;
        config.protocol.enable_mdns              = true;
        config.protocol.enable_ftp               = true;
        config.protocol.enable_ssh               = true;
        config.protocol.tls_cert_extraction      = true;
        config.protocol.tls_intelligence_enabled = true;
        config.protocol.smb_track_auth           = true;
        config.protocol.dhcp_track_leases        = true;
        config.protocol.ja3_enabled              = true;
        config.protocol.ja4_enabled              = true;
        config.protocol.doh_detection            = true;

        // Intelligence: full scoring and attribution
        config.intelligence.enable_asn_mapping       = true;
        config.intelligence.enable_geoip_mapping     = true;
        config.intelligence.enable_reverse_dns       = true;
        config.intelligence.entropy_analysis_enabled = true;
        config.intelligence.dga_detection_enabled    = true;
        config.intelligence.tls_risk_alert_on_score  = true;
        config.intelligence.tls_risk_threshold       = 30;

        // Output: maximum verbosity, all protocol logs on
        config.output.verbosity             = 3;
        config.output.output_format         = "ndjson".to_string();
        config.output.suppress_flow_updates = false;
        config.output.suppress_parse_errors = false;
        config.output.show_packet_logs      = true;
        config.output.show_dns_logs         = true;
        config.output.show_tls_logs         = true;
        config.output.show_http_logs        = true;
        config.output.show_smb_logs         = true;
        config.output.show_dhcp_logs        = true;
        config.output.show_mdns_logs        = true;

        // Performance: single thread for determinism by default in forensic mode
        config.performance.worker_threads = 1;
        config.performance.stats_enabled  = true;

        Self { config, mode: OperationMode::Forensic, threads_explicit: false, no_auto_scale: false }
    }

    /// Monitor mode - lightweight 24/7 SOC deployment.
    /// Flow-level visibility, reduced verbosity, suppressed noisy events.
    pub fn monitor() -> Self {
        let mut config = EngineConfig::default();

        // Capture: standard, moderate stats interval
        config.capture.promiscuous_mode  = true;
        config.capture.stats_interval_ms = 30_000;

        // Flow: moderate timeouts, filter single-packet noise
        config.flow.flow_timeout         = 120;
        config.flow.tcp_stream_timeout   = 300;
        config.flow.export_expired_flows = true;
        config.flow.min_flow_packets     = 2;

        // Protocol: core protocols only - skip expensive/noisy ones
        config.protocol.enable_dns               = true;
        config.protocol.enable_tls               = true;
        config.protocol.enable_quic              = true;
        config.protocol.enable_icmp              = false;
        config.protocol.enable_http              = true;
        config.protocol.enable_dhcp              = true;
        config.protocol.enable_smb               = true;
        config.protocol.enable_mdns              = false;
        config.protocol.tls_cert_extraction      = false;
        config.protocol.ja3_enabled              = true;
        config.protocol.ja4_enabled              = false;
        config.protocol.doh_detection            = true;

        // Intelligence: attribution + scoring, moderate threshold
        config.intelligence.enable_asn_mapping       = true;
        config.intelligence.enable_geoip_mapping     = true;
        config.intelligence.enable_reverse_dns       = true;
        config.intelligence.tls_risk_alert_on_score  = true;
        config.intelligence.tls_risk_threshold       = 60;
        config.intelligence.dga_detection_enabled    = true;
        config.intelligence.beacon_detection_enabled = true;

        // Output: events only, suppress flow updates and parse errors
        config.output.verbosity             = 1;
        config.output.output_format         = "ndjson".to_string();
        config.output.suppress_flow_updates = true;
        config.output.suppress_parse_errors = true;
        config.output.show_packet_logs      = false;
        config.output.show_dns_logs         = false;

        // Performance: multiple threads acceptable in monitor mode
        config.performance.worker_threads           = 2;
        config.performance.stats_enabled            = true;
        config.performance.stats_output_interval_ms = 60_000;

        Self { config, mode: OperationMode::Monitor, threads_explicit: false, no_auto_scale: false }
    }

    /// Stealth mode - minimal footprint covert sensor.
    /// No console output. No disk writes unless explicitly configured.
    /// Passive only - no active queries of any kind.
    pub fn stealth() -> Self {
        let mut config = EngineConfig::default();

        // Capture: promiscuous, no stats output (zero console noise)
        config.capture.promiscuous_mode  = true;
        config.capture.stats_interval_ms = 0;

        // Flow: moderate timeouts, further reduce noise
        config.flow.flow_timeout         = 120;
        config.flow.export_expired_flows = true;
        config.flow.min_flow_packets     = 3;

        // Protocol: core passive analysis only
        config.protocol.enable_dns               = true;
        config.protocol.enable_tls               = true;
        config.protocol.enable_quic              = true;
        config.protocol.enable_icmp              = false;
        config.protocol.enable_http              = false;
        config.protocol.enable_dhcp              = true;
        config.protocol.enable_smb               = false;
        config.protocol.smb_track_auth           = false;
        config.protocol.enable_mdns              = true;
        config.protocol.tls_cert_extraction      = false;
        config.protocol.ja3_enabled              = true;
        config.protocol.ja4_enabled              = false;
        config.protocol.doh_detection            = false;

        // Intelligence: no file reads in stealth mode
        config.intelligence.enable_asn_mapping       = false;
        config.intelligence.enable_geoip_mapping     = false;
        config.intelligence.enable_reverse_dns       = false;
        config.intelligence.rdns_learning_enabled    = false;
        config.intelligence.tls_risk_alert_on_score  = false;
        config.intelligence.dga_detection_enabled    = false;
        config.intelligence.beacon_detection_enabled = false;

        // Output: completely silent
        config.output.verbosity             = 0;
        config.output.output_format         = "ndjson".to_string();
        config.output.ndjson_output_path    = None;
        config.output.suppress_flow_updates = true;
        config.output.suppress_parse_errors = true;
        config.output.show_packet_logs      = false;
        config.output.show_dns_logs         = false;
        config.output.show_tls_logs         = false;
        config.output.show_flow_logs        = false;
        config.output.show_device_logs      = false;
        config.output.show_icmp_logs        = false;
        config.output.show_quic_logs        = false;
        config.output.show_http_logs        = false;
        config.output.show_smb_logs         = false;
        config.output.show_dhcp_logs        = false;
        config.output.show_mdns_logs        = false;

        // Performance: minimal, no watchdog
        config.performance.worker_threads   = 1;
        config.performance.stats_enabled    = false;
        config.performance.watchdog_enabled = false;

        Self { config, mode: OperationMode::Stealth, threads_explicit: false, no_auto_scale: false }
    }

    /// Replay mode - deterministic PCAP replay.
    /// SHA-256 of (input PCAP + config + SNF version) = identical output every run.
    /// Single-threaded by requirement. No wall-clock time used anywhere.
    pub fn replay() -> Self {
        let mut config = EngineConfig::default();

        // Capture: PCAP mode, no live interface, deterministic timestamps only
        config.capture.capture_mode       = "pcap".to_string();
        config.capture.promiscuous_mode   = false;
        config.capture.nano_timestamp     = false;
        config.capture.zero_copy_mode     = false;
        config.capture.stats_interval_ms  = 0;

        // Flow: fixed hash seed for reproducibility
        config.flow.flow_hash_seed        = 0;
        config.flow.flow_label_mode       = "normalized".to_string();
        config.flow.export_expired_flows  = true;

        // Protocol: all analyzers on — full depth deterministic replay
        config.protocol.enable_dns               = true;
        config.protocol.enable_tls               = true;
        config.protocol.enable_quic              = true;
        config.protocol.enable_icmp              = true;
        config.protocol.enable_http              = true;
        config.protocol.enable_dhcp              = true;
        config.protocol.enable_smb               = true;
        config.protocol.enable_mdns              = true;
        config.protocol.tls_cert_extraction      = true;
        config.protocol.ja3_enabled              = true;
        config.protocol.ja4_enabled              = true;
        config.protocol.doh_detection            = true;

        // Intelligence: enabled, RDNS learning disabled for determinism
        config.intelligence.enable_asn_mapping       = true;
        config.intelligence.enable_geoip_mapping     = true;
        config.intelligence.enable_reverse_dns       = true;
        config.intelligence.rdns_learning_enabled    = false;
        config.intelligence.tls_risk_alert_on_score  = true;
        config.intelligence.tls_risk_threshold       = 30;
        config.intelligence.entropy_analysis_enabled = true;
        config.intelligence.dga_detection_enabled    = true;

        // Output: NDJSON, all events emitted
        config.output.verbosity             = 2;
        config.output.output_format         = "ndjson".to_string();
        config.output.pretty_print_json     = false;
        config.output.suppress_flow_updates = false;
        config.output.suppress_parse_errors = false;

        // Performance: single thread — NON-NEGOTIABLE for determinism
        config.performance.worker_threads   = 1;
        config.performance.stats_enabled    = false;
        config.performance.io_uring_enabled = false;
        config.performance.batch_event_emit = false;

        Self { config, mode: OperationMode::Replay, threads_explicit: false, no_auto_scale: false }
    }

    // ----------------------------------------------------------------
    // LEGACY MODE ALIASES
    // ----------------------------------------------------------------

    /// Legacy --light flag - Monitor mode.
    pub fn light()    -> Self { Self::monitor() }

    /// Legacy --advanced flag - Forensic mode.
    pub fn advanced() -> Self { Self::forensic() }

    /// Legacy --minimal flag - Stealth mode.
    pub fn minimal()  -> Self { Self::stealth() }

    // ----------------------------------------------------------------
    // FLUENT SETTERS
    // ----------------------------------------------------------------

    pub fn set_interface(mut self, index: usize) -> Self {
        self.config.capture.interface_index = index;
        self
    }

    pub fn set_interface_name(mut self, name: String) -> Self {
        self.config.capture.interface_name = Some(name);
        self
    }

    pub fn set_packet_limit(mut self, limit: usize) -> Self {
        self.config.capture.packet_limit = limit;
        self
    }

    pub fn set_timeout(mut self, timeout: u64) -> Self {
        self.config.capture.capture_timeout = timeout;
        self
    }

    pub fn set_threads(mut self, threads: usize) -> Self {
        self.config.performance.worker_threads = threads;
        self
    }

    pub fn set_bpf(mut self, filter: String) -> Self {
        self.config.filter.bpf_filter = Some(filter);
        self
    }

    pub fn set_domain_filter(mut self, domain: String) -> Self {
        self.config.domain_filter = Some(domain);
        self
    }

    pub fn set_pcap_file(mut self, path: String) -> Self {
        self.config.capture.pcap_file    = Some(path);
        self.config.capture.capture_mode = "pcap".to_string();
        self
    }

    pub fn set_output_file(mut self, path: String) -> Self {
        self.config.output.ndjson_output_path = Some(path);
        self
    }

    pub fn set_verbosity(mut self, level: u8) -> Self {
        self.config.output.verbosity = level;
        self
    }

    pub fn set_mode(mut self, mode: OperationMode) -> Self {
        self.mode = mode;
        self
    }

    // ----------------------------------------------------------------
    // VALIDATE + BUILD
    // ----------------------------------------------------------------

    /// Validate the config and build the final EngineConfig.
    ///
    /// Phase 13A: stamps self.mode into config.operation_mode before returning.
    /// Phase 13C: dry_run=true triggers dataset path checks and config summary.
    /// Phase 14F: hardware probe runs here. threads_explicit and no_auto_scale
    ///            control whether probe overrides are applied.
    ///
    /// Prints all warnings and errors to stderr.
    /// Exits with code 1 if any errors are found.
    pub fn validate_and_build(mut self, dry_run: bool) -> EngineConfig {
        self.config.operation_mode = self.mode.clone();

        // Phase 14F: probe hardware, apply auto-tuning, then print ACTUAL values.
        // The print happens AFTER apply_hardware_profile so it reflects what SNF
        // will actually use — not what the probe recommends.
        {
            use crate::platform::hardware_probe::{HardwareProbe, apply_hardware_profile};

            let profile = HardwareProbe::run(&self.config, &self.mode);

            apply_hardware_profile(
                &mut self.config,
                &profile,
                &self.mode,
                self.threads_explicit,
                self.no_auto_scale,
            );

            // Print actual config values post-tuning.
            // Use profile.summary() as the base but override the tail with real values
            // so --no-auto-scale and --threads show what's actually happening.
            let workers    = self.config.performance.worker_threads;
            let batch      = self.config.performance.packet_batch_size;
            let ring       = self.config.capture.ring_buffer_slots;
            let zero_copy  = self.config.performance.zero_copy_rx;
            let scale_note = if self.no_auto_scale { " [no-auto-scale]" } else { "" };

            // profile.summary() contains "Hardware: X CPUs ... → N workers / ..."
            // We rebuild the line from scratch using profile fields + actual config.
            eprintln!(
                "[SNF] Hardware: {} CPUs ({}), {} MB RAM, NUMA={}, {} → \
                 {} workers / batch={} / ring={} / zero_copy={}{}",
                profile.available_cpus,
                profile.cpu_arch,
                profile.total_ram_mb,
                if profile.numa.is_numa { "yes" } else { "no" },
                profile.capture.best.throughput_hint(),
                workers,
                batch,
                ring,
                zero_copy,
                scale_note,
            );
        }

        let result = validate_config(&self.config, &self.mode, dry_run);
        if !result.report() {
            eprintln!("\n[SNF] Configuration validation failed. Aborting.");
            std::process::exit(1);
        }

        self.config
    }

    /// Build without validation. Use only in unit tests.
    pub fn build(mut self) -> EngineConfig {
        self.config.operation_mode = self.mode;
        self.config
    }
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}