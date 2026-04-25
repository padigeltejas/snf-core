// src/config/cli.rs
//
// SNF Command Line Interface — argument parsing and help text.
//
// Phase 4:  expanded from 7 to 40+ flags covering all 7 engine layers.
// Phase 13D: added --dry-run, --determinism-check, --keep-determinism-files,
//            and --determinism-output flags.
// Phase 14F: added --threads (explicit override, disables hardware probe scaling),
//            --packet-batch, --max-memory, --no-auto-scale.
//
// Argument parsing is intentional hand-rolled (no clap dependency) to keep
// the binary lightweight and avoid supply-chain risk in a security tool.

// ----------------------------------------------------------------
// CLI ARGUMENT STRUCTURE
// ----------------------------------------------------------------

#[derive(Clone, Default)]
pub struct CliArgs {
    // ---------------- OPERATION MODE ----------------
    /// Explicit mode flag: forensic | monitor | stealth | replay
    pub mode: Option<String>,

    // ---------------- LEGACY MODE FLAGS (backward compat) ----------------
    pub light:    bool,
    pub advanced: bool,
    pub minimal:  bool,

    // ---------------- CAPTURE ----------------
    pub interface:         Option<usize>,
    pub interface_name:    Option<String>,
    pub packet_limit:      Option<usize>,
    pub timeout:           Option<u64>,
    pub snaplen:           Option<i32>,
    pub buffer_size:       Option<usize>,
    pub promiscuous:       Option<bool>,
    pub capture_mode:      Option<String>,
    pub pcap_file:         Option<String>,
    pub pcap_output:       Option<String>,
    pub capture_direction: Option<String>,

    // ---------------- FLOW ----------------
    pub flow_timeout:       Option<u64>,
    pub max_flows:          Option<usize>,
    pub tcp_stream_timeout: Option<u64>,
    pub udp_flow_timeout:   Option<u64>,
    pub min_flow_packets:   Option<usize>,

    // ---------------- PROTOCOL ----------------
    pub enable_dns:  Option<bool>,
    pub enable_tls:  Option<bool>,
    pub enable_quic: Option<bool>,
    pub enable_icmp: Option<bool>,
    pub enable_http: Option<bool>,
    pub enable_dhcp: Option<bool>,
    pub enable_smb:  Option<bool>,
    pub enable_mdns: Option<bool>,

    // ---------------- FILTER ----------------
    pub bpf:               Option<String>,
    pub port:              Option<u16>,
    pub src_port:          Option<u16>,
    pub dst_port:          Option<u16>,
    pub ip:                Option<String>,
    pub src_ip:            Option<String>,
    pub dst_ip:            Option<String>,
    pub subnet:            Option<String>,
    pub exclude_loopback:  Option<bool>,
    pub exclude_multicast: Option<bool>,
    pub domain_filter:     Option<String>,

    // ---------------- OUTPUT ----------------
    pub verbosity:             Option<u8>,
    pub output_format:         Option<String>,
    pub log_file:              Option<String>,
    pub ndjson_output:         Option<String>,
    pub suppress_flow_updates: Option<bool>,
    pub suppress_parse_errors: Option<bool>,

    // ---------------- PERFORMANCE ----------------
    /// --threads <n>: explicit worker thread count.
    /// When set, hardware probe auto-scaling is disabled for thread count.
    pub threads: Option<usize>,

    /// --packet-batch <n>: packets processed per worker loop iteration.
    pub packet_batch: Option<usize>,

    /// --max-memory <MB>: cap total memory usage in megabytes.
    /// When set, ring buffer slots and flow table size are scaled down to fit.
    pub max_memory_mb: Option<usize>,

    /// --no-auto-scale: disable hardware probe auto-tuning entirely.
    /// SNF will use conservative config defaults instead of probing hardware.
    /// Useful on shared servers where SNF should not consume all available resources.
    pub no_auto_scale: bool,

    // ---------------- DEBUG ----------------
    pub debug_packets: bool,
    pub dump_raw:      bool,

    // ---------------- META ----------------
    pub help:        bool,
    pub version:     bool,
    pub config_file: Option<String>,

    // ---------------- PHASE 13D: DRY-RUN ----------------
    /// --dry-run: validate config and all file paths, print summary, exit.
    /// Does NOT start capture. Exit 0 if valid, exit 1 if errors.
    pub dry_run: bool,

    // ---------------- PHASE 13B: DETERMINISM CHECK ----------------
    /// --determinism-check: run two replay passes, SHA-256 compare outputs.
    /// Requires --pcap-file. Forces --mode replay.
    pub determinism_check: bool,

    /// --keep-determinism-files: do not delete pass1/pass2 NDJSON after check.
    /// Useful for manual diff when a failure is reported.
    pub keep_determinism_files: bool,

    /// --determinism-output <base>: base path for determinism output files.
    /// Defaults to "snf_determinism" in the current directory.
    pub determinism_output: Option<String>,
}

// ----------------------------------------------------------------
// CLI PARSER
// ----------------------------------------------------------------

pub fn parse_cli() -> CliArgs {
    let args: Vec<String> = std::env::args().collect();
    let mut a = CliArgs::default();
    let mut i = 1;

    while i < args.len() {
        match args[i].as_str() {

            // ---------------- META ----------------
            "--help" | "-h"    => { a.help = true; }
            "--version" | "-v" => { a.version = true; }
            "--config" | "-c"  => {
                a.config_file = next_arg(&args, &mut i);
            }

            // ---------------- OPERATION MODES ----------------
            "--mode" | "-m" => {
                a.mode = next_arg(&args, &mut i);
            }
            "--forensic" => { a.mode = Some("forensic".to_string()); }
            "--monitor"  => { a.mode = Some("monitor".to_string());  }
            "--stealth"  => { a.mode = Some("stealth".to_string());  }
            "--replay"   => { a.mode = Some("replay".to_string());   }

            // Legacy mode flags
            "--light"    => { a.light    = true; }
            "--advanced" => { a.advanced = true; }
            "--minimal"  => { a.minimal  = true; }

            // ---------------- CAPTURE ----------------
            "--interface" | "-i" => {
                a.interface = next_arg(&args, &mut i).and_then(|s| s.parse().ok());
            }
            "--interface-name" | "--iface" => {
                a.interface_name = next_arg(&args, &mut i);
            }
            "--limit" | "-l" | "--packet-limit" => {
                a.packet_limit = next_arg(&args, &mut i).and_then(|s| s.parse().ok());
            }
            "--timeout" | "-t" => {
                a.timeout = next_arg(&args, &mut i).and_then(|s| s.parse().ok());
            }
            "--snaplen" => {
                a.snaplen = next_arg(&args, &mut i).and_then(|s| s.parse().ok());
            }
            "--buffer-size" => {
                a.buffer_size = next_arg(&args, &mut i).and_then(|s| s.parse().ok());
            }
            "--promiscuous" | "--promisc" => { a.promiscuous = Some(true);  }
            "--no-promiscuous"            => { a.promiscuous = Some(false); }
            "--capture-mode" => {
                a.capture_mode = next_arg(&args, &mut i);
            }
            "--pcap-file" | "--pcap" => {
                a.pcap_file    = next_arg(&args, &mut i);
                // Auto-set capture mode to pcap when file is specified.
                a.capture_mode = Some("pcap".to_string());
            }
            "--pcap-output" => {
                a.pcap_output = next_arg(&args, &mut i);
            }
            "--direction" => {
                a.capture_direction = next_arg(&args, &mut i);
            }

            // ---------------- FLOW ----------------
            "--flow-timeout" => {
                a.flow_timeout = next_arg(&args, &mut i).and_then(|s| s.parse().ok());
            }
            "--max-flows" => {
                a.max_flows = next_arg(&args, &mut i).and_then(|s| s.parse().ok());
            }
            "--tcp-timeout" => {
                a.tcp_stream_timeout = next_arg(&args, &mut i).and_then(|s| s.parse().ok());
            }
            "--udp-timeout" => {
                a.udp_flow_timeout = next_arg(&args, &mut i).and_then(|s| s.parse().ok());
            }
            "--min-flow-packets" => {
                a.min_flow_packets = next_arg(&args, &mut i).and_then(|s| s.parse().ok());
            }

            // ---------------- PROTOCOL GATES ----------------
            "--enable-dns"   => { a.enable_dns  = Some(true);  }
            "--disable-dns"  => { a.enable_dns  = Some(false); }
            "--enable-tls"   => { a.enable_tls  = Some(true);  }
            "--disable-tls"  => { a.enable_tls  = Some(false); }
            "--enable-quic"  => { a.enable_quic = Some(true);  }
            "--disable-quic" => { a.enable_quic = Some(false); }
            "--enable-icmp"  => { a.enable_icmp = Some(true);  }
            "--disable-icmp" => { a.enable_icmp = Some(false); }
            "--enable-http"  => { a.enable_http = Some(true);  }
            "--disable-http" => { a.enable_http = Some(false); }
            "--enable-dhcp"  => { a.enable_dhcp = Some(true);  }
            "--disable-dhcp" => { a.enable_dhcp = Some(false); }
            "--enable-smb"   => { a.enable_smb  = Some(true);  }
            "--disable-smb"  => { a.enable_smb  = Some(false); }
            "--enable-mdns"  => { a.enable_mdns = Some(true);  }
            "--disable-mdns" => { a.enable_mdns = Some(false); }

            // ---------------- FILTER ----------------
            "--bpf" | "--filter" => {
                a.bpf = next_arg(&args, &mut i);
            }
            "--port" | "-p" => {
                a.port = next_arg(&args, &mut i).and_then(|s| s.parse().ok());
            }
            "--src-port" => {
                a.src_port = next_arg(&args, &mut i).and_then(|s| s.parse().ok());
            }
            "--dst-port" => {
                a.dst_port = next_arg(&args, &mut i).and_then(|s| s.parse().ok());
            }
            "--ip" => {
                a.ip = next_arg(&args, &mut i);
            }
            "--src-ip" => {
                a.src_ip = next_arg(&args, &mut i);
            }
            "--dst-ip" => {
                a.dst_ip = next_arg(&args, &mut i);
            }
            "--subnet" => {
                a.subnet = next_arg(&args, &mut i);
            }
            "--exclude-loopback"  => { a.exclude_loopback  = Some(true);  }
            "--include-loopback"  => { a.exclude_loopback  = Some(false); }
            "--exclude-multicast" => { a.exclude_multicast = Some(true);  }
            "--domain" | "-d"     => {
                a.domain_filter = next_arg(&args, &mut i);
            }

            // ---------------- OUTPUT ----------------
            "--verbosity" | "--verbose" => {
                a.verbosity = next_arg(&args, &mut i).and_then(|s| s.parse().ok());
            }
            "--output-format" | "--format" => {
                a.output_format = next_arg(&args, &mut i);
            }
            "--log-file" | "--log" => {
                a.log_file = next_arg(&args, &mut i);
            }
            "--output" | "-o" | "--ndjson-output" => {
                a.ndjson_output = next_arg(&args, &mut i);
            }
            "--suppress-flow-updates" => { a.suppress_flow_updates = Some(true); }
            "--suppress-parse-errors" => { a.suppress_parse_errors = Some(true); }
            "--silent"                => { a.verbosity = Some(0); }
            "--quiet"                 => { a.verbosity = Some(1); }

            // ---------------- PERFORMANCE ----------------
            "--threads" => {
                a.threads = next_arg(&args, &mut i).and_then(|s| s.parse().ok());
            }
            "--packet-batch" => {
                a.packet_batch = next_arg(&args, &mut i).and_then(|s| s.parse().ok());
            }
            "--max-memory" | "--max-mem" => {
                a.max_memory_mb = next_arg(&args, &mut i).and_then(|s| s.parse().ok());
            }
            "--no-auto-scale" => {
                a.no_auto_scale = true;
            }

            // ---------------- DEBUG ----------------
            "--debug-packets" | "--debug" => { a.debug_packets = true; }
            "--dump-raw"                  => { a.dump_raw = true;       }

            // ----------------------------------------------------------------
            // PHASE 13D — DRY-RUN
            // ----------------------------------------------------------------

            // --dry-run: validate config + all file paths, print summary, exit.
            // Does not start capture. Exit 0 if valid, exit 1 if config errors found.
            "--dry-run" => {
                a.dry_run = true;
            }

            // ----------------------------------------------------------------
            // PHASE 13B — DETERMINISM CHECK
            // ----------------------------------------------------------------

            // --determinism-check: run two PCAP replay passes and SHA-256 compare.
            // Forces replay mode. Requires --pcap-file.
            "--determinism-check" => {
                a.determinism_check = true;
                // Determinism check always uses replay mode for correctness.
                a.mode = Some("replay".to_string());
            }

            // --keep-determinism-files: keep pass1/pass2 NDJSON after check.
            "--keep-determinism-files" => {
                a.keep_determinism_files = true;
            }

            // --determinism-output <base>: base path for intermediate files.
            "--determinism-output" => {
                a.determinism_output = next_arg(&args, &mut i);
            }

            // ---------------- UNKNOWN ----------------
            other => {
                eprintln!("[SNF] Unknown argument: {}  (use --help for usage)", other);
            }
        }

        i += 1;
    }

    a
}

// ----------------------------------------------------------------
// APPLY CLI ARGS TO CONFIG BUILDER
// ----------------------------------------------------------------
// Applies parsed CLI arguments on top of a mode preset.
// Order: mode preset → config file → CLI flags (CLI wins).

use super::builder::ConfigBuilder;
use super::mode::OperationMode;

pub fn apply_cli_to_builder(args: &CliArgs) -> ConfigBuilder {
    // Select base mode — explicit --mode wins, then legacy flags, then default.
    let mut builder = if let Some(ref mode_str) = args.mode {
        match OperationMode::from_str(mode_str) {
            Some(OperationMode::Forensic) => ConfigBuilder::forensic(),
            Some(OperationMode::Monitor)  => ConfigBuilder::monitor(),
            Some(OperationMode::Stealth)  => ConfigBuilder::stealth(),
            Some(OperationMode::Replay)   => ConfigBuilder::replay(),
            None => {
                eprintln!(
                    "[SNF ERROR] Unknown mode '{}'. Valid modes: forensic, monitor, stealth, replay",
                    mode_str
                );
                std::process::exit(1);
            }
        }
    } else if args.advanced {
        ConfigBuilder::forensic()
    } else if args.light {
        ConfigBuilder::monitor()
    } else if args.minimal {
        ConfigBuilder::stealth()
    } else {
        ConfigBuilder::new()
    };

    // ---------------- CAPTURE OVERRIDES ----------------
    if let Some(idx)    = args.interface              { builder.config.capture.interface_index   = idx; }
    if let Some(ref n)  = args.interface_name         { builder.config.capture.interface_name    = Some(n.clone()); }
    if let Some(limit)  = args.packet_limit           { builder.config.capture.packet_limit      = limit; }
    if let Some(t)      = args.timeout                { builder.config.capture.capture_timeout   = t; }
    if let Some(s)      = args.snaplen                { builder.config.capture.snaplen            = s; }
    if let Some(b)      = args.buffer_size            { builder.config.capture.buffer_size       = b; }
    if let Some(p)      = args.promiscuous            { builder.config.capture.promiscuous_mode  = p; }
    if let Some(ref m)  = args.capture_mode           { builder.config.capture.capture_mode      = m.clone(); }
    if let Some(ref p)  = args.pcap_file {
        builder.config.capture.pcap_file    = Some(p.clone());
        builder.config.capture.capture_mode = "pcap".to_string();
    }
    if let Some(ref p)  = args.pcap_output            { builder.config.capture.pcap_output_path  = Some(p.clone()); }
    if let Some(ref d)  = args.capture_direction      { builder.config.capture.capture_direction = d.clone(); }

    // ---------------- FLOW OVERRIDES ----------------
    if let Some(t) = args.flow_timeout        { builder.config.flow.flow_timeout        = t; }
    if let Some(n) = args.max_flows           { builder.config.flow.max_flows           = n; }
    if let Some(t) = args.tcp_stream_timeout  { builder.config.flow.tcp_stream_timeout  = t; }
    if let Some(t) = args.udp_flow_timeout    { builder.config.flow.udp_flow_timeout    = t; }
    if let Some(n) = args.min_flow_packets    { builder.config.flow.min_flow_packets    = n; }

    // ---------------- PROTOCOL OVERRIDES ----------------
    if let Some(v) = args.enable_dns   { builder.config.protocol.enable_dns   = v; }
    if let Some(v) = args.enable_tls   { builder.config.protocol.enable_tls   = v; }
    if let Some(v) = args.enable_quic  { builder.config.protocol.enable_quic  = v; }
    if let Some(v) = args.enable_icmp  { builder.config.protocol.enable_icmp  = v; }
    if let Some(v) = args.enable_http  { builder.config.protocol.enable_http  = v; }
    if let Some(v) = args.enable_dhcp  { builder.config.protocol.enable_dhcp  = v; }
    if let Some(v) = args.enable_smb   { builder.config.protocol.enable_smb   = v; }
    if let Some(v) = args.enable_mdns  { builder.config.protocol.enable_mdns  = v; }

    // ---------------- FILTER OVERRIDES ----------------
    if let Some(ref f)  = args.bpf               { builder.config.filter.bpf_filter        = Some(f.clone()); }
    if let Some(p)      = args.port              { builder.config.filter.port_filter        = Some(p); }
    if let Some(p)      = args.src_port          { builder.config.filter.src_port_filter    = Some(p); }
    if let Some(p)      = args.dst_port          { builder.config.filter.dst_port_filter    = Some(p); }
    if let Some(ref ip) = args.ip                { builder.config.filter.ip_filter          = Some(ip.clone()); }
    if let Some(ref ip) = args.src_ip            { builder.config.filter.src_ip_filter      = Some(ip.clone()); }
    if let Some(ref ip) = args.dst_ip            { builder.config.filter.dst_ip_filter      = Some(ip.clone()); }
    if let Some(ref s)  = args.subnet            { builder.config.filter.ip_subnet_filter   = Some(s.clone()); }
    if let Some(v)      = args.exclude_loopback  { builder.config.filter.exclude_loopback   = v; }
    if let Some(v)      = args.exclude_multicast { builder.config.filter.exclude_multicast  = v; }
    if let Some(ref d)  = args.domain_filter     { builder.config.domain_filter             = Some(d.clone()); }

    // ---------------- OUTPUT OVERRIDES ----------------
    if let Some(v)      = args.verbosity              { builder.config.output.verbosity              = v; }
    if let Some(ref f)  = args.output_format          { builder.config.output.output_format          = f.clone(); }
    if let Some(ref f)  = args.log_file               { builder.config.output.log_file               = Some(f.clone()); }
    if let Some(ref f)  = args.ndjson_output          { builder.config.output.ndjson_output_path     = Some(f.clone()); }
    if let Some(v)      = args.suppress_flow_updates  { builder.config.output.suppress_flow_updates  = v; }
    if let Some(v)      = args.suppress_parse_errors  { builder.config.output.suppress_parse_errors  = v; }

    // ---------------- PERFORMANCE OVERRIDES ----------------
    if let Some(t) = args.threads {
        // Explicit --threads disables hardware probe auto-scaling for worker count.
        builder.config.performance.worker_threads = t;
        builder.threads_explicit = true;
    }
    if let Some(b) = args.packet_batch {
        builder.config.performance.packet_batch_size = b;
    }
    if let Some(m) = args.max_memory_mb {
        // Cap memory usage. Hardware probe respects this when sizing ring buffers.
        builder.config.performance.max_memory_mb = m;
    }
    if args.no_auto_scale {
        // Disable all hardware probe auto-tuning. SNF uses conservative defaults.
        // Useful on shared servers where resource hoarding is unacceptable.
        builder.threads_explicit = true;
        builder.no_auto_scale    = true;
    }

    // ---------------- DEBUG OVERRIDES ----------------
    if args.debug_packets { builder.config.debug.debug_packets    = true; }
    if args.dump_raw      { builder.config.debug.dump_raw_packets  = true; }

    builder
}

// ----------------------------------------------------------------
// NEXT ARG HELPER
// ----------------------------------------------------------------

fn next_arg(args: &[String], i: &mut usize) -> Option<String> {
    if *i + 1 < args.len() {
        *i += 1;
        Some(args[*i].clone())
    } else {
        eprintln!("[SNF] Missing value for argument '{}'", args[*i]);
        None
    }
}

// ----------------------------------------------------------------
// HELP TEXT
// ----------------------------------------------------------------

pub fn print_help() {
    println!(
        r#"
SNF — Shadow Network Fingerprinting Engine
==========================================
Passive network intelligence: traffic fingerprinting, device discovery,
protocol analysis, threat scoring, and behavioral anomaly detection.
Designed for air-gapped, ICS/SCADA, DFIR, and regulated enterprise environments.

SNF v0.1 — Author: Tejas Padigel

USAGE
-----
  snf [MODE] [OPTIONS]
  snf --pcap-file capture.pcap --mode forensic -o results.ndjson
  snf --mode monitor --interface 2 --output events.ndjson
  snf --mode stealth --interface 1 --output /var/log/snf/events.ndjson
  snf --domain github.com --verbosity 3
  snf --dry-run --forensic --pcap-file evidence.pcap -o out.ndjson
  snf --determinism-check --pcap-file evidence.pcap

OPERATION MODES
---------------
  --forensic          Full depth — all analyzers, all events, max verbosity.
                      Intended for DFIR and post-incident analysis.

  --monitor           Lightweight 24/7 SOC mode — flow-level visibility,
                      suppressed noisy events. Good for continuous deployment.

  --stealth           Minimal footprint — no console output, passive only.
                      Intended for covert sensor deployments.

  --replay            Deterministic PCAP replay — identical output every run.
                      Requires --pcap-file. Single-threaded.

  --mode <name>       Explicit mode flag. Same as above flags.
                      Values: forensic | monitor | stealth | replay

  --light             Alias for --monitor  (legacy)
  --advanced          Alias for --forensic (legacy)
  --minimal           Alias for --stealth  (legacy)

CAPTURE OPTIONS
---------------
  --interface <id>          Network interface index (default: 0)
  --iface <name>            Network interface name (e.g. eth0, en0)
  --pcap-file <path>        Read packets from PCAP file (sets mode to pcap)
  --pcap-output <path>      Also write captured packets to PCAP file
  --packet-limit <n>        Stop after N packets (0 = unlimited)
  --timeout <sec>           Stop after N seconds (0 = unlimited)
  --snaplen <bytes>         Max bytes captured per packet (default: 65535)
  --buffer-size <bytes>     Kernel capture buffer size (default: 4MB)
  --promiscuous             Enable promiscuous mode (default: on)
  --no-promiscuous          Disable promiscuous mode
  --direction <dir>         Capture direction: in | out | both (default: both)
  --capture-mode <mode>     realtime | snapshot | pcap

FLOW OPTIONS
------------
  --flow-timeout <sec>      Flow idle timeout (default: 120s)
  --tcp-timeout <sec>       TCP stream idle timeout (default: 300s)
  --udp-timeout <sec>       UDP flow idle timeout (default: 30s)
  --max-flows <n>           Max simultaneous flows (default: 100000)
  --min-flow-packets <n>    Min packets before a flow is reported (default: 1)

PROTOCOL OPTIONS
----------------
  --enable-dns / --disable-dns      DNS analysis (default: on)
  --enable-tls / --disable-tls      TLS analysis (default: on)
  --enable-quic / --disable-quic    QUIC analysis (default: on)
  --enable-icmp / --disable-icmp    ICMP analysis (default: on)
  --enable-http / --disable-http    HTTP analysis (default: on)
  --enable-dhcp / --disable-dhcp    DHCP analysis (default: on)
  --enable-smb / --disable-smb      SMB analysis (default: on)
  --enable-mdns / --disable-mdns    mDNS analysis (default: on)

FILTER OPTIONS
--------------
  --bpf "<expr>"            Berkeley Packet Filter (kernel-level, most efficient)
  --port <n>                Filter to port N (src or dst)
  --src-port <n>            Filter to source port N
  --dst-port <n>            Filter to destination port N
  --ip <addr>               Filter to IP address (src or dst)
  --src-ip <addr>           Filter to source IP
  --dst-ip <addr>           Filter to destination IP
  --subnet <cidr>           Filter to subnet (e.g. 192.168.1.0/24)
  --domain <name>           Only show flows matching this domain name
  --exclude-loopback        Drop loopback traffic (default: on)
  --include-loopback        Include loopback traffic
  --exclude-multicast       Drop multicast traffic

OUTPUT OPTIONS
--------------
  --output <path> / -o      Write NDJSON event stream to file
  --log-file <path>         Write text/JSON log to file
  --output-format <fmt>     text | json | ndjson (default: ndjson)
  --verbosity <0-3>         0=silent 1=events 2=protocols 3=full debug
  --silent                  Alias for --verbosity 0
  --quiet                   Alias for --verbosity 1
  --suppress-flow-updates   Don't emit flow.update events (reduces volume)
  --suppress-parse-errors   Don't emit engine.parse_error events

PERFORMANCE OPTIONS
-------------------
  --threads <n>             Worker threads (default: auto-scaled to CPU count).
                            Overrides hardware probe. Replay mode always uses 1.
  --packet-batch <n>        Packets processed per worker per loop (default: auto).
  --max-memory <MB>         Cap total memory usage in megabytes (default: unlimited).
                            Ring buffer and flow table are scaled to stay within this.
  --no-auto-scale           Disable hardware probe auto-tuning entirely.
                            SNF uses conservative defaults instead of probing hardware.
                            Use this on shared servers to prevent resource hoarding.

  Resource control examples:
    snf --threads 2                          # pin to 2 workers
    snf --max-memory 512                     # cap at 512MB
    snf --no-auto-scale                      # minimal footprint, safe defaults
    snf --threads 4 --packet-batch 64        # manual full control

DEBUG OPTIONS
-------------
  --debug-packets           Print full per-packet debug output
  --dump-raw                Dump raw packet bytes (hex) to console

DRY-RUN (Phase 13D)
-------------------
  --dry-run                 Validate configuration and all file paths, print a
                            full summary of what SNF would do, then exit.
                            Does NOT start capture.
                            Exit 0 if config is valid. Exit 1 if errors found.

                            Example:
                              snf --dry-run --forensic --pcap-file evidence.pcap \
                                -o /mnt/output/events.ndjson

DETERMINISM CHECK (Phase 13B)
-----------------------------
  --determinism-check       Run the PCAP through SNF twice and compare SHA-256
                            hashes of both outputs. PASS = byte-identical.
                            FAIL = determinism contract violated.
                            Requires --pcap-file. Forces --replay mode.
                            Exit 0 on PASS, exit 1 on FAIL, exit 2 on error.

  --determinism-output <base>
                            Base path for intermediate files (default: snf_determinism).
                            Produces <base>_pass1.ndjson and <base>_pass2.ndjson.

  --keep-determinism-files  Keep pass1/pass2 NDJSON files after check.
                            Default: files are deleted on PASS, kept on FAIL.

                            Example:
                              snf --determinism-check --pcap-file evidence.pcap \
                                --determinism-output /tmp/snf_det

OTHER
-----
  --config <path>           Load config from TOML file (not yet implemented)
  --version / -v            Show SNF version
  --help / -h               Show this help

CLASH DETECTION
---------------
SNF validates your configuration at startup and will refuse to run if
conflicting settings are detected. Examples:

  ERROR: --port 443 but --disable-tls and --disable-quic
  ERROR: --domain github.com but --disable-dns
  ERROR: --mode replay but --threads 4
  WARN:  --mode stealth but --verbosity 3

EXAMPLES
--------
  snf --forensic --pcap-file sample.pcap -o findings.ndjson
  snf --monitor --interface 2 -o /var/log/snf/live.ndjson
  snf --stealth --interface 1 -o /tmp/.snf.ndjson
  snf --replay --pcap-file evidence.pcap -o replay_out.ndjson
  snf --domain google.com --verbosity 3
  snf --bpf "tcp port 443" --forensic --interface 0
  snf --disable-dns --disable-http --enable-smb --mode forensic
  snf --limit 1000 --interface 3
  snf --threads 2 --max-memory 512 --monitor --interface eth0
  snf --no-auto-scale --forensic --pcap-file evidence.pcap -o out.ndjson
  snf --dry-run --forensic --pcap-file evidence.pcap -o out.ndjson
  snf --determinism-check --pcap-file evidence.pcap
"#
    );
}

pub fn print_version() {
    println!("SNF — Shadow Network Fingerprinting Engine");
    println!("Version : 0.1.0");
    println!("Author  : Tejas Padigel");
    println!("Target  : Air-gapped defense / ICS / DFIR / Regulated enterprise");
}