// src/capture/mod.rs
//
// SNF-Core — Packet capture engine.
// Supports PCAP file replay and live interface capture.
// Multi-threaded via WorkerPool with flow-affinity routing.
// Single clean NDJSON output per session (worker shards merged at shutdown).

pub mod interface;

use crate::config::engine_config::EngineConfig;
use crate::config::capture_mode::CaptureMode;
use crate::config::mode::OperationMode;
use crate::discovery::dns_cache::DnsCache;
use crate::flow::flow_table::FlowTable;
use crate::core::packet_context_builder::PacketContextBuilder;
use crate::core::analyzer_manager::AnalyzerManager;
use crate::core::event_bus::EventBus;
use crate::core::event::{SnfEvent, EventType};
use crate::core::session_header::SessionHeader;
use crate::core::config_hasher::hash_config;
use crate::pipeline::packet_pipeline::PacketPipeline;
use crate::reporting::SessionReporter;
use crate::threading::{WorkerPool, RawPacket, compute_worker_for_packet};
use crate::capture::interface::auto_detect_interface;

use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pcap::{Capture, Device};
use sha2::{Sha256, Digest};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

macro_rules! snf_log {
    ($config:expr, $($arg:tt)*) => {
        if !$config.is_stealth() { println!($($arg)*) }
    };
}

// ── Worker shard merge ────────────────────────────────────────────────────────

fn merge_worker_shards(output_path: &str, num_workers: usize) {
    if num_workers <= 1 { return; }
    let shard_paths: Vec<String> = (0..num_workers)
        .map(|i| format!("{}.worker_{}", output_path, i))
        .collect();
    let mut out = match std::fs::File::create(output_path) {
        Ok(f) => f,
        Err(e) => { eprintln!("[SNF] merge failed: {}", e); return; }
    };
    use std::io::{BufRead, BufReader, Write};
    for (idx, shard_path) in shard_paths.iter().enumerate() {
        let file = match std::fs::File::open(shard_path) { Ok(f) => f, Err(_) => continue };
        for (line_num, line) in BufReader::new(file).lines().enumerate() {
            let line = match line { Ok(l) => l, Err(_) => continue };
            let t = line.trim();
            if t.is_empty() { continue; }
            if idx > 0 && line_num == 0 && t.contains("snf_session_header") { continue; }
            let _ = writeln!(out, "{}", t);
        }
    }
    for p in &shard_paths { let _ = std::fs::remove_file(p); }
    eprintln!("[SNF] Merged {} shards -> '{}'", num_workers, output_path);
}

fn default_output_path(config: &EngineConfig) -> String {
    if let Some(ref p) = config.output.ndjson_output_path { return p.clone(); }
    // SNF_RUN_DIR is set once in run_capture() — use it for a consistent
    // timestamped path across all calls in the same session.
    if let Ok(run_dir) = std::env::var("SNF_RUN_DIR") {
        let ts = std::env::var("SNF_RUN_TS").unwrap_or_else(|_| "session".to_string());
        return format!("{}/snf_output_{}.ndjson", run_dir.trim_end_matches('/'), ts);
    }
    if let Ok(dir) = std::env::var("SNF_OUTPUT_DIR") {
        return format!("{}/snf_output.ndjson", dir.trim_end_matches('/'));
    }
    "output/snf_output.ndjson".to_string()
}

fn hash_pcap_file(path: &str) -> String {
    use std::fs::File; use std::io::Read;
    let mut file = match File::open(path) { Ok(f) => f, Err(_) => return String::new() };
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        match file.read(&mut buf) {
            Ok(0) => break, Ok(n) => hasher.update(&buf[..n]), Err(_) => return String::new(),
        }
    }
    format!("{:x}", hasher.finalize())
}

// ── Public entry point ────────────────────────────────────────────────────────

pub fn run_capture(ports_db: &HashMap<u16, String>, config: &EngineConfig) {
    // ── Timestamped run directory ─────────────────────────────────────────────
    // Generate run_<timestamp> subfolder ONCE before any threads spawn.
    // All calls to default_output_path() read SNF_RUN_DIR for consistency.
    {
        use chrono::Local;
        let ts      = Local::now().format("%Y-%m-%d_%H-%M-%S").to_string();
        let base    = std::env::var("SNF_OUTPUT_DIR").unwrap_or_else(|_| "output".to_string());
        let run_dir = format!("{}/run_{}", base.trim_end_matches('/'), ts);
        let _       = std::fs::create_dir_all(&run_dir);
        // SAFETY: called before any threads are spawned.
        unsafe {
            std::env::set_var("SNF_RUN_DIR", &run_dir);
            std::env::set_var("SNF_RUN_TS",  &ts);
        }
    }

    if config.is_replay() && config.performance.worker_threads != 1 {
        eprintln!("[SNF] Fatal: Replay mode requires worker_threads=1 for determinism.");
        std::process::exit(1);
    }
    let capture_mode = CaptureMode::from_str(&config.capture.capture_mode)
        .unwrap_or(CaptureMode::Realtime);
    match capture_mode {
        CaptureMode::Pcap | CaptureMode::Replay => {
            if let Some(ref path) = config.capture.pcap_file {
                run_pcap_file(path.clone(), capture_mode, ports_db, config);
            } else {
                eprintln!("[SNF] Fatal: --pcap-file required for pcap/replay mode");
            }
        }
        CaptureMode::Realtime | CaptureMode::Snapshot => {
            run_live_capture(capture_mode, ports_db, config);
        }
    }
}

// ── PCAP replay ───────────────────────────────────────────────────────────────

fn run_pcap_file(
    pcap_path:    String,
    capture_mode: CaptureMode,
    ports_db:     &HashMap<u16, String>,
    config:       &EngineConfig,
) {
    snf_log!(config, "[SNF] {} - {}", config.operation_mode.as_str().to_uppercase(), pcap_path);
    let pcap_sha256 = hash_pcap_file(&pcap_path);
    snf_log!(config, "[SNF] PCAP SHA-256: {}",
        if pcap_sha256.is_empty() { "FAILED".to_string() } else { pcap_sha256.clone() });

    let mut cap = match Capture::from_file(&pcap_path) {
        Ok(c) => c,
        Err(e) => { eprintln!("[SNF] Fatal: {:?}", e); return; }
    };

    let output_path = default_output_path(config);
    let num_workers = config.performance.worker_threads;
    let use_threading = num_workers > 1 && !config.is_replay() && !config.is_stealth();

    if use_threading {
        let header = SessionHeader::new(0, config.operation_mode.as_str(),
            &hash_config(config), &pcap_path);
        let (pool, tx) = WorkerPool::new(num_workers, Arc::new(config.clone()),
            Arc::new(ports_db.clone()), output_path.clone(), header.to_json_line());
        let mut seq: u64 = 0; let mut drops: u64 = 0;
        loop {
            match cap.next_packet() {
                Ok(p) => {
                    if config.capture.packet_limit > 0 && seq >= config.capture.packet_limit as u64 { break; }
                    let ts = (p.header.ts.tv_sec as u64).saturating_mul(1_000_000)
                        .saturating_add(p.header.ts.tv_usec as u64);
                    seq += 1;
                    let wi = compute_worker_for_packet(p.data, seq, num_workers);
                    let raw = RawPacket { data: p.data.to_vec(), timestamp_us: ts,
                        wire_len: p.header.len, packet_seq: seq, shard_index: wi };
                    if !tx[wi].push(raw) { drops += 1; }
                }
                Err(pcap::Error::NoMorePackets) => { snf_log!(config, "[SNF] PCAP complete."); break; }
                Err(e) => { eprintln!("[SNF] Error: {:?}", e); break; }
            }
        }
        if drops > 0 { snf_log!(config, "[SNF] Queue drops: {}", drops); }
        drop(tx);
        let stats = pool.shutdown();
        merge_worker_shards(&output_path, num_workers);
        snf_log!(config, "[SNF] {}", stats.summary_line());
    } else {
        let mut engine = CaptureEngine::new(config, &output_path, &pcap_path, capture_mode, pcap_sha256);
        snf_log!(config, "[SNF] Replaying PCAP...");
        loop {
            match cap.next_packet() {
                Ok(p) => {
                    if config.capture.packet_limit > 0
                        && engine.packet_count >= config.capture.packet_limit as u64 { break; }
                    engine.process_raw_packet(&p, ports_db, config);
                }
                Err(pcap::Error::NoMorePackets) => { snf_log!(config, "[SNF] PCAP complete."); break; }
                Err(e) => { eprintln!("[SNF] Error: {:?}", e); engine.record_capture_error(&format!("{:?}", e)); break; }
            }
        }
        engine.shutdown(config, &output_path);
    }
}

// ── Live capture ──────────────────────────────────────────────────────────────

fn run_live_capture(
    capture_mode: CaptureMode,
    ports_db:     &HashMap<u16, String>,
    config:       &EngineConfig,
) {
    let devices = match Device::list() {
        Ok(d) => d,
        Err(e) => { eprintln!("[SNF] Fatal: {:?}", e); return; }
    };

    let device = if config.capture.interface_index == 0 {
        match auto_detect_interface(&devices) {
            Some(d) => d,
            None => { eprintln!("[SNF] No interface found"); return; }
        }
    } else {
        match devices.get(config.capture.interface_index) {
            Some(d) => d.clone(),
            None => { eprintln!("[SNF] Interface index out of range"); return; }
        }
    };

    snf_log!(config, "[SNF] Interface: {}", device.name);

    let mut cap = match Capture::from_device(device.name.as_str())
        .and_then(|b| b.promisc(config.capture.promiscuous_mode)
            .snaplen(config.capture.snaplen).timeout(500).open())
    {
        Ok(c) => c,
        Err(e) => { eprintln!("[SNF] Fatal: {:?}", e); return; }
    };

    let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let r = running.clone();
    let _ = ctrlc::set_handler(move || { r.store(false, std::sync::atomic::Ordering::SeqCst); });

    let output_path = default_output_path(config);
    let num_workers = config.performance.worker_threads;
    let use_threading = num_workers > 1 && !config.is_replay() && !config.is_stealth();

    if use_threading {
        let header = SessionHeader::new(0, config.operation_mode.as_str(),
            &hash_config(config), &device.name);
        let (pool, tx) = WorkerPool::new(num_workers, Arc::new(config.clone()),
            Arc::new(ports_db.clone()), output_path.clone(), header.to_json_line());
        let mut seq: u64 = 0; let mut drops: u64 = 0;
        loop {
            if !running.load(std::sync::atomic::Ordering::SeqCst) { eprintln!("[SNF] Interrupted."); break; }
            match cap.next_packet() {
                Ok(p) => {
                    let ts = (p.header.ts.tv_sec as u64).saturating_mul(1_000_000)
                        .saturating_add(p.header.ts.tv_usec as u64);
                    seq += 1;
                    let wi = compute_worker_for_packet(p.data, seq, num_workers);
                    let raw = RawPacket { data: p.data.to_vec(), timestamp_us: ts,
                        wire_len: p.header.len, packet_seq: seq, shard_index: wi };
                    if !tx[wi].push(raw) { drops += 1; }
                }
                Err(pcap::Error::NoMorePackets) => break,
                Err(_) => {}
            }
        }
        if drops > 0 { snf_log!(config, "[SNF] Drops: {}", drops); }
        drop(tx);
        let stats = pool.shutdown();
        merge_worker_shards(&output_path, num_workers);
        snf_log!(config, "[SNF] {}", stats.summary_line());
        return;
    }

    let mut engine = CaptureEngine::new(config, &output_path,
        &device.name, capture_mode, "live".to_string());
    snf_log!(config, "Listening for packets...");
    loop {
        if !running.load(std::sync::atomic::Ordering::SeqCst) { eprintln!("[SNF] Interrupted."); break; }
        if config.capture.packet_limit > 0
            && engine.packet_count >= config.capture.packet_limit as u64 { break; }
        match cap.next_packet() {
            Ok(p) => engine.process_raw_packet(&p, ports_db, config),
            Err(pcap::Error::NoMorePackets) => break,
            Err(e) => { engine.record_capture_error(&format!("{:?}", e)); }
        }
    }
    engine.shutdown(config, &output_path);
}

// ── Capture Engine ────────────────────────────────────────────────────────────

struct CaptureEngine {
    flow_table:        FlowTable,
    dns_cache:         DnsCache,
    analyzer_manager:  AnalyzerManager,
    pipeline:          PacketPipeline,
    discovered_macs:   HashSet<String>,
    event_bus:         Option<EventBus>,
    config_hash:       String,
    capture_source:    String,
    #[allow(dead_code)]
    capture_mode:      CaptureMode,
    #[allow(dead_code)]
    pcap_sha256:       String,
    pub packet_count:  u64,
    last_timestamp_us: u64,
    header_written:    bool,
    session_reporter:  SessionReporter,
}

impl CaptureEngine {
    fn new(
        config:         &EngineConfig,
        output_path:    &str,
        capture_source: &str,
        capture_mode:   CaptureMode,
        pcap_sha256:    String,
    ) -> Self {
        let _ = std::fs::create_dir_all(
            std::path::Path::new(output_path).parent()
                .unwrap_or(std::path::Path::new("."))
        );
        Self {
            flow_table:        FlowTable::with_capacity(config.flow.max_flows),
            dns_cache:         DnsCache::with_capacity(config.dns.dns_cache_size),
            analyzer_manager:  AnalyzerManager::new(config),
            pipeline:          PacketPipeline::new(),
            discovered_macs:   HashSet::new(),
            event_bus:         None,
            config_hash:       hash_config(config),
            capture_source:    capture_source.to_string(),
            capture_mode,
            pcap_sha256,
            packet_count:      0,
            last_timestamp_us: 0,
            header_written:    false,
            session_reporter:  SessionReporter::default_interval(),
        }
    }

    fn record_capture_error(&mut self, reason: &str) {
        if let Some(ref mut bus) = self.event_bus {
            let mut e = SnfEvent::new(0, self.packet_count, self.last_timestamp_us,
                EventType::CaptureError, "CAPTURE", "");
            e.attr_str("reason", reason.to_string());
            bus.emit(e);
        }
    }

    fn process_raw_packet(
        &mut self,
        packet:   &pcap::Packet,
        ports_db: &HashMap<u16, String>,
        config:   &EngineConfig,
    ) {
        self.packet_count += 1;
        let timestamp_us = (packet.header.ts.tv_sec as u64)
            .saturating_mul(1_000_000)
            .saturating_add(packet.header.ts.tv_usec as u64);
        self.last_timestamp_us = timestamp_us;

        if !self.header_written {
            let output_path = default_output_path(config);
            let header = SessionHeader::new(timestamp_us, config.operation_mode.as_str(),
                &self.config_hash, &self.capture_source);
            self.event_bus = Some(EventBus::new(&output_path, &header.to_json_line()));
            self.header_written = true;
        }

        match SlicedPacket::from_ethernet(&packet.data) {
            Ok(sliced) => self.process_sliced(sliced, packet, timestamp_us, ports_db, config),
            Err(e) => {
                if let Some(ref mut bus) = self.event_bus {
                    if !config.output.suppress_parse_errors {
                        let mut ev = SnfEvent::new(0, self.packet_count, timestamp_us,
                            EventType::ParseError, "FRAME", "");
                        ev.attr_str("reason", format!("{:?}", e));
                        bus.emit(ev);
                    }
                }
            }
        }
    }

    fn process_sliced(
        &mut self,
        sliced:       SlicedPacket,
        packet:       &pcap::Packet,
        timestamp_us: u64,
        ports_db:     &HashMap<u16, String>,
        config:       &EngineConfig,
    ) {
        // MAC discovery
        if let Some(ref link) = sliced.link {
            if let etherparse::LinkSlice::Ethernet2(eth) = link {
                let mac = eth.source();
                let mac_str = format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                if !self.discovered_macs.contains(&mac_str) {
                    self.discovered_macs.insert(mac_str.clone());
                    if let Some(ref mut bus) = self.event_bus {
                        let mut ev = SnfEvent::new(0, self.packet_count, timestamp_us,
                            EventType::DeviceDiscovered, "ARP", "");
                        ev.attr_str("mac", mac_str);
                        bus.emit(ev);
                    }
                }
            }
        }

        if let Some(net) = sliced.net {
            let (src_ip_addr, dst_ip_addr) = match &net {
                NetSlice::Ipv4(h) => (
                    IpAddr::V4(h.header().source_addr()),
                    IpAddr::V4(h.header().destination_addr()),
                ),
                NetSlice::Ipv6(h) => (
                    IpAddr::V6(h.header().source_addr()),
                    IpAddr::V6(h.header().destination_addr()),
                ),
            };
            let src_ip = src_ip_addr.to_string();
            let dst_ip = dst_ip_addr.to_string();

            self.session_reporter.observe_packet(timestamp_us, src_ip_addr,
                packet.header.len as u64, false);
            self.session_reporter.maybe_report(timestamp_us, config);

            if let Some(transport) = sliced.transport {
                match transport {
                    TransportSlice::Tcp(tcp) => {
                        let src_port = tcp.source_port();
                        let dst_port = tcp.destination_port();
                        let payload  = tcp.payload();
                        let tcp_seq  = Some(tcp.sequence_number());
                        let mut ctx  = PacketContextBuilder::build(
                            src_ip, dst_ip, src_port, dst_port,
                            "TCP".to_string(), packet.header.len as usize, timestamp_us,
                        );
                        self.pipeline.process_packet(
                            &mut ctx, payload, tcp_seq, config,
                            &mut self.flow_table, &mut self.dns_cache,
                            ports_db, &mut self.analyzer_manager, &mut self.event_bus,
                        );
                        if let Some(ref bus) = self.event_bus {
                            if bus.event_count() > 0 {
                                self.session_reporter.observe_event(ctx.protocol.as_str());
                            }
                        }
                    }
                    TransportSlice::Udp(udp) => {
                        let src_port = udp.source_port();
                        let dst_port = udp.destination_port();
                        let payload  = udp.payload();
                        let mut ctx  = PacketContextBuilder::build(
                            src_ip, dst_ip, src_port, dst_port,
                            "UDP".to_string(), packet.header.len as usize, timestamp_us,
                        );
                        self.pipeline.process_packet(
                            &mut ctx, payload, None, config,
                            &mut self.flow_table, &mut self.dns_cache,
                            ports_db, &mut self.analyzer_manager, &mut self.event_bus,
                        );
                        if let Some(ref bus) = self.event_bus {
                            if bus.event_count() > 0 {
                                self.session_reporter.observe_event(ctx.protocol.as_str());
                            }
                        }
                    }
                    TransportSlice::Icmpv4(icmp) => {
                        if config.protocol.enable_icmp {
                            let mut ctx = PacketContextBuilder::build(
                                src_ip, dst_ip, 0, 0,
                                "ICMP".to_string(), packet.header.len as usize, timestamp_us,
                            );
                            ctx.icmp_type = Some(icmp.type_u8());
                            ctx.icmp_code = Some(icmp.code_u8());
                            self.pipeline.process_packet(
                                &mut ctx, icmp.payload(), None, config,
                                &mut self.flow_table, &mut self.dns_cache,
                                ports_db, &mut self.analyzer_manager, &mut self.event_bus,
                            );
                        }
                    }
                    TransportSlice::Icmpv6(_icmp) => {
                        if config.protocol.enable_icmp {
                            let mut ctx = PacketContextBuilder::build(
                                src_ip, dst_ip, 0, 0,
                                "ICMPv6".to_string(), packet.header.len as usize, timestamp_us,
                            );
                            self.pipeline.process_packet(
                                &mut ctx, &[], None, config,
                                &mut self.flow_table, &mut self.dns_cache,
                                ports_db, &mut self.analyzer_manager, &mut self.event_bus,
                            );
                        }
                    }

                }
            }
        }
    }

    fn shutdown(mut self, config: &EngineConfig, output_path: &str) {
        if let Some(ref mut bus) = self.event_bus { bus.flush(); }
        match config.operation_mode {
            OperationMode::Stealth => {}
            OperationMode::Replay => {
                println!("[SNF] Replay complete - {} packets processed", self.packet_count);
            }
            _ => {
                println!("[SNF] Session complete - {} packets -> {}", self.packet_count, output_path);
                // Print the end-of-run summary box (non-stealth, non-replay only).
                self.session_reporter.print_final_summary(
                    self.last_timestamp_us,
                    config.operation_mode.as_str(),
                    output_path,
                );
            }
        }
    }
}

fn is_rfc1918_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 10
                || (o[0] == 172 && o[1] >= 16 && o[1] <= 31)
                || (o[0] == 192 && o[1] == 168)
                || o[0] == 127
                || (o[0] == 169 && o[1] == 254)
        }
        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00 == 0xfc00),
    }
}

pub fn is_rfc1918_ip_pub(ip: IpAddr) -> bool {
    is_rfc1918_ip(ip)
}
