// src/threading/worker_pool.rs
//
// WorkerPool — parallel packet processing worker thread pool.
// Phase 11C: Flow-affinity routing (hash by 5-tuple).
// Phase 11D: Batch processing (drain up to BATCH_SIZE packets per wakeup).
// Phase 11E: Drop event emission.
// Phase 17:  Worker shard files merged at session end by capture/mod.rs.

use std::sync::Arc;
use std::thread;
use std::collections::HashMap;

use crate::config::engine_config::EngineConfig;
use crate::threading::packet_queue::{PacketQueue, PacketQueueTx, PacketQueueRx, RawPacket, DEFAULT_QUEUE_DEPTH};
use crate::threading::thread_stats::{ThreadStats, AggregateStats};
use crate::core::packet_context_builder::PacketContextBuilder;
use crate::core::event_bus::EventBus;
use crate::core::event::{SnfEvent, EventType};
use crate::flow::flow_table::FlowTable;
use crate::discovery::dns_cache::DnsCache;
use crate::core::analyzer_manager::AnalyzerManager;
use crate::pipeline::packet_pipeline::PacketPipeline;

use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use std::net::IpAddr;

// ── Constants ─────────────────────────────────────────────────────────────────

pub const DEFAULT_BATCH_SIZE: usize = 64;
const WORKER_BLOCK_TIMEOUT_MS: u64  = 1;
#[allow(dead_code)]
const DROP_EMIT_THRESHOLD: u64      = 100;
const DROP_FLUSH_INTERVAL_PACKETS: u64 = 10_000;

// ── WorkerHandle ──────────────────────────────────────────────────────────────

#[allow(dead_code)]
struct WorkerHandle {
    thread:        Option<thread::JoinHandle<ThreadStats>>,
    tx:            Option<PacketQueueTx>,
    worker_index:  usize,
    restart_count: u32,
}

// ── WorkerPool ────────────────────────────────────────────────────────────────

#[allow(dead_code)]
pub struct WorkerPool {
    workers:             Vec<WorkerHandle>,
    config:              Arc<EngineConfig>,
    ports_db:            Arc<HashMap<u16, String>>,
    output_path:         String,
    session_header_json: String,
}

impl WorkerPool {
    pub fn new(
        num_workers:         usize,
        config:              Arc<EngineConfig>,
        ports_db:            Arc<HashMap<u16, String>>,
        output_path:         String,
        session_header_json: String,
    ) -> (Self, Vec<PacketQueueTx>) {
        assert!(num_workers >= 1, "WorkerPool requires at least 1 worker");

        if config.is_replay() {
            eprintln!("[SNF] FATAL: WorkerPool::new() called in Replay mode. Aborting.");
            std::process::exit(1);
        }

        let queue_depth = config.performance.event_queue_size.max(DEFAULT_QUEUE_DEPTH);
        let batch_size  = config.performance.packet_batch_size.clamp(1, 256);

        let mut pool = Self {
            workers:             Vec::with_capacity(num_workers),
            config:              Arc::clone(&config),
            ports_db:            Arc::clone(&ports_db),
            output_path:         output_path.clone(),
            session_header_json: session_header_json.clone(),
        };

        let mut tx_handles = Vec::with_capacity(num_workers);

        for idx in 0..num_workers {
            let (tx, rx) = PacketQueue::with_capacity(queue_depth);
            let tx_clone = tx.clone();

            let worker_config = Arc::clone(&config);
            let worker_ports  = Arc::clone(&ports_db);
            let worker_out = if num_workers > 1 {
                format!("{}.worker_{}", output_path, idx)
            } else {
                output_path.clone()
            };
            let worker_header = session_header_json.clone();

            let handle = Self::spawn_worker(
                idx, rx, worker_config, worker_ports, worker_out, worker_header, batch_size,
            );

            pool.workers.push(WorkerHandle {
                thread:        Some(handle),
                tx:            Some(tx_clone),
                worker_index:  idx,
                restart_count: 0,
            });
            tx_handles.push(tx);
        }

        (pool, tx_handles)
    }

    fn spawn_worker(
        worker_index: usize,
        rx:           PacketQueueRx,
        config:       Arc<EngineConfig>,
        ports_db:     Arc<HashMap<u16, String>>,
        output_path:  String,
        header_json:  String,
        batch_size:   usize,
    ) -> thread::JoinHandle<ThreadStats> {
        thread::Builder::new()
            .name(format!("snf-worker-{}", worker_index))
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run_worker(worker_index, rx, &config, &ports_db, &output_path, &header_json, batch_size)
                }));
                match result {
                    Ok(stats) => stats,
                    Err(_) => {
                        eprintln!("[SNF] Worker {} panicked.", worker_index);
                        let mut stats = ThreadStats::new(worker_index);
                        stats.mark_finished();
                        stats
                    }
                }
            })
            .unwrap_or_else(|e| {
                eprintln!("[SNF] FATAL: Failed to spawn worker {}: {}", worker_index, e);
                std::process::exit(1)
            })
    }

    pub fn shutdown(mut self) -> AggregateStats {
        // Drop all internal Tx clones BEFORE joining — signals workers to stop.
        for handle in &mut self.workers {
            drop(handle.tx.take());
        }
        let mut all_stats: Vec<ThreadStats> = Vec::with_capacity(self.workers.len());
        for handle in &mut self.workers {
            if let Some(join_handle) = handle.thread.take() {
                match join_handle.join() {
                    Ok(stats) => all_stats.push(stats),
                    Err(_) => {
                        eprintln!("[SNF] Worker {} join failed.", handle.worker_index);
                        let mut stats = ThreadStats::new(handle.worker_index);
                        stats.mark_finished();
                        all_stats.push(stats);
                    }
                }
            }
        }
        AggregateStats::from_workers(&all_stats)
    }

    pub fn worker_count(&self) -> usize { self.workers.len() }
}

// ── Drop Accumulator ──────────────────────────────────────────────────────────

struct DropAccumulator {
    pending:           HashMap<&'static str, u64>,
    last_flush_packet: u64,
}

impl DropAccumulator {
    fn new() -> Self { Self { pending: HashMap::new(), last_flush_packet: 0 } }

    #[inline]
    #[allow(dead_code)]
    fn record(&mut self, reason: &'static str) -> bool {
        let count = self.pending.entry(reason).or_insert(0);
        *count = count.saturating_add(1);
        *count >= DROP_EMIT_THRESHOLD
    }

    fn flush(&mut self, packet_seq: u64, timestamp_us: u64,
             event_bus: &mut Option<EventBus>, stats: &mut ThreadStats) {
        let bus = match event_bus { Some(b) => b, None => return };
        for (reason, count) in self.pending.drain() {
            if count == 0 { continue; }
            let mut ev = SnfEvent::new(0, packet_seq, timestamp_us,
                EventType::CaptureDropped, "CAPTURE", "");
            ev.attr_str("reason", reason.to_string());
            ev.attr_u64("drop_count", count);
            ev.attr_str("location", "worker".to_string());
            bus.emit(ev);
            stats.upstream_queue_drops = stats.upstream_queue_drops.saturating_add(count);
        }
        self.last_flush_packet = packet_seq;
    }

    #[inline]
    fn maybe_flush_periodic(&mut self, packet_seq: u64, timestamp_us: u64,
                            event_bus: &mut Option<EventBus>, stats: &mut ThreadStats) {
        if packet_seq.wrapping_sub(self.last_flush_packet) >= DROP_FLUSH_INTERVAL_PACKETS {
            self.flush(packet_seq, timestamp_us, event_bus, stats);
        }
    }
}

// ── Worker main loop ──────────────────────────────────────────────────────────

fn run_worker(
    worker_index: usize,
    rx:           PacketQueueRx,
    config:       &EngineConfig,
    ports_db:     &HashMap<u16, String>,
    output_path:  &str,
    header_json:  &str,
    batch_size:   usize,
) -> ThreadStats {
    let mut stats      = ThreadStats::new(worker_index);
    let mut drop_accum = DropAccumulator::new();
    stats.mark_started();

    // Per-worker independent state — zero sharing across workers.
    let mut flow_table       = FlowTable::with_capacity(config.flow.max_flows);
    let mut dns_cache        = DnsCache::with_capacity(config.dns.dns_cache_size);
    let mut analyzer_manager = AnalyzerManager::new(config);
    let mut pipeline         = PacketPipeline::new();

    // EventBus — written lazily on first packet so header timestamp is real.
    let mut event_bus: Option<EventBus> = None;
    let mut header_written = false;
    let mut last_timestamp_us: u64 = 0;

    let timeout = std::time::Duration::from_millis(WORKER_BLOCK_TIMEOUT_MS);

    loop {
        // Block for the first packet of this batch.
        let first = match rx.pop_timeout(timeout) {
            Some(p) => p,
            None => {
                if rx.is_shutdown() { break; }
                continue;
            }
        };

        // Process first packet then drain up to batch_size - 1 more.
        let mut batch = Vec::with_capacity(batch_size);
        batch.push(first);
        for _ in 1..batch_size {
            match rx.try_pop() {
                Some(p) => batch.push(p),
                None    => break,
            }
        }

        for raw in batch {
            let ts = raw.timestamp_us;
            last_timestamp_us = ts;
            stats.packets_processed = stats.packets_processed.saturating_add(1);

            // Initialise EventBus on first real packet.
            if !header_written {
                let _ = std::fs::create_dir_all(
                    std::path::Path::new(output_path).parent()
                        .unwrap_or(std::path::Path::new("."))
                );
                event_bus = Some(EventBus::new(output_path, header_json));
                header_written = true;
            }

            process_raw_packet(
                &raw, ts, config, ports_db,
                &mut flow_table, &mut dns_cache,
                &mut analyzer_manager, &mut pipeline,
                &mut event_bus, &mut stats,
            );

            drop_accum.maybe_flush_periodic(
                stats.packets_processed, ts, &mut event_bus, &mut stats,
            );
        }

        if rx.is_shutdown() { break; }
    }

    // Final flush.
    drop_accum.flush(stats.packets_processed, last_timestamp_us, &mut event_bus, &mut stats);
    stats.flows_created = flow_table.flow_count() as u64;
    stats.events_emitted = event_bus.as_ref().map(|b| b.event_count()).unwrap_or(0);
    if let Some(mut bus) = event_bus { bus.flush(); }

    stats.mark_finished();
    stats
}

// ── Per-packet processing ─────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn process_raw_packet(
    raw:              &RawPacket,
    timestamp_us:     u64,
    config:           &EngineConfig,
    ports_db:         &HashMap<u16, String>,
    flow_table:       &mut FlowTable,
    dns_cache:        &mut DnsCache,
    analyzer_manager: &mut AnalyzerManager,
    pipeline:         &mut PacketPipeline,
    event_bus:        &mut Option<EventBus>,
    stats:            &mut ThreadStats,
) {
    let sliced = match SlicedPacket::from_ethernet(&raw.data) {
        Ok(s)  => s,
        Err(e) => {
            if let Some(bus) = event_bus {
                let mut ev = SnfEvent::new(0, raw.packet_seq, timestamp_us,
                    EventType::ParseError, "FRAME", "");
                ev.attr_str("reason", format!("{:?}", e));
                bus.emit(ev);
            }
            stats.packets_parse_error = stats.packets_parse_error.saturating_add(1);
            return;
        }
    };

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
            NetSlice::Arp(_) => return, // ARP has no IP src/dst — skip
        };

        let src_ip = src_ip_addr.to_string();
        let dst_ip = dst_ip_addr.to_string();

        if let Some(transport) = sliced.transport {
            match transport {
                TransportSlice::Tcp(tcp) => {
                    let src_port = tcp.source_port();
                    let dst_port = tcp.destination_port();
                    let payload  = tcp.payload();
                    let tcp_seq  = Some(tcp.sequence_number());
                    let mut ctx  = PacketContextBuilder::build(
                        src_ip, dst_ip, src_port, dst_port,
                        "TCP".to_string(), raw.wire_len as usize, timestamp_us,
                    );
                    pipeline.process_packet(
                        &mut ctx, payload, tcp_seq, config,
                        flow_table, dns_cache, ports_db,
                        analyzer_manager, event_bus,
                    );
                }
                TransportSlice::Udp(udp) => {
                    let src_port = udp.source_port();
                    let dst_port = udp.destination_port();
                    let payload  = udp.payload();
                    let mut ctx  = PacketContextBuilder::build(
                        src_ip, dst_ip, src_port, dst_port,
                        "UDP".to_string(), raw.wire_len as usize, timestamp_us,
                    );
                    pipeline.process_packet(
                        &mut ctx, payload, None, config,
                        flow_table, dns_cache, ports_db,
                        analyzer_manager, event_bus,
                    );
                }
               TransportSlice::Icmpv4(icmp) => {
                    if config.protocol.enable_icmp {
                        let mut ctx = PacketContextBuilder::build(
                            src_ip, dst_ip, 0, 0,
                            "ICMP".to_string(), raw.wire_len as usize, timestamp_us,
                        );
                        ctx.icmp_type = Some(icmp.type_u8());
                        ctx.icmp_code = Some(icmp.code_u8());
                        pipeline.process_packet(
                            &mut ctx, icmp.payload(), None, config,
                            flow_table, dns_cache, ports_db,
                            analyzer_manager, event_bus,
                        );
                    }
                }
                TransportSlice::Icmpv6(_icmp) => {
                    if config.protocol.enable_icmp {
                        let mut ctx = PacketContextBuilder::build(
                            src_ip, dst_ip, 0, 0,
                            "ICMPv6".to_string(), raw.wire_len as usize, timestamp_us,
                        );
                        pipeline.process_packet(
                            &mut ctx, &[], None, config,
                            flow_table, dns_cache, ports_db,
                            analyzer_manager, event_bus,
                        );
                    }
                }
              
                }
        }
    }
}