// src/threading/watchdog.rs
//
// Worker watchdog and backpressure monitor — Phase 14F.
//
// ── The Problem at 25 Gbps ────────────────────────────────────────────────────
//
//   At 25 Gbps with 64-byte packets: 46.5 Mpps. A 10ms worker stall causes:
//     46.5M × 0.010s = 465,000 packets arriving while the worker is stuck.
//   The ring buffer holds ~8192 packets (16MB UMEM). After 8192 packets,
//   the NIC starts dropping silently at the hardware level.
//
//   Without a watchdog:
//     - The operator sees reduced event output but no indication of why
//     - The session report shows incorrect packet counts
//     - Forensic artifacts are incomplete without any warning
//
//   With a watchdog:
//     - Every stall emits a `capture.drop` event with reason="worker_stall"
//     - Every ring buffer overrun emits a `capture.drop` event with reason="ring_overrun"
//     - The operator can see exactly when, how long, and how many packets were lost
//     - Post-session report includes stall count and duration for SLA verification
//
// ── Design ───────────────────────────────────────────────────────────────────
//
//   The watchdog runs as a separate thread — lightweight, low-overhead.
//   It samples each worker's packet counter every watchdog_interval_ms.
//   If a worker's counter has not advanced in watchdog_timeout_ms, it emits
//   a WorkerStall event.
//
//   Backpressure monitoring:
//     - Reads NIC drop counters from /proc/net/dev or ethtool -S periodically
//     - When kernel drop count increases, emits CaptureOverrun event
//     - Tracks total session overrun count for the evidence report
//
//   The watchdog does NOT restart workers. Worker restarts (Phase 14F future)
//   require careful state management — the watchdog only observes and reports.
//
// ── Thread Safety ────────────────────────────────────────────────────────────
//
//   Worker packet counters are exposed via Arc<AtomicU64> per worker.
//   The watchdog reads these without locking — AtomicU64 with Relaxed
//   ordering is sufficient for monitoring (we don't need exact values,
//   just whether they are advancing).
//
//   EventBus access: the watchdog emits events via a dedicated EventBus
//   instance or via a channel to the capture thread's EventBus.
//   In Phase 14F: uses a crossbeam channel to the capture thread.
//
// Phase 14F addition.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};
use std::collections::HashMap;

use crate::core::event::{SnfEvent, EventType};

// ── CONSTANTS ─────────────────────────────────────────────────────────────────

/// How often the watchdog samples worker counters (milliseconds).
/// Low overhead: 1 thread doing N atomic reads every 100ms.
const WATCHDOG_SAMPLE_INTERVAL_MS: u64 = 100;

/// How often the watchdog checks NIC drop counters (milliseconds).
const OVERRUN_CHECK_INTERVAL_MS: u64 = 1_000;

// ── WorkerWatchHandle ─────────────────────────────────────────────────────────

/// A handle the watchdog uses to observe one worker thread.
#[derive(Clone)]
pub struct WorkerWatchHandle {
    /// Worker index for reporting.
    pub worker_index: usize,

    /// Packet counter — atomically updated by the worker on each packet.
    /// The watchdog reads this to detect stalls.
    pub packets_processed: Arc<AtomicU64>,
}

impl WorkerWatchHandle {
    pub fn new(worker_index: usize) -> (Self, Arc<AtomicU64>) {
        let counter = Arc::new(AtomicU64::new(0));
        let handle = Self {
            worker_index,
            packets_processed: Arc::clone(&counter),
        };
        (handle, counter)
    }
}

// ── WatchdogConfig ────────────────────────────────────────────────────────────

/// Configuration for the watchdog thread.
#[derive(Debug, Clone)]
pub struct WatchdogConfig {
    /// How long a worker must be stalled before emitting a WorkerStall event.
    pub stall_timeout_ms: u64,

    /// Network interface to monitor for NIC-level drops (e.g. "eth0").
    pub interface_name: String,

    /// Emit a CaptureOverrun event when NIC drops increase by this many packets.
    /// 0 = emit on every non-zero increase.
    pub overrun_threshold: u64,
}

impl Default for WatchdogConfig {
    fn default() -> Self {
        Self {
            stall_timeout_ms:  30_000, // 30 seconds (from PerformanceConfig)
            interface_name:    String::new(),
            overrun_threshold: 1000,
        }
    }
}

// ── WatchdogStats ─────────────────────────────────────────────────────────────

/// Statistics collected by the watchdog over the session.
#[derive(Debug, Default)]
pub struct WatchdogStats {
    /// Total worker stall events emitted.
    pub stall_events_emitted: u64,

    /// Total NIC overrun events emitted.
    pub overrun_events_emitted: u64,

    /// Total NIC-level packets dropped (cumulative).
    pub total_nic_drops: u64,

    /// Maximum stall duration observed across all workers (microseconds).
    pub max_stall_duration_us: u64,
}

// ── Watchdog ──────────────────────────────────────────────────────────────────

/// Worker watchdog and NIC overrun monitor.
///
/// Runs as an independent thread. Observes worker packet counters via
/// atomic reads and NIC drop counters via /proc/net/dev.
/// Emits structured events on stall detection and NIC overrun.
pub struct Watchdog {
    config:       WatchdogConfig,
    workers:      Vec<WorkerWatchHandle>,
    shutdown_flag: Arc<AtomicBool>,
}

impl Watchdog {
    /// Create a new watchdog with the given config and worker handles.
    pub fn new(
        config:  WatchdogConfig,
        workers: Vec<WorkerWatchHandle>,
    ) -> Self {
        Self {
            config,
            workers,
            shutdown_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Start the watchdog thread.
    ///
    /// Returns a WatchdogHandle that can be used to shut down the watchdog
    /// and collect its final statistics.
    pub fn start(
        self,
        event_tx: crossbeam_channel::Sender<SnfEvent>,
    ) -> WatchdogHandle {
        let shutdown_flag = Arc::clone(&self.shutdown_flag);

        let handle = thread::Builder::new()
            .name("snf-watchdog".to_string())
            .spawn(move || {
                run_watchdog(self, event_tx)
            })
            .unwrap_or_else(|e| {
                eprintln!("[SNF][Watchdog] Failed to spawn watchdog thread: {}", e);
                std::process::exit(1);
            });

        WatchdogHandle {
            thread:        Some(handle),
            shutdown_flag,
        }
    }
}

// ── WatchdogHandle ────────────────────────────────────────────────────────────

/// Handle to a running watchdog thread.
pub struct WatchdogHandle {
    thread:        Option<thread::JoinHandle<WatchdogStats>>,
    shutdown_flag: Arc<AtomicBool>,
}

impl WatchdogHandle {
    /// Signal the watchdog to shut down and collect final stats.
    pub fn shutdown(mut self) -> WatchdogStats {
        self.shutdown_flag.store(true, Ordering::SeqCst);
        if let Some(handle) = self.thread.take() {
            handle.join().unwrap_or_else(|_| {
                eprintln!("[SNF][Watchdog] Thread join failed.");
                WatchdogStats::default()
            })
        } else {
            WatchdogStats::default()
        }
    }
}

// ── WATCHDOG MAIN LOOP ────────────────────────────────────────────────────────

fn run_watchdog(
    watchdog: Watchdog,
    event_tx: crossbeam_channel::Sender<SnfEvent>,
) -> WatchdogStats {
    let mut stats = WatchdogStats::default();

    // Track the last seen packet count per worker.
    let mut last_counts: HashMap<usize, u64> = watchdog.workers.iter()
        .map(|w| (w.worker_index, 0u64))
        .collect();

    // Track when each worker was last seen advancing.
    let mut last_advance: HashMap<usize, Instant> = watchdog.workers.iter()
        .map(|w| (w.worker_index, Instant::now()))
        .collect();

    // Track last NIC drop count for delta computation.
    let mut last_nic_drops: u64 = 0;
    let mut last_overrun_check = Instant::now();

    let sample_interval = Duration::from_millis(WATCHDOG_SAMPLE_INTERVAL_MS);
    let stall_timeout   = Duration::from_millis(watchdog.config.stall_timeout_ms);

    while !watchdog.shutdown_flag.load(Ordering::Relaxed) {
        thread::sleep(sample_interval);

        let now = Instant::now();

        // ── Worker stall detection ────────────────────────────────────────────
        for worker in &watchdog.workers {
            let current = worker.packets_processed.load(Ordering::Relaxed);
            let last    = *last_counts.get(&worker.worker_index).unwrap_or(&0);

            if current > last {
                // Worker is advancing — reset stall timer.
                last_counts.insert(worker.worker_index, current);
                last_advance.insert(worker.worker_index, now);
            } else {
                // Worker hasn't advanced — check if we've exceeded the timeout.
                let since_last = now.duration_since(
                    *last_advance.get(&worker.worker_index).unwrap_or(&now)
                );

                if since_last >= stall_timeout {
                    let stall_us = since_last.as_micros() as u64;

                    eprintln!(
                        "[SNF][Watchdog] Worker {} stalled for {}ms (last count: {}).",
                        worker.worker_index,
                        since_last.as_millis(),
                        current
                    );

                    // Emit WorkerStall event.
                    let mut ev = SnfEvent::new(
                        0, 0, 0, // event_id/packet_id/timestamp filled by EventBus
                        EventType::WorkerStall,
                        "ENGINE", "",
                    );
                    ev.attr_u64("worker_index", worker.worker_index as u64);
                    ev.attr_u64("stall_duration_us", stall_us);
                    ev.attr_u64("last_packet_count", current);

                    let _ = event_tx.try_send(ev); // Non-blocking — drop if channel full

                    stats.stall_events_emitted  = stats.stall_events_emitted.saturating_add(1);
                    if stall_us > stats.max_stall_duration_us {
                        stats.max_stall_duration_us = stall_us;
                    }

                    // Reset timer to avoid repeated events for the same stall.
                    last_advance.insert(worker.worker_index, now);
                }
            }
        }

        // ── NIC overrun detection ─────────────────────────────────────────────
        if now.duration_since(last_overrun_check)
            >= Duration::from_millis(OVERRUN_CHECK_INTERVAL_MS)
        {
            last_overrun_check = now;

            if let Some(nic_drops) = read_nic_drop_count(&watchdog.config.interface_name) {
                let delta = nic_drops.saturating_sub(last_nic_drops);
                last_nic_drops = nic_drops;

                if delta >= watchdog.config.overrun_threshold {
                    eprintln!(
                        "[SNF][Watchdog] NIC overrun detected: {} packets dropped \
                         on '{}' (total: {}).",
                        delta, watchdog.config.interface_name, nic_drops
                    );

                    let mut ev = SnfEvent::new(
                        0, 0, 0,
                        EventType::CaptureOverrun,
                        "CAPTURE", "",
                    );
                    ev.attr_str("interface",    watchdog.config.interface_name.clone());
                    ev.attr_u64("drop_delta",   delta);
                    ev.attr_u64("drop_total",   nic_drops);
                    ev.attr_str("reason",       "ring_overrun".to_string());

                    let _ = event_tx.try_send(ev);

                    stats.overrun_events_emitted = stats.overrun_events_emitted.saturating_add(1);
                    stats.total_nic_drops        = stats.total_nic_drops.saturating_add(delta);
                }
            }
        }
    }

    stats
}

// ── NIC Drop Counter Reader ───────────────────────────────────────────────────

/// Read the RX drop count for a network interface from /proc/net/dev.
///
/// /proc/net/dev format (columns):
///   Interface | RX bytes packets errs drop fifo frame compressed multicast |
///              | TX bytes packets errs drop fifo colls carrier compressed
///
/// Returns None if the interface is not found or /proc/net/dev is unreadable.
fn read_nic_drop_count(interface: &str) -> Option<u64> {
    if interface.is_empty() { return None; }

    #[cfg(target_os = "linux")]
    {
        let content = std::fs::read_to_string("/proc/net/dev").ok()?;
        for line in content.lines() {
            let line = line.trim();
            if !line.starts_with(interface) { continue; }

            // Strip "interface:" prefix
            let after_colon = line.splitn(2, ':').nth(1)?;
            let fields: Vec<&str> = after_colon.split_whitespace().collect();

            // RX drop is field index 3 (0-based): bytes, packets, errs, drop
            fields.get(3)?.parse::<u64>().ok();
        }
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = interface;
        None
    }
}