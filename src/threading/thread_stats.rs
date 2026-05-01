// src/threading/thread_stats.rs
//
// ThreadStats — per-worker and aggregate performance statistics.
//
// Provides precise per-worker counters for:
//   - Packets processed / dropped / errored
//   - Events emitted
//   - Queue depth snapshots
//   - Lock contention estimates (shard wait cycles)
//   - Throughput (packets per second, bytes per second)
//
// Design:
//   Each WorkerThread owns a ThreadStats. At shutdown, WorkerPool collects
//   all per-worker stats and aggregates them into an AggregateStats.
//
//   Stats are NOT updated on the hot path via Mutex — each worker updates
//   its own ThreadStats exclusively (no shared mutable state between workers).
//   The WorkerPool collects them only at shutdown, when each worker has
//   already exited and returned ownership of its ThreadStats.
//
//   This means stats have zero hot-path overhead (no atomics, no locks)
//   while still providing complete session coverage.
//
//   ENTERPRISE NOTE: For live stats dashboards (Phase 14+), promote the
//   counters that matter most (packets_processed, events_emitted) to
//   Arc<AtomicU64> so a monitoring thread can sample them without
//   acquiring any lock. For Phase 11B, shutdown-time collection is sufficient.
//
// Phase 11B addition.

use std::time::{Duration, Instant};

// ── ThreadStats ───────────────────────────────────────────────────────────────

/// Performance counters for a single worker thread.
///
/// Owned exclusively by one worker — no synchronization required on writes.
/// Collected by WorkerPool at shutdown when the worker has exited.
#[derive(Debug, Default)]
pub struct ThreadStats {
    // ── Identity ──────────────────────────────────────────────────────────────

    /// Worker index (0-based). Matches the worker's assignment in WorkerPool.
    pub worker_index: usize,

    /// Shard indices this worker is responsible for.
    /// Populated at worker creation — informational only.
    pub assigned_shards: Vec<usize>,

    // ── Packet Counters ────────────────────────────────────────────────────────

    /// Total packets pulled from this worker's PacketQueueRx and processed.
    pub packets_processed: u64,

    /// Packets that failed Ethernet/IP parsing (malformed frames).
    pub packets_parse_error: u64,

    /// Packets that triggered a protocol analyzer error (counted per-packet,
    /// not per-error — a single packet can produce at most one parse error event).
    pub packets_analyzer_error: u64,

    /// Packets dropped by the upstream capture thread before reaching this worker.
    /// Populated at shutdown from PacketQueueTx.drop_count().
    pub upstream_queue_drops: u64,

    // ── Event Counters ─────────────────────────────────────────────────────────

    /// Total SnfEvents emitted to EventBus by this worker.
    pub events_emitted: u64,

    // ── Flow Counters ──────────────────────────────────────────────────────────

    /// New flows created by this worker.
    pub flows_created: u64,

    /// Flows expired (idle timeout) by this worker during periodic GC.
    pub flows_expired: u64,

    /// Flows evicted from the FlowTable due to LRU capacity pressure.
    pub flows_evicted: u64,

    // ── Timing ────────────────────────────────────────────────────────────────

    /// Wall-clock time when this worker thread started processing.
    /// Set by the worker at the top of its main loop.
    pub started_at: Option<Instant>,

    /// Wall-clock time when this worker thread finished processing.
    /// Set just before the worker exits.
    pub finished_at: Option<Instant>,

    /// Total wall-clock time this worker spent waiting on its PacketQueueRx
    /// (i.e. idle time — queue was empty). Measured by timing pop_timeout calls.
    pub total_idle_duration: Duration,

    // ── Queue Depth Samples ───────────────────────────────────────────────────

    /// Queue depth sampled at the start of each processing cycle.
    /// Stored as a running max — the peak queue depth observed by this worker.
    /// Peak depth > 0 for extended periods indicates worker is the bottleneck.
    pub peak_queue_depth: usize,

    // ── Shard Lock Contention ─────────────────────────────────────────────────

    /// Number of times this worker had to wait for a FlowTable shard lock.
    /// In the per-shard-per-worker model this should be zero — if non-zero,
    /// the shard assignment is not perfectly partitioned (expected for odd
    /// worker counts where some workers share shards).
    pub shard_lock_contentions: u64,
}

impl ThreadStats {
    /// Create a new ThreadStats for the given worker index.
    pub fn new(worker_index: usize) -> Self {
        Self {
            worker_index,
            ..Default::default()
        }
    }

    /// Record that the worker has started. Call at top of worker main loop.
    pub fn mark_started(&mut self) {
        self.started_at = Some(Instant::now());
    }

    /// Record that the worker has finished. Call just before worker exits.
    pub fn mark_finished(&mut self) {
        self.finished_at = Some(Instant::now());
    }

    /// Record an idle wait cycle (pop_timeout returned None).
    pub fn record_idle(&mut self, duration: Duration) {
        self.total_idle_duration += duration;
    }

    /// Update the peak queue depth observation.
    pub fn observe_queue_depth(&mut self, depth: usize) {
        if depth > self.peak_queue_depth {
            self.peak_queue_depth = depth;
        }
    }

    /// Total wall-clock duration this worker ran (start to finish).
    /// Returns None if the worker has not started or not finished.
    pub fn total_duration(&self) -> Option<Duration> {
        match (self.started_at, self.finished_at) {
            (Some(s), Some(f)) => Some(f.duration_since(s)),
            _                  => None,
        }
    }

    /// Fraction of time the worker was idle (waiting for packets).
    /// Returns 0.0 if total duration is zero.
    pub fn idle_fraction(&self) -> f64 {
        let total_secs = self.total_duration()
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        if total_secs <= 0.0 { return 0.0; }
        self.total_idle_duration.as_secs_f64() / total_secs
    }

    /// Packets processed per second (over the worker's total duration).
    /// Returns 0.0 if duration is zero.
    pub fn packets_per_second(&self) -> f64 {
        let secs = self.total_duration()
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        if secs <= 0.0 { return 0.0; }
        self.packets_processed as f64 / secs
    }
}

// ── AggregateStats ────────────────────────────────────────────────────────────

/// Aggregate statistics across all worker threads for a session.
///
/// Built by WorkerPool::collect_stats() at shutdown by summing all per-worker
/// ThreadStats. Surfaced in the Evidence report and session summary.
#[derive(Debug, Default)]
pub struct AggregateStats {
    /// Number of workers that contributed to these stats.
    pub worker_count: usize,

    // ── Totals ─────────────────────────────────────────────────────────────────

    pub total_packets_processed:  u64,
    pub total_packets_parse_error: u64,
    pub total_events_emitted:     u64,
    pub total_flows_created:      u64,
    pub total_flows_expired:      u64,
    pub total_flows_evicted:      u64,
    pub total_upstream_drops:     u64,
    pub total_shard_contentions:  u64,

    // ── Per-worker summaries ───────────────────────────────────────────────────

    /// Per-worker packet count for load balance analysis.
    /// Index = worker_index.
    pub per_worker_packets: Vec<u64>,

    /// Maximum queue depth observed across all workers.
    pub peak_queue_depth: usize,

    /// Total session duration (wall clock from first worker start to last finish).
    pub session_duration: Option<Duration>,

    // ── Derived Rates ──────────────────────────────────────────────────────────

    /// Average packets per second across the session.
    pub avg_packets_per_second: f64,

    /// Worker load balance ratio: min_worker_packets / max_worker_packets.
    /// 1.0 = perfect balance. <0.5 = significant imbalance.
    pub load_balance_ratio: f64,
}

impl AggregateStats {
    /// Build AggregateStats from a slice of per-worker ThreadStats.
    pub fn from_workers(workers: &[ThreadStats]) -> Self {
        if workers.is_empty() {
            return Self::default();
        }

        let mut agg = Self {
            worker_count: workers.len(),
            ..Default::default()
        };

        let mut earliest_start: Option<Instant> = None;
        let mut latest_finish:  Option<Instant> = None;

        for w in workers {
            agg.total_packets_processed  = agg.total_packets_processed.saturating_add(w.packets_processed);
            agg.total_packets_parse_error = agg.total_packets_parse_error.saturating_add(w.packets_parse_error);
            agg.total_events_emitted     = agg.total_events_emitted.saturating_add(w.events_emitted);
            agg.total_flows_created      = agg.total_flows_created.saturating_add(w.flows_created);
            agg.total_flows_expired      = agg.total_flows_expired.saturating_add(w.flows_expired);
            agg.total_flows_evicted      = agg.total_flows_evicted.saturating_add(w.flows_evicted);
            agg.total_upstream_drops     = agg.total_upstream_drops.saturating_add(w.upstream_queue_drops);
            agg.total_shard_contentions  = agg.total_shard_contentions.saturating_add(w.shard_lock_contentions);
            agg.per_worker_packets.push(w.packets_processed);

            if w.peak_queue_depth > agg.peak_queue_depth {
                agg.peak_queue_depth = w.peak_queue_depth;
            }

            // Track overall session wall-clock span.
            if let Some(s) = w.started_at {
                earliest_start = Some(match earliest_start {
                    None    => s,
                    Some(e) => if s < e { s } else { e },
                });
            }
            if let Some(f) = w.finished_at {
                latest_finish = Some(match latest_finish {
                    None    => f,
                    Some(l) => if f > l { f } else { l },
                });
            }
        }

        // Compute session duration.
        if let (Some(s), Some(f)) = (earliest_start, latest_finish)
            && f > s {
                agg.session_duration = Some(f.duration_since(s));
            }

        // Derived rates.
        if let Some(dur) = agg.session_duration {
            let secs = dur.as_secs_f64();
            if secs > 0.0 {
                agg.avg_packets_per_second = agg.total_packets_processed as f64 / secs;
            }
        }

        // Load balance ratio.
        if !agg.per_worker_packets.is_empty() {
            let max_pkts = *agg.per_worker_packets.iter().max().unwrap_or(&1);
            let min_pkts = *agg.per_worker_packets.iter().min().unwrap_or(&0);
            if max_pkts > 0 {
                agg.load_balance_ratio = min_pkts as f64 / max_pkts as f64;
            }
        }

        agg
    }

    /// Human-readable summary for session report.
    pub fn summary_line(&self) -> String {
        format!(
            "Workers: {} | Packets: {} | Events: {} | Flows: {} | \
             Drops: {} | PPS: {:.0} | Balance: {:.2}",
            self.worker_count,
            self.total_packets_processed,
            self.total_events_emitted,
            self.total_flows_created,
            self.total_upstream_drops,
            self.avg_packets_per_second,
            self.load_balance_ratio,
        )
    }

    /// Print a full structured summary box at end of a multi-threaded session.
    ///
    /// Called from capture/mod.rs after pool.shutdown() + merge_worker_shards().
    pub fn print_final_summary(&self, mode: &str, output_path: &str, pcap_sha256: &str) {
        let sep  = "=".repeat(62);
        let dsep = "-".repeat(62);
        println!();
        println!("{}", sep);
        println!("  SNF-Core  |  Session Complete");
        println!("{}", sep);
        println!("  Mode      : {}", mode);
        println!("  Output    : {}", output_path);
        if !pcap_sha256.is_empty() && pcap_sha256 != "live" {
            println!("  SHA-256   : {}", pcap_sha256);
        }
        println!("{}", dsep);
        println!("  Workers   : {}", self.worker_count);
        println!("  Packets   : {}", self.total_packets_processed);
        println!("  Events    : {}", self.total_events_emitted);
        println!("  Flows     : {} (across all workers)", self.total_flows_created);
        if let Some(dur) = self.session_duration {
            let secs = dur.as_secs_f64();
            if secs > 0.0 {
                println!("  Duration  : {:.1}s  ({:.0} pps avg)", secs, self.avg_packets_per_second);
            }
        }
        if self.total_upstream_drops > 0 {
            println!("  Drops     : {} (queue full)", self.total_upstream_drops);
        }
        if self.per_worker_packets.len() > 1 {
            println!("{}", dsep);
            println!("  Worker Distribution (balance: {:.2}):", self.load_balance_ratio);
            for (i, pkts) in self.per_worker_packets.iter().enumerate() {
                println!("    Worker {:>2}   {} pkts", i, pkts);
            }
        }
        println!("{}", sep);
        println!();
    }
}