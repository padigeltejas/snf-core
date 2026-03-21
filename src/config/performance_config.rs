// src/config/performance_config.rs
//
// Performance layer configuration — controls threading, memory, and I/O tuning.
//
// Phase 4: expanded from 2 to 15 parameters.

#[derive(Clone)]
pub struct PerformanceConfig {
    // ---------------- THREADING ----------------
    /// Number of worker threads for packet processing.
    /// 1 = single-threaded (deterministic, required for Replay mode).
    /// >1 = parallel processing (higher throughput, non-deterministic order).
    pub worker_threads: usize,

    /// Number of packets processed per worker batch.
    /// Larger batches = better throughput, higher latency per packet.
    pub packet_batch_size: usize,

    /// CPU core affinity mask for the capture thread.
    /// None = OS decides. Set to a specific core to reduce jitter.
    pub cpu_affinity: Option<usize>,

    // ---------------- FLOW TABLE ----------------
    /// Number of shards in the flow hash table.
    /// More shards = less contention under multithreaded access.
    /// Must be a power of 2. Ignored in single-threaded mode.
    pub flow_table_shards: usize,

    /// How often to run the flow garbage collector in milliseconds.
    /// Lower = more responsive expiry, higher CPU cost.
    pub gc_interval_ms: u64,

    // ---------------- MEMORY ----------------
    /// Maximum total memory SNF may use in megabytes.
    /// 0 = unlimited. When limit is approached, aggressive eviction begins.
    pub max_memory_mb: usize,

    /// Size of the internal event queue (number of events).
    /// Events are buffered here before being written to output.
    pub event_queue_size: usize,

    /// Parser input queue depth (number of packets queued for processing).
    pub parser_queue_depth: usize,

    // ---------------- I/O ----------------
    /// Enable io_uring for async disk I/O on Linux.
    /// Significantly improves NDJSON write throughput on high packet rates.
    /// Falls back to synchronous I/O on unsupported kernels.
    pub io_uring_enabled: bool,

    /// Enable zero-copy receive path (AF_XDP / XDP on Linux).
    /// Requires kernel 4.18+ and compatible NIC driver.
    pub zero_copy_rx: bool,

    /// Batch event emission — accumulate events and write in bulk.
    /// Reduces syscall overhead at high event rates.
    pub batch_event_emit: bool,

    // ---------------- STATS ----------------
    /// Enable internal performance statistics collection.
    pub stats_enabled: bool,

    /// How often to output performance stats in milliseconds.
    /// Only used when stats_enabled = true.
    pub stats_output_interval_ms: u64,

    // ---------------- WATCHDOG ----------------
    /// Enable watchdog thread that restarts SNF if processing stalls.
    pub watchdog_enabled: bool,

    /// How long the watchdog waits before declaring a stall, in milliseconds.
    pub watchdog_timeout_ms: u64,
    /// Enable NUMA-aware memory allocation for flow tables and ring buffers.
    /// Only meaningful on multi-socket Linux servers.
    pub numa_enabled: bool,

    /// Enable NIC hardware timestamping via SO_TIMESTAMPING.
    /// Falls back to pcap timestamps if NIC does not support it.
    pub hw_timestamps_enabled: bool,

    /// Backpressure action when ring buffer is full.
    /// "drop" = drop packet (default), "log" = drop + log only.
    pub backpressure_action: String,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            worker_threads: 1,
            packet_batch_size: 32,
            cpu_affinity: None,
            flow_table_shards: 8,
            gc_interval_ms: 1000,
            max_memory_mb: 0,
            event_queue_size: 65536,
            parser_queue_depth: 1024,
            io_uring_enabled: false,
            zero_copy_rx: false,
            batch_event_emit: true,
            stats_enabled: false,
            stats_output_interval_ms: 5000,
            watchdog_enabled: false,
            watchdog_timeout_ms: 30_000,
            numa_enabled:          false,
            hw_timestamps_enabled: false,
            backpressure_action:   "drop".to_string(),
        }
    }
}