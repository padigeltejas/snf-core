// src/threading/packet_queue.rs
//
// PacketQueue — bounded MPSC packet queue for multi-threaded capture.
//
// ── Why crossbeam_channel over std::sync::mpsc ───────────────────────────────
//
//   std::sync::mpsc::channel() is unbounded — a line-rate capture engine cannot
//   use it because a slow worker thread would cause unbounded heap growth and
//   eventual OOM under sustained traffic. std::sync::mpsc::sync_channel() is
//   bounded but its blocking behaviour under contention has higher latency than
//   crossbeam's lock-free ring buffer implementation.
//
//   crossbeam_channel::bounded() gives us:
//     (a) Lock-free MPSC with a fixed-size ring buffer.
//     (b) Backpressure: push blocks (or times out) when full — correct for
//         line-rate capture where we prefer a controlled drop over OOM.
//     (c) send_timeout() — lets the capture thread impose a hard deadline
//         and drop the packet rather than stalling indefinitely.
//     (d) is_disconnected() — clean shutdown signalling to worker threads.
//
// ── Backpressure Policy ───────────────────────────────────────────────────────
//
//   push() waits up to PUSH_TIMEOUT_US (500µs) for a free slot.
//   If still full, the packet is dropped and drop_count is incremented.
//   This is intentional: a bounded drop at ingestion is safer than OOM.
//   drop_count is surfaced to stats and reporting — operators can tune
//   queue depth or add workers if they see non-zero drops.
//
// ── Capacity ─────────────────────────────────────────────────────────────────
//
//   DEFAULT_QUEUE_DEPTH = 8192. At 1500B average packet size, that is ~12MB
//   of queued packet data (owned Vec<u8> copies). Configurable per deployment.
//
// ── Determinism Contract ─────────────────────────────────────────────────────
//
//   PacketQueue is only active when worker_threads > 1. Replay mode enforces
//   worker_threads == 1 before this code path is ever reached. The queue is
//   therefore completely outside any deterministic code path.
//
// Phase 11B addition.

use std::time::Duration;
use crossbeam_channel::{bounded, Sender, Receiver, SendTimeoutError, RecvTimeoutError};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

// ── CONSTANTS ─────────────────────────────────────────────────────────────────

/// Default queue depth in packets.
/// 8192 packets × ~1500 bytes avg ≈ 12MB peak queue memory.
/// Increase for high-throughput deployments (10Gbps links may need 65536).
pub const DEFAULT_QUEUE_DEPTH: usize = 8_192;

/// How long the capture thread waits for a free slot before dropping.
/// 500µs: if workers cannot drain within half a millisecond at the current
/// throughput, we are genuinely overwhelmed and must drop.
const PUSH_TIMEOUT_US: u64 = 500;

// ── RawPacket ─────────────────────────────────────────────────────────────────

/// A single raw packet work item — everything a worker needs, nothing more.
///
/// Contains a heap-allocated copy of the raw frame bytes plus metadata
/// from the pcap packet header. Workers do not need to touch any shared
/// state to process a RawPacket.
#[derive(Debug)]
pub struct RawPacket {
    /// Raw packet bytes starting at the Ethernet frame header.
    /// Owned heap allocation — zero shared state between producer and consumer.
    pub data: Vec<u8>,

    /// Capture timestamp in microseconds UTC (sourced from pcap packet header).
    /// Never wall-clock. All temporal reasoning in workers must use this field.
    pub timestamp_us: u64,

    /// Original on-wire length. May exceed data.len() if pcap snaplen truncated
    /// the frame. Used for accurate byte accounting in FlowTable.
    pub wire_len: u32,

    /// Monotonically increasing packet sequence number assigned by the capture
    /// thread at ingestion time. Workers use this as packet_id when constructing
    /// SnfEvent objects. Sequence is global across all shards.
    pub packet_seq: u64,

    /// Pre-computed shard index: packet_seq % num_shards.
    /// Computed once by the capture thread so workers can route without hashing.
    pub shard_index: usize,
}

// ── PacketQueueTx ─────────────────────────────────────────────────────────────

/// Producer (capture thread) side of a packet queue.
///
/// Clone is supported — but in SNF's architecture only the capture thread
/// produces, so one PacketQueueTx is sufficient. The clone capability exists
/// for future multi-NIC capture support.
pub struct PacketQueueTx {
    sender:     Sender<RawPacket>,
    drop_count: Arc<AtomicU64>,
}

impl PacketQueueTx {
    /// Push a packet onto the queue, waiting up to PUSH_TIMEOUT_US.
    ///
    /// Returns true if successfully queued.
    /// Returns false (and increments drop_count) if the queue was full
    /// for the full timeout duration.
    pub fn push(&self, packet: RawPacket) -> bool {
        let timeout = Duration::from_micros(PUSH_TIMEOUT_US);
        match self.sender.send_timeout(packet, timeout) {
            Ok(())                               => true,
            Err(SendTimeoutError::Timeout(_))    => {
                self.drop_count.fetch_add(1, Ordering::Relaxed);
                false
            }
            // All Rx handles dropped — clean shutdown in progress.
            Err(SendTimeoutError::Disconnected(_)) => false,
        }
    }

    /// Non-blocking push. Returns immediately if queue is full.
    /// More aggressive than push() — use in tight capture loops where
    /// even 500µs stall is unacceptable (e.g. 10Gbps+ deployments).
    pub fn try_push(&self, packet: RawPacket) -> bool {
        use crossbeam_channel::TrySendError;
        match self.sender.try_send(packet) {
            Ok(())                            => true,
            Err(TrySendError::Full(_))        => {
                self.drop_count.fetch_add(1, Ordering::Relaxed);
                false
            }
            Err(TrySendError::Disconnected(_)) => false,
        }
    }

    /// Total packets dropped due to queue saturation since this Tx was created.
    /// Non-zero values indicate the worker pool is undersized for the traffic rate.
    pub fn drop_count(&self) -> u64 {
        self.drop_count.load(Ordering::Relaxed)
    }
}

impl Clone for PacketQueueTx {
    fn clone(&self) -> Self {
        Self {
            sender:     self.sender.clone(),
            drop_count: Arc::clone(&self.drop_count),
        }
    }
}

// ── PacketQueueRx ─────────────────────────────────────────────────────────────

/// Consumer (worker thread) side of a packet queue.
///
/// One PacketQueueRx per worker thread. Not Clone — the channel is MPSC
/// (multiple producers, single consumer per Rx). For N workers, create
/// N independent (Tx, Rx) pairs and distribute one Tx clone and one Rx
/// per worker. See WorkerPool for how this is done in SNF.
pub struct PacketQueueRx {
    receiver: Receiver<RawPacket>,
}

impl PacketQueueRx {
    /// Block until a packet is available or deadline elapses.
    ///
    /// Returns None on timeout — worker should loop and check shutdown flag.
    /// Returns None if all Tx handles are dropped — signals clean shutdown.
    pub fn pop_timeout(&self, timeout: Duration) -> Option<RawPacket> {
        match self.receiver.recv_timeout(timeout) {
            Ok(pkt)                          => Some(pkt),
            Err(RecvTimeoutError::Timeout)   => None,
            Err(RecvTimeoutError::Disconnected) => None,
        }
    }

    /// True if all Tx handles have been dropped AND the queue is empty.
    /// Workers poll this after pop_timeout returns None to decide whether
    /// to flush and exit, or to keep polling.
    ///
    /// crossbeam_channel::Receiver has no is_disconnected() method.
    /// We detect disconnection by attempting a non-blocking recv:
    ///   - Err(TryRecvError::Disconnected) = all senders dropped, queue empty → shutdown.
    ///   - Err(TryRecvError::Empty)        = senders still alive but nothing queued → keep polling.
    ///   - Ok(_)                           = packet available → not shutdown (caller should process it).
    pub fn is_shutdown(&self) -> bool {
        use crossbeam_channel::TryRecvError;
        matches!(self.receiver.try_recv(), Err(TryRecvError::Disconnected))
    }

    /// Non-blocking pop — returns immediately if queue is empty.
    ///
    /// Used by Phase 11D batch drain: after the first blocking recv,
    /// the worker drains up to BATCH_SIZE-1 more packets without sleeping.
    /// Returns None if queue is empty OR all senders are disconnected.
    #[inline]
    pub fn try_pop(&self) -> Option<RawPacket> {
        use crossbeam_channel::TryRecvError;
        match self.receiver.try_recv() {
            Ok(pkt)                          => Some(pkt),
            Err(TryRecvError::Empty)         => None,
            Err(TryRecvError::Disconnected)  => None,
        }
    }

    /// Current number of packets sitting in this queue.
    /// Used by stats and monitoring to detect worker lag.
    pub fn pending_count(&self) -> usize {
        self.receiver.len()
    }
}

// ── PacketQueue ───────────────────────────────────────────────────────────────

/// Factory for creating a matched (PacketQueueTx, PacketQueueRx) pair.
///
/// The typical setup in WorkerPool is:
///   - One (Tx, Vec<Rx>) construction per worker count.
///   - Capture thread holds the Tx (clones it if needed).
///   - Each worker thread is given one Rx.
pub struct PacketQueue;

impl PacketQueue {
    /// Create a bounded (Tx, Rx) pair with DEFAULT_QUEUE_DEPTH capacity.
    pub fn new() -> (PacketQueueTx, PacketQueueRx) {
        Self::with_capacity(DEFAULT_QUEUE_DEPTH)
    }

    /// Create a bounded (Tx, Rx) pair with a specific capacity.
    /// Minimum enforced at 64 entries to prevent accidental starvation.
    pub fn with_capacity(capacity: usize) -> (PacketQueueTx, PacketQueueRx) {
        let cap = capacity.max(64);
        let (sender, receiver) = bounded(cap);
        let drop_count = Arc::new(AtomicU64::new(0));

        let tx = PacketQueueTx { sender, drop_count };
        let rx = PacketQueueRx { receiver };
        (tx, rx)
    }
}