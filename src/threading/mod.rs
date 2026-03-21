// src/threading/mod.rs
//
// Threading Engine — Phase 11B/11C/11D/11E + Phase 14B/14F.
//
// ── Module Map ────────────────────────────────────────────────────────────────
//
//   packet_queue       — Bounded MPSC packet queue with backpressure.
//                        Phase 11D: try_pop() for batch drain.
//
//   worker_pool        — N worker threads, independent pipeline state.
//                        Phase 11D: batch drain (BATCH_SIZE=64).
//                        Phase 11E: DropAccumulator — batched capture.drop events.
//
//   flow_affinity      — Phase 11C: 5-tuple hash routing.
//                        compute_worker_for_packet() — zero-copy frame parsing.
//
//   sharded_flow_table — Shard-locked FlowTable for cross-worker shared state.
//
//   ring_buffer        — AF_PACKET TPACKET_V3 interface (Phase 14A full path).
//
//   thread_stats       — Per-worker + aggregate performance counters.
//
//   rss_config         — Phase 14B: RSS NIC queue configuration.
//                        RssConfig::apply() configures N-queue RSS on the NIC.
//                        RssQueueAssignment maps queues to workers.
//
//   watchdog           — Phase 14F: worker stall detection + NIC overrun monitoring.
//                        Watchdog thread emits WorkerStall and CaptureOverrun events.
//                        Reads /proc/net/dev for NIC-level drop counts.
//
// ── Determinism Contract ──────────────────────────────────────────────────────
//
//   This module is only reached when worker_threads > 1.
//   Replay mode enforces worker_threads = 1 before any code here runs.
//
// Phase 11B/11C/11D/11E + Phase 14B/14F.

pub mod packet_queue;
pub mod worker_pool;
pub mod flow_affinity;
pub mod sharded_flow_table;
pub mod ring_buffer;
pub mod thread_stats;
pub mod rss_config;
pub mod watchdog;

// ── Public re-exports ─────────────────────────────────────────────────────────

pub use worker_pool::WorkerPool;
pub use packet_queue::{PacketQueue, PacketQueueTx, PacketQueueRx, RawPacket};
pub use flow_affinity::compute_worker_for_packet;
pub use sharded_flow_table::ShardedFlowTable;
pub use ring_buffer::{RingBufferCapture, RingBufferConfig, RingBufferAvailability, FanoutMode};
pub use thread_stats::{ThreadStats, AggregateStats};
pub use rss_config::{RssConfig, RssQueueAssignment};
pub use watchdog::{Watchdog, WatchdogConfig, WatchdogHandle, WorkerWatchHandle};