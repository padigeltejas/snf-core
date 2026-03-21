// src/platform/mod.rs
//
// Platform abstraction layer — Phase 14.
//
// Provides Linux-specific high-performance I/O and CPU/memory topology
// primitives, each gated behind #[cfg(target_os = "linux")] so the
// codebase compiles cleanly on Windows and macOS with graceful fallbacks.
//
// ── Module Map ────────────────────────────────────────────────────────────────
//
//   numa            — NUMA topology detection and memory binding.
//                     mbind(2) / move_pages(2) for local-node allocation.
//                     Eliminates cross-socket memory latency at 10+ Gbps.
//
//   hw_timestamp    — NIC hardware timestamping via SO_TIMESTAMPING.
//                     Provides ±1µs accuracy vs ±10µs software timestamps.
//                     Critical for beacon detection and forensic timelines.
//
//   core_affinity   — Thread-to-core pinning via sched_setaffinity(2).
//                     Eliminates OS scheduler migration overhead.
//                     Required for NUMA-correct worker placement.
//
//   hardware_probe  — Hardware auto-detection and config auto-tuning.
//                     Probes CPU count, RAM, NUMA topology, best capture
//                     backend, and NIC timestamp capability at startup.
//                     Produces a HardwareProfile used by ConfigBuilder to
//                     scale worker_threads, batch_size, ring_buffer_slots
//                     automatically without operator configuration.
//
// ── Platform Policy ──────────────────────────────────────────────────────────
//
//   All public types in this module implement a consistent pattern:
//     - `probe()` or `detect()` — query OS/hardware capability
//     - `is_available()` — returns bool, never panics
//     - `apply()` or `bind()` — applies the optimization if available
//     - Falls back gracefully with a clear eprintln! if unavailable
//
//   No code in this module ever panics on unsupported platforms.
//   Every function that can fail returns Result<_, String> — not unwrap().
//
// Phase 14 addition. Phase 14F: hardware_probe added.

pub mod numa;
pub mod hw_timestamp;
pub mod core_affinity;
pub mod hardware_probe;

// ── Public re-exports ─────────────────────────────────────────────────────────

pub use numa::{NumaTopology, NumaPolicy};
pub use hw_timestamp::{HwTimestampConfig, HwTimestampSource, TimestampCapability};
pub use core_affinity::{CoreAffinityConfig, pin_thread_to_core, get_available_cores};
pub use hardware_probe::{HardwareProbe, HardwareProfile, CaptureBackendKind, apply_hardware_profile};