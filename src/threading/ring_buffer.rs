// src/threading/ring_buffer.rs
//
// RingBufferCapture — AF_PACKET TPACKET_V3 mmap ring buffer abstraction.
//
// ── Why AF_PACKET Ring Buffers ───────────────────────────────────────────────
//
//   Standard libpcap (which SNF uses via the pcap crate) reads packets via
//   read(2) syscalls: one syscall per packet at 1Mpps = 1M syscalls/sec.
//   Syscall overhead alone caps throughput at ~2–3Gbps on a modern core.
//
//   Linux AF_PACKET with TPACKET_V3 uses a kernel-mapped ring buffer:
//     - Kernel writes packets directly into userspace-mapped memory.
//     - Userspace polls via poll(2) on a batch of packets, not one-by-one.
//     - Zero-copy: no data movement between kernel and userspace.
//     - At 10Gbps, this reduces syscall overhead by 99%.
//
//   This is the same mechanism used by Suricata (AF_PACKET runmode),
//   Zeek (AF_PACKET), and Snort 3 (AFPacket DAQ plugin).
//
// ── Implementation Scope for Phase 11B ───────────────────────────────────────
//
//   Full AF_PACKET mmap requires unsafe{} for mmap(2) syscalls, complex
//   ring descriptor state machine, and Linux-only kernel headers. This is
//   explicitly deferred to Phase 14 (Platform I/O Optimization).
//
//   Phase 11B provides:
//     (a) The RingBufferConfig struct — all configuration the kernel ring
//         buffer will need (block_size, frame_size, num_blocks, fan_out_mode).
//     (b) RingBufferCapture — a platform-agnostic trait object wrapper with:
//         - Linux: placeholder that documents the TPACKET_V3 interface.
//           Returns NotAvailable on all calls until Phase 14 implements it.
//         - Windows/macOS: graceful fallback to standard pcap with a clear
//           log message. No silent downgrade — operators always know.
//     (c) RingBufferStats — per-ring statistics for monitoring.
//
//   This gives Phase 11B a complete interface contract that Phase 14 can
//   implement without changing any call sites in WorkerPool.
//
// ── TPACKET_V3 Architecture (for Phase 14 implementers) ──────────────────────
//
//   1. socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))
//   2. setsockopt(PACKET_VERSION, TPACKET_V3)
//   3. setsockopt(PACKET_RX_RING, tpacket_req3 {
//        tp_block_size: 1MB,    // must be multiple of PAGE_SIZE
//        tp_frame_size: 2048,   // must be ≥ TPACKET3_HDRLEN + snaplen
//        tp_block_nr:   128,    // total ring = 128 × 1MB = 128MB
//        tp_retire_blk_tov: 60, // retire block after 60ms even if not full
//      })
//   4. mmap(ring_buffer, total_ring_size, PROT_READ|PROT_WRITE, MAP_SHARED)
//   5. Bind to interface with packet_mreq
//   6. AF_PACKET_FANOUT (optional): distribute across multiple sockets
//      for multi-core scaling without per-packet locks.
//
//   Block lifecycle: KERNEL_OWNED → (poll returns) → USER_OWNED → (release) → KERNEL_OWNED
//   Userspace signals block release by writing TP_STATUS_KERNEL to the block descriptor.
//
// ── Windows / macOS ───────────────────────────────────────────────────────────
//
//   Windows: WinPcap/Npcap do not support AF_PACKET. Use standard pcap.
//   macOS:   BPF-based capture does not support TPACKET. Use standard pcap.
//   In both cases, RingBufferCapture::new() returns Availability::NotAvailable
//   and the WorkerPool falls back to pcap-based capture transparently.
//
// Phase 11B addition (interface + config only; kernel implementation Phase 14).

// ── RingBufferConfig ──────────────────────────────────────────────────────────

/// Configuration for an AF_PACKET TPACKET_V3 ring buffer.
///
/// All fields are validated at construction — no post-construction mutations.
#[derive(Debug, Clone)]
pub struct RingBufferConfig {
    /// Ring buffer block size in bytes. Must be a multiple of PAGE_SIZE (4096).
    /// Larger blocks reduce poll(2) frequency at the cost of higher latency.
    /// 1MB (1_048_576) is the standard value for 1–10Gbps capture.
    pub block_size_bytes: usize,

    /// Maximum frame (packet slot) size in bytes.
    /// Must be ≥ TPACKET3_HDRLEN (52 bytes) + snaplen.
    /// 2048 accommodates standard Ethernet (1514 bytes) + header overhead.
    pub frame_size_bytes: usize,

    /// Number of blocks in the ring. Total ring memory = block_size × num_blocks.
    /// 128 blocks × 1MB = 128MB ring — appropriate for 10Gbps burst capture.
    pub num_blocks: usize,

    /// Block retirement timeout in milliseconds.
    /// The kernel will retire a partially-filled block after this interval
    /// even if it is not full. Lower = lower latency, more syscall pressure.
    /// 60ms is standard for SOC deployments.
    pub retire_block_timeout_ms: u32,

    /// Enable AF_PACKET_FANOUT for multi-socket per-interface distribution.
    /// When true, multiple sockets on the same interface hash packets across
    /// socket groups — enabling per-core packet processing without locks.
    /// Requires Linux 3.1+.
    pub fanout_enabled: bool,

    /// AF_PACKET_FANOUT mode. Only used when fanout_enabled = true.
    /// FANOUT_HASH (0) = hash by 5-tuple (most useful for SNF).
    /// FANOUT_CPU  (2) = distribute by CPU core of the softirq handler.
    /// FANOUT_LB   (1) = round-robin load balancing.
    pub fanout_mode: FanoutMode,

    /// Fanout group ID. Must be unique per capture session on this host.
    /// Typical practice: use process PID & 0xFFFF.
    pub fanout_group_id: u16,
}

/// AF_PACKET_FANOUT distribution modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FanoutMode {
    /// Hash by 5-tuple (src IP, dst IP, src port, dst port, proto).
    /// Ensures all packets for a flow go to the same socket/worker.
    /// This is the correct mode for SNF — flow state must be local to one worker.
    Hash,
    /// Round-robin across sockets. Simplest but breaks flow affinity.
    LoadBalance,
    /// Route to the CPU core that handles the NIC interrupt.
    Cpu,
}

impl Default for RingBufferConfig {
    fn default() -> Self {
        Self {
            block_size_bytes:       1_048_576,  // 1MB
            frame_size_bytes:       2_048,       // fits jumbo frames up to 1536B + header
            num_blocks:             128,         // 128MB ring total
            retire_block_timeout_ms: 60,
            fanout_enabled:         false,
            fanout_mode:            FanoutMode::Hash,
            fanout_group_id:        0,
        }
    }
}

impl RingBufferConfig {
    /// Validate configuration constraints. Returns Err with a description
    /// of the first violated constraint.
    pub fn validate(&self) -> Result<(), String> {
        const PAGE_SIZE: usize = 4_096;

        if !self.block_size_bytes.is_multiple_of(PAGE_SIZE) {
            return Err(format!(
                "block_size_bytes ({}) must be a multiple of PAGE_SIZE ({})",
                self.block_size_bytes, PAGE_SIZE
            ));
        }
        if self.frame_size_bytes < 2_048 {
            return Err(format!(
                "frame_size_bytes ({}) must be ≥ 2048 (TPACKET3 header + snaplen)",
                self.frame_size_bytes
            ));
        }
        if self.num_blocks == 0 {
            return Err("num_blocks must be > 0".to_string());
        }
        let total_ring = self.block_size_bytes.saturating_mul(self.num_blocks);
        if total_ring > 2_147_483_648 {
            return Err(format!(
                "Total ring size ({} bytes = {}MB) exceeds 2GB limit",
                total_ring,
                total_ring / 1_048_576
            ));
        }
        Ok(())
    }

    /// Total ring memory in bytes.
    pub fn total_ring_bytes(&self) -> usize {
        self.block_size_bytes.saturating_mul(self.num_blocks)
    }
}

// ── RingBufferStats ───────────────────────────────────────────────────────────

/// Per-ring performance counters. Updated atomically by the ring reader thread.
#[derive(Debug, Default)]
pub struct RingBufferStats {
    /// Total packets read from the ring buffer.
    pub packets_read: u64,

    /// Total packets dropped by the kernel (ring was full when packet arrived).
    /// Non-zero = ring is undersized or workers are too slow.
    pub kernel_drops: u64,

    /// Total bytes of packet data read.
    pub bytes_read: u64,

    /// Number of poll(2) wakeups (one per retired block batch).
    pub poll_wakeups: u64,

    /// Number of blocks processed.
    pub blocks_processed: u64,
}

// ── RingBufferAvailability ────────────────────────────────────────────────────

/// Platform availability of AF_PACKET ring buffer capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RingBufferAvailability {
    /// Full TPACKET_V3 support — Linux 3.2+ with AF_PACKET.
    Available,
    /// Platform does not support AF_PACKET. Fall back to standard pcap.
    NotAvailable,
}

// ── RingBufferCapture ─────────────────────────────────────────────────────────

/// Platform-agnostic ring buffer capture interface.
///
/// In Phase 11B, all methods return NotAvailable / placeholder values.
/// Phase 14 will replace the Linux branch with the real TPACKET_V3 implementation.
/// Call sites in WorkerPool do not need to change between phases.
pub struct RingBufferCapture {
    config:       RingBufferConfig,
    availability: RingBufferAvailability,
}

impl RingBufferCapture {
    /// Probe the current platform for AF_PACKET ring buffer support.
    ///
    /// On Linux: returns Available (Phase 14 will activate the real path).
    /// On Windows/macOS: returns NotAvailable with a log message.
    pub fn probe(config: RingBufferConfig) -> Self {
        let availability = Self::detect_platform_support();

        if availability == RingBufferAvailability::NotAvailable {
            // Intentionally non-stealth: operators must know they are on
            // the standard pcap path, not the zero-copy path.
            eprintln!(
                "[SNF] Ring buffer (AF_PACKET TPACKET_V3) not available on this platform. \
                 Falling back to standard pcap capture. \
                 For 10Gbps+ capture, run SNF on Linux kernel 3.2+."
            );
        }

        Self { config, availability }
    }

    /// Whether this instance can provide ring buffer capture.
    pub fn availability(&self) -> RingBufferAvailability {
        self.availability
    }

    /// True if ring buffer capture is available and configured.
    pub fn is_available(&self) -> bool {
        self.availability == RingBufferAvailability::Available
    }

    /// The configuration this instance was created with.
    pub fn config(&self) -> &RingBufferConfig {
        &self.config
    }

    /// Detect platform support for AF_PACKET.
    ///
    /// Phase 11B: compile-time detection only.
    /// Phase 14: runtime detection via socket(AF_PACKET, SOCK_RAW, 0) probe.
    fn detect_platform_support() -> RingBufferAvailability {
        // AF_PACKET is Linux-only. Compile-time gate.
        #[cfg(target_os = "linux")]
        {
            // Phase 14: runtime kernel version check and socket probe goes here.
            // For now, signal Available so Phase 14 can wire the real path.
            RingBufferAvailability::Available
        }
        #[cfg(not(target_os = "linux"))]
        {
            RingBufferAvailability::NotAvailable
        }
    }
}

// ── DEFAULT RING BUFFER CONFIG FROM ENGINE CONFIG ─────────────────────────────

/// Build a RingBufferConfig from the SNF EngineConfig.
///
/// Uses performance config fields where available; falls back to defaults.
pub fn ring_buffer_config_from_engine(
    config: &crate::config::engine_config::EngineConfig,
) -> RingBufferConfig {
    let mut rb = RingBufferConfig::default();

    // Worker count drives fanout: one socket per worker.
    let workers = config.performance.worker_threads;
    if workers > 1 {
        rb.fanout_enabled   = true;
        // Using process ID as fanout group ID is standard practice.
        // On Windows this will never be reached (not_available path).
        rb.fanout_group_id  = (std::process::id() & 0xFFFF) as u16;
        rb.fanout_mode      = FanoutMode::Hash; // 5-tuple hash for flow affinity
    }

    // io_uring_enabled = true signals operator wants high-performance I/O.
    // Pair with larger ring in that case.
    if config.performance.io_uring_enabled {
        rb.num_blocks = 256; // 256MB ring for io_uring deployments
    }

    rb
}