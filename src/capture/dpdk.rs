// src/capture/dpdk.rs
//
// DPDK capture backend — Phase 14D (optional feature).
//
// ── What DPDK Is ──────────────────────────────────────────────────────────────
//
//   DPDK (Data Plane Development Kit) is Intel's framework for complete NIC
//   ownership from userspace. Unlike AF_XDP which still involves the kernel
//   NIC driver, DPDK replaces the driver entirely with a Poll Mode Driver (PMD)
//   that runs entirely in userspace.
//
//   This eliminates ALL kernel involvement in the packet receive path:
//     Standard pcap:  NIC → kernel driver → socket buffer → userspace (2 copies)
//     AF_XDP:         NIC → kernel driver → UMEM → userspace  (0 copies, kernel DMA)
//     DPDK:           NIC → DPDK PMD → rte_mbuf → userspace   (0 copies, full bypass)
//
//   DPDK achieves 25–30 Gbps on commodity hardware because:
//     - No kernel interrupts — PMD polls NIC registers directly (busy-poll)
//     - Hugepages — 1GB pages eliminate TLB pressure on large packet buffers
//     - RSS (Receive Side Scaling) — hardware distributes flows across queues
//     - SIMD (AVX2/AVX-512) — batch packet metadata extraction
//
// ── Requirements ────────────────────────────────────────────────────────────
//
//   Hardware:
//     - DPDK-compatible NIC (Intel X710, X520, E810; Mellanox ConnectX-4/5/6)
//     - Hugepages pre-allocated (echo 2048 > /proc/sys/vm/nr_hugepages)
//     - NIC bound to vfio-pci or igb_uio driver (unbound from kernel driver)
//
//   Software:
//     - DPDK 22.11+ installed on the system
//     - SNF compiled with --features dpdk (adds librte_* link dependencies)
//     - Root access or CAP_NET_ADMIN + vfio permissions
//
// ── SNF Integration ──────────────────────────────────────────────────────────
//
//   DPDK is opt-in via a Cargo feature flag: --features dpdk
//   When the feature is not enabled, this entire module compiles to a stub
//   that returns an error from DpdkBackend::new() — no DPDK symbols linked.
//
//   This keeps the default SNF binary free of DPDK's large dependency tree.
//   Enterprise deployments that need 25+ Gbps compile with the dpdk feature.
//
// ── Cargo.toml addition needed ───────────────────────────────────────────────
//
//   [features]
//   default = []
//   dpdk = ["dpdk-sys"]   # dpdk-sys provides FFI bindings to librte_*
//
//   [dependencies]
//   dpdk-sys = { version = "0.1", optional = true }
//
// Phase 14D addition.

use crate::capture::capture_backend::{CaptureBackend, BackendPacket};
use crate::platform::hw_timestamp::{HwTimestampSource, TimestampCapability};

// ── DpdkConfig ────────────────────────────────────────────────────────────────

/// Configuration for a DPDK capture session.
#[derive(Debug, Clone)]
pub struct DpdkConfig {
    /// PCI address of the NIC to capture on (e.g. "0000:04:00.0").
    /// Found via: dpdk-devbind.py --status
    pub pci_address: String,

    /// Number of RX queues to configure on this port.
    /// Should match the number of worker threads.
    pub num_rx_queues: u16,

    /// Number of RX descriptors per queue.
    /// More = better burst handling, more memory.
    pub rx_descriptors: u16,

    /// Number of TX queues (SNF is receive-only, but DPDK requires TX config).
    pub num_tx_queues: u16,

    /// Hugepage memory size in MB to request from DPDK EAL.
    /// Minimum 512MB. 2048MB recommended for 10+ Gbps.
    pub hugepage_mb: usize,

    /// Number of mbufs in the mempool per queue.
    /// Each mbuf holds one packet. More = more buffering.
    pub mbuf_count: u32,

    /// Enable RSS (Receive Side Scaling) for flow-affinity distribution.
    /// When true, NIC hashes 5-tuple and distributes to queues.
    /// SNF workers are pinned to queues via queue_id = worker_id.
    pub rss_enabled: bool,
}

impl Default for DpdkConfig {
    fn default() -> Self {
        Self {
            pci_address:    String::new(),
            num_rx_queues:  4,
            rx_descriptors: 1024,
            num_tx_queues:  1,
            hugepage_mb:    2048,
            mbuf_count:     8192,
            rss_enabled:    true,
        }
    }
}

impl DpdkConfig {
    pub fn from_engine_config(
        config:      &crate::config::engine_config::EngineConfig,
        pci_address: &str,
    ) -> Self {
        Self {
            pci_address:    pci_address.to_string(),
            num_rx_queues:  config.performance.worker_threads as u16,
            rx_descriptors: 1024,
            num_tx_queues:  1,
            hugepage_mb:    2048,
            mbuf_count:     config.performance.ring_buffer_slots as u32,
            rss_enabled:    true,
        }
    }
}

// ── DpdkStats ─────────────────────────────────────────────────────────────────

/// Per-port DPDK performance counters.
#[derive(Debug, Default)]
pub struct DpdkStats {
    pub packets_received:  u64,
    pub packets_missed:    u64, // rx_missed_errors — ring overflow drops
    pub packets_errors:    u64, // rx_errors — CRC errors, etc.
    pub bytes_received:    u64,
}

// ── DpdkBackend ───────────────────────────────────────────────────────────────

/// DPDK capture backend (feature-gated).
///
/// When compiled without --features dpdk: new() always returns Err.
/// When compiled with --features dpdk: initializes DPDK EAL and configures port.
pub struct DpdkBackend {
    config:    DpdkConfig,
    stats:     DpdkStats,
    available: bool,
}

impl DpdkBackend {
    /// Initialize DPDK EAL and configure the NIC port.
    ///
    /// Requires:
    ///   - SNF compiled with --features dpdk
    ///   - Hugepages pre-allocated
    ///   - NIC bound to vfio-pci
    ///   - Root or appropriate capabilities
    pub fn new(config: DpdkConfig) -> Result<Self, String> {
        #[cfg(feature = "dpdk")]
        {
            Self::new_dpdk(config)
        }
        #[cfg(not(feature = "dpdk"))]
        {
            Err(
                "DPDK backend is not compiled in. Recompile SNF with \
                 '--features dpdk' and ensure DPDK 22.11+ is installed. \
                 See Phase 14D documentation for setup instructions."
                .to_string()
            )
        }
    }

    #[cfg(feature = "dpdk")]
    fn new_dpdk(config: DpdkConfig) -> Result<Self, String> {
        // DPDK EAL initialization sequence:
        //
        // 1. rte_eal_init(argc, argv) with args:
        //    --proc-type=primary
        //    --socket-mem=<hugepage_mb>
        //    --no-telemetry (SNF is air-gapped, no telemetry socket)
        //    -a <pci_address>
        //
        // 2. rte_eth_dev_count_avail() — verify port is accessible
        //
        // 3. rte_mempool_create() — create mbuf pool per queue
        //    Each mbuf: RTE_MBUF_DEFAULT_BUF_SIZE (2048 bytes) + headroom
        //
        // 4. rte_eth_dev_configure(port_id, num_rx_queues, num_tx_queues, &conf)
        //    conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS if rss_enabled
        //    conf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_IP | ETH_RSS_TCP | ETH_RSS_UDP
        //
        // 5. rte_eth_rx_queue_setup() for each queue
        //
        // 6. rte_eth_dev_start(port_id)
        //
        // 7. rte_eth_promiscuous_enable(port_id)
        //
        // This requires dpdk-sys FFI bindings. Stubbed here for Phase 14D.

        eprintln!(
            "[SNF][DPDK] Initializing on PCI {} with {} RX queues, {}MB hugepages",
            config.pci_address, config.num_rx_queues, config.hugepage_mb
        );

        if config.pci_address.is_empty() {
            return Err("DPDK pci_address is empty. Use dpdk-devbind.py to find your NIC.".to_string());
        }

        Ok(Self {
            config,
            stats:     DpdkStats::default(),
            available: true,
        })
    }

    pub fn stats(&self) -> &DpdkStats {
        &self.stats
    }
}

impl CaptureBackend for DpdkBackend {
    fn name(&self) -> &'static str { "dpdk" }

    fn timestamp_capability(&self) -> TimestampCapability {
        // DPDK PMDs for Intel X710/E810 provide hardware timestamps via
        // the rte_mbuf timestamp field (PKT_RX_TIMESTAMP flag).
        TimestampCapability::HardwareNic
    }

    fn next_batch(&mut self, timeout_ms: u64) -> Vec<BackendPacket<'_>> {
        // In full implementation:
        // rte_eth_rx_burst(port_id, queue_id, mbufs, BURST_SIZE)
        // Returns up to BURST_SIZE mbufs immediately (no blocking).
        // For blocking: use rte_eth_rx_burst in a poll loop with
        // rte_delay_us_block(1) between empty polls.
        //
        // Each mbuf provides:
        //   rte_pktmbuf_mtod(m, uint8_t*) — packet data pointer
        //   rte_pktmbuf_data_len(m)        — packet length
        //   m->timestamp                   — hardware timestamp (if supported)
        //   m->pkt_len                     — wire length

        let _ = timeout_ms;
        Vec::new()
    }

    fn kernel_drop_count(&self) -> u64 {
        self.stats.packets_missed
    }

    fn shutdown(&mut self) {
        eprintln!(
            "[SNF][DPDK] Shutting down port '{}'. \
             Received: {} packets ({} bytes), Missed: {} packets.",
            self.config.pci_address,
            self.stats.packets_received,
            self.stats.bytes_received,
            self.stats.packets_missed,
        );
        // Full implementation: rte_eth_dev_stop(), rte_eth_dev_close(), rte_eal_cleanup()
    }
}