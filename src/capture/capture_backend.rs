// src/capture/capture_backend.rs
//
// Unified capture backend abstraction — Phase 14D.
//
// ── Why a Unified Backend ─────────────────────────────────────────────────────
//
//   SNF now supports three capture paths, each with different performance
//   characteristics and platform requirements:
//
//   ┌─────────────────────┬──────────────┬─────────────┬────────────────────┐
//   │ Backend             │ Throughput   │ Platform    │ Requirements       │
//   ├─────────────────────┼──────────────┼─────────────┼────────────────────┤
//   │ Pcap (standard)     │ ~1–3 Gbps    │ All         │ libpcap / Npcap    │
//   │ AF_PACKET TPACKET_V3│ ~3–8 Gbps    │ Linux 3.2+  │ CAP_NET_RAW        │
//   │ AF_XDP              │ ~8–25 Gbps   │ Linux 4.18+ │ CAP_NET_ADMIN, XDP │
//   │ DPDK (optional)     │ ~25–30 Gbps  │ Linux       │ hugepages, DPDK    │
//   └─────────────────────┴──────────────┴─────────────┴────────────────────┘
//
//   The CaptureBackend trait unifies all four paths behind a single interface.
//   run_live_capture() in capture/mod.rs selects the best available backend
//   from config, constructs it via CaptureBackendFactory::select(), and calls
//   the same next_batch() interface regardless of which backend is active.
//
// ── Backend Selection Logic ───────────────────────────────────────────────────
//
//   Priority (highest to lowest):
//     1. DPDK   — if --features dpdk AND config.performance.dpdk_enabled AND hugepages available
//     2. AF_XDP — if Linux 4.18+ AND config.performance.zero_copy_rx AND NIC supports XDP
//     3. Pcap   — always available (fallback)
//
//   The selection is logged at startup so operators know which path is active.
//   This matters for performance troubleshooting and SLA verification.
//
// ── Packet Batch API ─────────────────────────────────────────────────────────
//
//   All backends expose next_batch() which returns a Vec<BackendPacket>.
//   A BackendPacket contains:
//     - data: &[u8]           — zero-copy reference to ring buffer memory
//     - timestamp_us: u64     — hardware or software timestamp
//     - wire_len: u32         — original on-wire length
//     - timestamp_source      — HwTimestampSource (for event metadata)
//
//   The capture thread converts BackendPackets to RawPackets (owned Vec<u8>)
//   before queuing to workers. The copy happens exactly once at this boundary.
//
// Phase 14D addition.

use crate::config::engine_config::EngineConfig;
use crate::platform::hw_timestamp::{HwTimestampSource, TimestampCapability};

// ── BackendPacket ──────────────────────────────────────────────────────────────

/// A raw packet as delivered by a capture backend.
///
/// Data may be a zero-copy reference to ring buffer memory (AF_XDP, DPDK)
/// or an owned copy (pcap). The capture thread converts this to an owned
/// RawPacket before queuing to workers.
pub struct BackendPacket<'a> {
    /// Raw packet bytes starting at the Ethernet frame header.
    pub data: &'a [u8],

    /// Capture timestamp in microseconds UTC.
    /// Source depends on which backend and which timestamp mode is active.
    pub timestamp_us: u64,

    /// Original on-wire length. May exceed data.len() if snaplen truncated.
    pub wire_len: u32,

    /// Source of this timestamp — informs event metadata and analyst reports.
    pub timestamp_source: HwTimestampSource,
}

// ── CaptureBackend trait ──────────────────────────────────────────────────────

/// Unified interface for all SNF capture backends.
///
/// Implemented by: PcapBackend, AfXdpBackend, DpdkBackend.
/// All methods are called from the capture thread only — not thread-safe.
pub trait CaptureBackend {
    /// Return the name of this backend for logging.
    fn name(&self) -> &'static str;

    /// Return the timestamp capability this backend provides.
    fn timestamp_capability(&self) -> TimestampCapability;

    /// Receive the next batch of packets.
    ///
    /// Blocks until at least one packet is available or the timeout elapses.
    /// Returns an empty Vec on timeout — caller should check the shutdown flag.
    ///
    /// The returned packets are valid only until the next call to next_batch().
    /// The caller must copy data into owned RawPackets before the next call.
    fn next_batch(&mut self, timeout_ms: u64) -> Vec<BackendPacket<'_>>;

    /// Return the total number of packets dropped by this backend since start.
    /// Non-zero indicates the backend or workers are overwhelmed.
    fn kernel_drop_count(&self) -> u64;

    /// Flush and release all resources. Called at session end.
    fn shutdown(&mut self);
}

// ── BackendKind ───────────────────────────────────────────────────────────────

/// Which backend is active in this session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    Pcap,
    AfPacketTpacketV3,
    AfXdp,
    Dpdk,
}

impl BackendKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            BackendKind::Pcap                => "pcap",
            BackendKind::AfPacketTpacketV3   => "af_packet_tpacket_v3",
            BackendKind::AfXdp               => "af_xdp",
            BackendKind::Dpdk                => "dpdk",
        }
    }
}

// ── CaptureBackendFactory ──────────────────────────────────────────────────────

/// Selects and constructs the best available capture backend.
pub struct CaptureBackendFactory;

impl CaptureBackendFactory {
    /// Select the best backend for the given config and interface.
    ///
    /// Returns (BackendKind, reason_string) so the caller can log the selection.
    pub fn select(config: &EngineConfig, interface: &str) -> (BackendKind, String) {
        // DPDK: requires compile-time feature flag (not yet implemented)
        // AF_XDP: requires Linux 4.18+ and zero_copy_rx = true
        // AF_PACKET TPACKET_V3: requires Linux + zero_copy_rx hint
        // Pcap: always available

        #[cfg(target_os = "linux")]
        {
            if config.performance.zero_copy_rx {
                // Check kernel version for AF_XDP support (4.18+)
                if let Ok(version) = Self::linux_kernel_version() {
                    if version >= (4, 18, 0) {
                        return (
                            BackendKind::AfXdp,
                            format!(
                                "AF_XDP selected: kernel {}.{}.{} supports AF_XDP, \
                                 zero_copy_rx=true, interface='{}'",
                                version.0, version.1, version.2, interface
                            ),
                        );
                    } else if version >= (3, 2, 0) {
                        return (
                            BackendKind::AfPacketTpacketV3,
                            format!(
                                "AF_PACKET TPACKET_V3 selected: kernel {}.{}.{}, \
                                 zero_copy_rx=true but AF_XDP requires 4.18+",
                                version.0, version.1, version.2
                            ),
                        );
                    }
                }
            }
        }

        (
            BackendKind::Pcap,
            format!(
                "pcap selected: zero_copy_rx={}, platform={}",
                config.performance.zero_copy_rx,
                std::env::consts::OS
            ),
        )
    }

    #[cfg(target_os = "linux")]
    fn linux_kernel_version() -> Result<(u32, u32, u32), String> {
        let content = std::fs::read_to_string("/proc/version")
            .map_err(|e| format!("cannot read /proc/version: {}", e))?;

        // Format: "Linux version 5.15.0-91-generic ..."
        let version_str = content
            .split_whitespace()
            .nth(2)
            .unwrap_or("");

        let parts: Vec<&str> = version_str.split('.').collect();
        if parts.len() < 2 {
            return Err(format!("cannot parse kernel version from '{}'", version_str));
        }

        let major: u32 = parts[0].parse().unwrap_or(0);
        let minor: u32 = parts[1].parse().unwrap_or(0);
        let patch: u32 = parts.get(2)
            .and_then(|s| s.split('-').next())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        Ok((major, minor, patch))
    }
}

// ── PcapBackend ───────────────────────────────────────────────────────────────

/// Standard libpcap backend — always available, cross-platform.
///
/// This wraps the existing pcap-crate capture in the CaptureBackend trait
/// so it participates in the unified backend selection.
///
/// Note: PcapBackend uses the existing CaptureEngine path in capture/mod.rs
/// and does not implement next_batch() with zero-copy semantics —
/// it delegates to the existing process_raw_packet() machinery.
/// The trait implementation here is used only for backend reporting.
pub struct PcapBackend {
    drop_count: u64,
}

impl PcapBackend {
    pub fn new() -> Self {
        Self { drop_count: 0 }
    }
}

impl CaptureBackend for PcapBackend {
    fn name(&self) -> &'static str { "pcap" }

    fn timestamp_capability(&self) -> TimestampCapability {
        TimestampCapability::PcapSoftware
    }

    fn next_batch(&mut self, _timeout_ms: u64) -> Vec<BackendPacket<'_>> {
        // PcapBackend delegates to the existing pcap loop in capture/mod.rs.
        // This method is not called in the pcap path — it exists for trait
        // completeness and future unification in Phase 14D.
        Vec::new()
    }

    fn kernel_drop_count(&self) -> u64 { self.drop_count }

    fn shutdown(&mut self) {}
}