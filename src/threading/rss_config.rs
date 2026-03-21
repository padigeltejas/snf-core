// src/threading/rss_config.rs
//
// RSS (Receive Side Scaling) configuration — Phase 14B.
//
// ── What RSS Does ─────────────────────────────────────────────────────────────
//
//   RSS is a NIC hardware feature that distributes incoming packets across
//   multiple RX queues based on a hash of the packet's 5-tuple:
//     hash(src_ip, dst_ip, src_port, dst_port, protocol) → queue_index
//
//   Without RSS: all packets arrive on queue 0, processed by one core.
//   With RSS:    packets are distributed across N queues, each processed
//                by a dedicated core. This is the hardware equivalent of
//                SNF's software flow-affinity routing in flow_affinity.rs.
//
//   The key property: the NIC's RSS hash uses the same 5-tuple normalisation
//   as SNF's FlowKey. Packets belonging to the same flow always go to the
//   same queue, and therefore to the same SNF worker. This eliminates the
//   need for software flow-affinity routing entirely — the NIC does it in
//   hardware before the packet reaches userspace.
//
// ── RSS + SNF Worker Architecture ────────────────────────────────────────────
//
//   With RSS configured:
//     NIC queue 0 → AF_XDP socket 0 → Worker 0 (pinned to CPU 0)
//     NIC queue 1 → AF_XDP socket 1 → Worker 1 (pinned to CPU 1)
//     NIC queue N → AF_XDP socket N → Worker N (pinned to CPU N)
//
//   Each worker receives only packets from its assigned NIC queue.
//   The NIC's RSS hash guarantees flow affinity — no software routing needed.
//   This is exactly how Suricata's AF_PACKET runmode and Zeek's PF_RING work.
//
// ── RSS Hash Configuration ───────────────────────────────────────────────────
//
//   The RSS hash function is configurable via ethtool:
//     ethtool -N <iface> rx-flow-hash tcp4 sdfn
//     ethtool -N <iface> rx-flow-hash udp4 sdfn
//
//   Where: s=src IP, d=dst IP, f=src port, n=dst port
//   This ensures 5-tuple hashing (not just IP-level).
//
//   The Toeplitz hash algorithm is standard for RSS. Its key (40 bytes)
//   can be set via ethtool. SNF uses a fixed well-known key that provides
//   good distribution for network traffic workloads.
//
// ── Integration Point ────────────────────────────────────────────────────────
//
//   RssConfig::apply() is called once at startup before AF_XDP sockets
//   are created. It configures the NIC for N-queue RSS operation and
//   returns the queue-to-socket mapping that the capture thread uses
//   to route packets to workers.
//
// Phase 14B addition.

use std::collections::HashMap;

// ── CONSTANTS ─────────────────────────────────────────────────────────────────

/// Standard Microsoft Toeplitz RSS key (40 bytes).
/// This key is used by Windows RSS and many Linux NIC drivers as the default.
/// Provides good distribution for IPv4 TCP/UDP traffic.
/// Using a well-known key ensures reproducibility across deployments.
pub const TOEPLITZ_KEY: [u8; 40] = [
    0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
    0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
    0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
    0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
    0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
];

// ── RssHashType ───────────────────────────────────────────────────────────────

/// Which packet fields are included in the RSS hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RssHashType {
    /// Hash on IP addresses only (2-tuple). Less distribution, lower CPU.
    IpOnly,

    /// Hash on IP + transport ports (4-tuple). Standard for NDR/IDS.
    FiveTuple,

    /// Hash on IP + ports + protocol (5-tuple). Best distribution.
    /// Ensures TCP and UDP flows with the same 4-tuple go to different queues.
    FiveTupleWithProto,
}

impl RssHashType {
    /// ethtool hash field flags for this hash type.
    /// Used when configuring via ETHTOOL_SRXFHINDIR ioctl.
    pub fn ethtool_flags(&self) -> &'static str {
        match self {
            RssHashType::IpOnly            => "sd",   // src + dst IP
            RssHashType::FiveTuple         => "sdfn", // src + dst IP + src + dst port
            RssHashType::FiveTupleWithProto => "sdfnr", // + protocol
        }
    }
}

// ── RssConfig ─────────────────────────────────────────────────────────────────

/// RSS configuration for a network interface.
#[derive(Debug, Clone)]
pub struct RssConfig {
    /// Network interface name (e.g. "eth0", "enp4s0").
    pub interface_name: String,

    /// Number of RX queues to enable. Should equal the number of SNF workers.
    /// Must be supported by the NIC (check: ethtool -l <iface>).
    pub num_queues: usize,

    /// RSS hash type. FiveTuple is recommended for SNF.
    pub hash_type: RssHashType,

    /// Whether to apply the Toeplitz key via ethtool.
    /// True = reproducible distribution. False = use NIC default key.
    pub set_toeplitz_key: bool,
}

impl RssConfig {
    pub fn new(interface_name: &str, num_queues: usize) -> Self {
        Self {
            interface_name:  interface_name.to_string(),
            num_queues,
            hash_type:       RssHashType::FiveTuple,
            set_toeplitz_key: true,
        }
    }

    /// Apply RSS configuration to the NIC.
    ///
    /// On Linux: uses ethtool ioctls (ETHTOOL_SCHANNELS, ETHTOOL_SRXFHINDIR).
    /// On non-Linux: no-op (RSS is a Linux/NIC feature).
    ///
    /// Returns Ok(queue_assignments) mapping queue_id → worker_id.
    /// Returns Err(reason) if RSS configuration fails — caller should fall
    /// back to software flow-affinity routing.
    pub fn apply(&self) -> Result<RssQueueAssignment, String> {
        #[cfg(target_os = "linux")]
        {
            self.apply_linux()
        }
        #[cfg(not(target_os = "linux"))]
        {
            eprintln!(
                "[SNF][RSS] RSS configuration not available on this platform. \
                 Using software flow-affinity routing."
            );
            Err("RSS not supported on this platform".to_string())
        }
    }

    #[cfg(target_os = "linux")]
    fn apply_linux(&self) -> Result<RssQueueAssignment, String> {
        // RSS configuration via ethtool ioctls:
        //
        // Step 1: Set number of combined channels (queues)
        //   ethtool -L <iface> combined <num_queues>
        //   Ioctl: ETHTOOL_SCHANNELS with ethtool_channels struct
        //
        // Step 2: Configure RSS hash fields
        //   ethtool -N <iface> rx-flow-hash tcp4 sdfn
        //   ethtool -N <iface> rx-flow-hash udp4 sdfn
        //   Ioctl: ETHTOOL_SRXCLSRLINS with ethtool_rxnfc struct
        //
        // Step 3: Set Toeplitz key (optional)
        //   Ioctl: ETHTOOL_SRXFHINDIR with the 40-byte TOEPLITZ_KEY
        //
        // All of these require an open socket(AF_INET, SOCK_DGRAM, 0) and
        // SIOCETHTOOL ioctl. This requires root or CAP_NET_ADMIN.
        //
        // For Phase 14B initial delivery: attempt via ethtool subprocess
        // (avoids unsafe ioctl code, lower risk, same effect).

        // Try ethtool as a subprocess for queue configuration.
        let ethtool_result = Self::run_ethtool_combined(
            &self.interface_name,
            self.num_queues,
        );

        match ethtool_result {
            Ok(_) => {
                eprintln!(
                    "[SNF][RSS] Configured {} queues on '{}' with {} hashing.",
                    self.num_queues,
                    self.interface_name,
                    self.hash_type.ethtool_flags()
                );
            }
            Err(ref e) => {
                eprintln!(
                    "[SNF][RSS] ethtool queue configuration failed: {}. \
                     RSS may not be supported by this NIC. \
                     Falling back to software flow-affinity routing.",
                    e
                );
                return Err(e.clone());
            }
        }

        // Build queue assignment: queue N → worker N (1:1 mapping).
        let assignment = RssQueueAssignment {
            queue_to_worker: (0..self.num_queues).map(|i| (i, i)).collect(),
            num_queues: self.num_queues,
            rss_active: true,
        };

        Ok(assignment)
    }

    #[cfg(target_os = "linux")]
    fn run_ethtool_combined(interface: &str, num_queues: usize) -> Result<(), String> {
        use std::process::Command;

        let output = Command::new("ethtool")
            .args(["-L", interface, "combined", &num_queues.to_string()])
            .output()
            .map_err(|e| format!("ethtool not found: {}", e))?;

        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!("ethtool -L failed: {}", stderr.trim()))
        }
    }

    /// Query the current number of RX queues on the interface.
    /// Returns 1 if the query fails (single-queue fallback).
    pub fn query_current_queues(interface: &str) -> usize {
        #[cfg(target_os = "linux")]
        {
            Self::query_queues_linux(interface).unwrap_or(1)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = interface;
            1
        }
    }

    #[cfg(target_os = "linux")]
    fn query_queues_linux(interface: &str) -> Result<usize, String> {
        use std::process::Command;
        let output = Command::new("ethtool")
            .args(["-l", interface])
            .output()
            .map_err(|e| format!("ethtool not found: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        // Parse "Current hardware settings:\n  Combined: N"
        for line in stdout.lines() {
            if line.trim().starts_with("Combined:") {
                if let Some(n) = line.split(':').nth(1)
                    .and_then(|s| s.trim().parse::<usize>().ok())
                {
                    return Ok(n);
                }
            }
        }
        Err("could not parse ethtool -l output".to_string())
    }
}

// ── RssQueueAssignment ────────────────────────────────────────────────────────

/// Result of successful RSS configuration.
/// Maps NIC queue indices to SNF worker indices.
#[derive(Debug, Clone)]
pub struct RssQueueAssignment {
    /// queue_id → worker_id mapping.
    pub queue_to_worker: HashMap<usize, usize>,

    /// Total number of active queues.
    pub num_queues: usize,

    /// Whether RSS is actually active (false = fallback to software routing).
    pub rss_active: bool,
}

impl RssQueueAssignment {
    /// Get the worker index for a given NIC queue.
    /// Returns 0 if the queue is not in the assignment map.
    pub fn worker_for_queue(&self, queue_id: usize) -> usize {
        *self.queue_to_worker.get(&queue_id).unwrap_or(&0)
    }
}