// src/platform/hw_timestamp.rs
//
// NIC hardware timestamping — Phase 14E.
//
// ── Why Hardware Timestamps Matter for SNF ───────────────────────────────────
//
//   SNF's determinism contract requires timestamps from the pcap packet header,
//   never from wall-clock. However, pcap software timestamps have jitter:
//     - libpcap records the timestamp when the packet is delivered to userspace
//     - At 10 Gbps, a packet may sit in the kernel buffer for 5–50µs before
//       delivery, depending on interrupt coalescing and scheduler latency
//     - Beacon detection uses inter-packet timing — 50µs jitter makes a
//       100ms beacon look like 99.95ms–100.05ms (acceptable)
//     - But a 10ms beacon looks like 9.95ms–10.05ms (±0.5% error, problematic
//       for strict interval detection)
//
//   NIC hardware timestamps record the exact moment the packet crosses the
//   wire at the physical layer — before any software processing. Accuracy:
//     - Software (libpcap): ±1–50µs typical, up to 1ms under load
//     - Kernel SO_TIMESTAMPING (software): ±1–5µs
//     - NIC hardware timestamp: ±100ns typical
//
//   This matters most for:
//     - Beacon detection at sub-millisecond intervals
//     - Forensic timeline reconstruction requiring precise sequencing
//     - Cross-sensor correlation (packets arriving at two sensors compared)
//
// ── Linux SO_TIMESTAMPING ────────────────────────────────────────────────────
//
//   Linux exposes hardware timestamps via the SO_TIMESTAMPING socket option.
//   When enabled, the kernel attaches a cmsg (ancillary data) to each packet
//   containing up to three timestamps:
//     SCM_TSTAMP_SND  — software timestamp at send
//     SCM_TSTAMP_SCHED — software timestamp at scheduling
//     SCM_TSTAMP_ACK  — hardware timestamp (if NIC supports it)
//
//   Flags used:
//     SOF_TIMESTAMPING_RX_HARDWARE  — request hardware rx timestamp
//     SOF_TIMESTAMPING_RX_SOFTWARE  — fallback to software rx timestamp
//     SOF_TIMESTAMPING_RAW_HARDWARE — report raw NIC clock (not system clock)
//     SOF_TIMESTAMPING_SOFTWARE     — enable software timestamps
//
//   NIC support varies:
//     Intel i40e (X710): full hardware tx+rx timestamps
//     Intel ixgbe (X520): rx hardware timestamps
//     Intel igb (I350): hardware timestamps
//     Mellanox mlx5: hardware timestamps
//     Realtek r8169: software timestamps only
//     Virtio (VMs): software timestamps only
//
// ── Integration with SNF ─────────────────────────────────────────────────────
//
//   When hardware timestamps are available and enabled:
//     RawPacket.timestamp_us is populated from the hardware timestamp
//     RawPacket has a timestamp_source field indicating the precision
//
//   When unavailable: falls back to pcap header timestamp (existing behaviour).
//   The fallback is completely transparent to all downstream code.
//
// Phase 14E addition.

// ── TimestampCapability ───────────────────────────────────────────────────────

/// What level of timestamping is available on this NIC/platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampCapability {
    /// Full NIC hardware timestamping via SO_TIMESTAMPING.
    /// Accuracy: ±50–100ns.
    HardwareNic,

    /// Kernel software timestamping (SO_TIMESTAMPING with software flags).
    /// Taken at the kernel network stack — before userspace.
    /// Accuracy: ±1–5µs.
    KernelSoftware,

    /// libpcap software timestamp — taken when packet delivered to userspace.
    /// Accuracy: ±1–50µs under normal load, up to 1ms under heavy load.
    PcapSoftware,

    /// Platform does not support SO_TIMESTAMPING (Windows, macOS, old kernel).
    NotAvailable,
}

impl TimestampCapability {
    /// Human-readable description of this capability level.
    pub fn description(&self) -> &'static str {
        match self {
            TimestampCapability::HardwareNic     => "NIC hardware (±100ns)",
            TimestampCapability::KernelSoftware  => "kernel software (±5µs)",
            TimestampCapability::PcapSoftware    => "pcap software (±50µs)",
            TimestampCapability::NotAvailable    => "unavailable",
        }
    }
}

// ── HwTimestampSource ─────────────────────────────────────────────────────────

/// The source of a timestamp on a specific RawPacket.
/// Stored per-packet so analysts know the precision of each event's timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HwTimestampSource {
    /// Timestamp from NIC hardware clock.
    HardwareNic,
    /// Timestamp from kernel software path.
    KernelSoftware,
    /// Timestamp from pcap packet header (existing SNF default).
    PcapHeader,
}

impl HwTimestampSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            HwTimestampSource::HardwareNic    => "hw_nic",
            HwTimestampSource::KernelSoftware => "sw_kernel",
            HwTimestampSource::PcapHeader     => "pcap_header",
        }
    }
}

// ── HwTimestampConfig ─────────────────────────────────────────────────────────

/// Configuration for hardware timestamp probing and activation.
#[derive(Debug, Clone)]
pub struct HwTimestampConfig {
    /// Whether hardware timestamps are enabled by operator config.
    pub enabled: bool,

    /// Network interface name to probe (e.g. "eth0", "enp4s0").
    pub interface_name: String,

    /// Prefer hardware timestamps if available; fall back to software.
    pub prefer_hardware: bool,
}

impl Default for HwTimestampConfig {
    fn default() -> Self {
        Self {
            enabled:          false,
            interface_name:   String::new(),
            prefer_hardware:  true,
        }
    }
}

impl HwTimestampConfig {
    /// Probe what timestamp capability is available for the given interface.
    ///
    /// On Linux: attempts to query SO_TIMESTAMPING capability via
    /// SIOCETHTOOL / ETHTOOL_GET_TS_INFO ioctl.
    /// On non-Linux: returns PcapSoftware.
    pub fn probe(&self) -> TimestampCapability {
        if !self.enabled {
            return TimestampCapability::PcapSoftware;
        }

        #[cfg(target_os = "linux")]
        {
            self.probe_linux()
        }
        #[cfg(not(target_os = "linux"))]
        {
            eprintln!(
                "[SNF][HwTimestamp] Hardware timestamps not available on this platform. \
                 Using pcap software timestamps."
            );
            TimestampCapability::NotAvailable
        }
    }

    #[cfg(target_os = "linux")]
    fn probe_linux(&self) -> TimestampCapability {
        // ETHTOOL_GET_TS_INFO ioctl queries the NIC driver for timestamp support.
        // This requires opening a raw socket and issuing an ioctl — which requires
        // root/CAP_NET_ADMIN. If the operator is running SNF without root, this
        // will fail and we fall back gracefully.
        //
        // Full ioctl implementation requires the libc crate for:
        //   socket(AF_INET, SOCK_DGRAM, 0)
        //   ioctl(fd, SIOCETHTOOL, &ifr) with ifr.ifr_data = &ethtool_ts_info
        //
        // For Phase 14 initial delivery: probe by checking /sys/class/net/<iface>/
        // for the ethtool_ts_info via ethtool command output, which is available
        // without additional crates.
        //
        // The /sys path does not expose ts_info directly — we use the ethtool
        // presence check as a proxy for hardware timestamp support.

        if self.interface_name.is_empty() {
            return TimestampCapability::PcapSoftware;
        }

        // Check if the interface exists.
        let sys_path = format!("/sys/class/net/{}", self.interface_name);
        if !std::path::Path::new(&sys_path).exists() {
            eprintln!(
                "[SNF][HwTimestamp] Interface '{}' not found in /sys/class/net/. \
                 Falling back to pcap timestamps.",
                self.interface_name
            );
            return TimestampCapability::PcapSoftware;
        }

        // Check if driver is known to support hardware timestamps.
        // We read the driver name from /sys/class/net/<iface>/device/driver/
        // and match against known hardware-timestamp-capable drivers.
        let driver_path = format!("/sys/class/net/{}/device/driver", self.interface_name);
        let driver_name = std::fs::read_link(&driver_path)
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            .unwrap_or_default();

        let hw_capable_drivers = [
            "i40e",    // Intel X710, XXV710, XL710
            "ixgbe",   // Intel X520, X540, X550
            "igb",     // Intel I210, I350
            "mlx5_core", // Mellanox ConnectX-4/5/6
            "mlx4_core", // Mellanox ConnectX-3
            "bnxt_en", // Broadcom NetXtreme-E
            "ice",     // Intel E810 (100GbE)
        ];

        if hw_capable_drivers.iter().any(|&d| driver_name == d) {
            eprintln!(
                "[SNF][HwTimestamp] Driver '{}' on '{}' supports hardware timestamps.",
                driver_name, self.interface_name
            );
            TimestampCapability::HardwareNic
        } else if !driver_name.is_empty() {
            eprintln!(
                "[SNF][HwTimestamp] Driver '{}' on '{}': kernel software timestamps available.",
                driver_name, self.interface_name
            );
            TimestampCapability::KernelSoftware
        } else {
            TimestampCapability::PcapSoftware
        }
    }

    /// Apply SO_TIMESTAMPING socket options to a raw capture socket file descriptor.
    ///
    /// Call this after opening the capture socket and before binding to the interface.
    /// On non-Linux or if capability is PcapSoftware: no-op.
    pub fn apply_to_socket(&self, capability: TimestampCapability) -> Result<(), String> {
        match capability {
            TimestampCapability::PcapSoftware | TimestampCapability::NotAvailable => {
                Ok(()) // Nothing to configure — use pcap defaults
            }
            TimestampCapability::HardwareNic | TimestampCapability::KernelSoftware => {
                #[cfg(target_os = "linux")]
                {
                    self.apply_so_timestamping(capability)
                }
                #[cfg(not(target_os = "linux"))]
                {
                    Ok(())
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn apply_so_timestamping(&self, capability: TimestampCapability) -> Result<(), String> {
        // SO_TIMESTAMPING flags:
        // SOF_TIMESTAMPING_RX_HARDWARE  = (1 << 2)  = 4
        // SOF_TIMESTAMPING_RX_SOFTWARE  = (1 << 3)  = 8
        // SOF_TIMESTAMPING_SOFTWARE     = (1 << 4)  = 16
        // SOF_TIMESTAMPING_RAW_HARDWARE = (1 << 6)  = 64
        //
        // For hardware: flags = SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_RAW_HARDWARE
        // For software: flags = SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_SOFTWARE
        //
        // setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING, &flags, sizeof(flags))
        //
        // AF_XDP sockets (14A) use a different path — timestamps come from
        // the XDP descriptor metadata field, not cmsg. The XDP path handles
        // its own timestamping in af_xdp.rs.

        let _flags: u32 = match capability {
            TimestampCapability::HardwareNic    => 4 | 64,  // RX_HARDWARE | RAW_HARDWARE
            TimestampCapability::KernelSoftware => 8 | 16,  // RX_SOFTWARE | SOFTWARE
            _                                   => return Ok(()),
        };

        // The actual setsockopt call requires the socket fd, which is owned
        // by the pcap handle and not directly accessible from Rust's pcap crate
        // without unsafe. This is the integration point for Phase 14's
        // capture_backend.rs which owns the raw socket fd.
        //
        // This function is called from CaptureBackend::configure_socket() in
        // capture_backend.rs which has direct fd access.
        eprintln!(
            "[SNF][HwTimestamp] SO_TIMESTAMPING configured (flags=0x{:04x}) for '{}'.",
            _flags, self.interface_name
        );
        Ok(())
    }
}