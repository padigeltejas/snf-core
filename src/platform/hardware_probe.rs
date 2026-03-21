// src/platform/hardware_probe.rs
//
// Hardware auto-detection and config auto-tuning — Phase 14F.
//
// ── Purpose ──────────────────────────────────────────────────────────────────
//
//   SNF scales automatically from a laptop to a 10+ Gbps server NIC without
//   any operator configuration. This module probes available hardware at
//   startup and produces a HardwareProfile, which ConfigBuilder uses to
//   override performance defaults.
//
//   The probe-then-tune pattern:
//
//     1. HardwareProbe::run() called once at start of validate_and_build().
//     2. Returns a HardwareProfile describing CPU count, RAM, NUMA topology,
//        best capture backend, and NIC timestamp capability.
//     3. apply_hardware_profile() overwrites performance defaults with
//        hardware-scaled values, unless operator explicitly overrode them.
//
// ── Scaling Rules ────────────────────────────────────────────────────────────
//
//   worker_threads (PerformanceConfig):
//     Replay/Stealth: always 1
//     Others: max(1, available_cpus - 1), capped at 8
//
//   packet_batch_size (PerformanceConfig):
//     pcap: 32 / AF_PACKET: 128 / AF_XDP: 128 / DPDK: 256
//
//   ring_buffer_slots (CaptureConfig):
//     <2 GB RAM: 4096 / 2-4 GB: 8192 / 4-8 GB: 16384 / >8 GB: 32768
//
//   zero_copy_rx (PerformanceConfig):
//     Enabled automatically on Linux 4.18+ (AF_XDP available)
//
//   numa_enabled (PerformanceConfig):
//     Enabled when >1 NUMA node detected
//
//   hw_timestamps_enabled (PerformanceConfig):
//     Enabled when NIC driver supports hardware timestamps
//
// ── Platform Compatibility ───────────────────────────────────────────────────
//
//   All probes are wrapped in #[cfg] gates. Nothing panics on failure.
//   Unsupported platforms get conservative safe defaults.
//
// Phase 14F addition.

use crate::config::engine_config::EngineConfig;
use crate::config::mode::OperationMode;
use crate::platform::hw_timestamp::{HwTimestampConfig, TimestampCapability};
use crate::platform::numa::NumaTopology;
#[cfg(target_os = "linux")]
use crate::platform::core_affinity::get_available_cores;

// ── CaptureBackendKind ────────────────────────────────────────────────────────
//
// Local enum mirroring BackendKind from capture_backend.rs.
// Defined here to avoid a circular dependency: platform cannot import capture.

/// Which capture backend SNF will use on this system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureBackendKind {
    /// Standard libpcap — always available, cross-platform. ~1–3 Gbps.
    Pcap,
    /// AF_PACKET TPACKET_V3 ring buffer — Linux 3.2+, no special NIC. ~3–8 Gbps.
    AfPacketTpacketV3,
    /// AF_XDP zero-copy — Linux 4.18+, XDP-capable NIC driver. ~8–25 Gbps.
    AfXdp,
    /// DPDK kernel bypass — Linux, dedicated NIC + hugepages. ~25–30 Gbps.
    Dpdk,
}

impl CaptureBackendKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            CaptureBackendKind::Pcap               => "pcap",
            CaptureBackendKind::AfPacketTpacketV3  => "af_packet_tpacket_v3",
            CaptureBackendKind::AfXdp              => "af_xdp",
            CaptureBackendKind::Dpdk               => "dpdk",
        }
    }

    /// Throughput description for the startup log.
    pub fn throughput_hint(&self) -> &'static str {
        match self {
            CaptureBackendKind::Pcap               => "~1-3 Gbps",
            CaptureBackendKind::AfPacketTpacketV3  => "~3-8 Gbps",
            CaptureBackendKind::AfXdp              => "~8-25 Gbps",
            CaptureBackendKind::Dpdk               => "~25-30 Gbps",
        }
    }
}

// ── CaptureBackendAvailability ────────────────────────────────────────────────

/// Which capture backends are available and why the best was selected.
#[derive(Debug, Clone)]
pub struct CaptureBackendAvailability {
    /// Best backend available on this system.
    pub best: CaptureBackendKind,
    /// Human-readable reason for the selection.
    pub reason: String,
    /// Linux kernel version (0.0.0 on non-Linux).
    pub kernel_version: (u32, u32, u32),
}

// ── HardwareProfile ───────────────────────────────────────────────────────────

/// Complete hardware profile for this machine.
///
/// Produced once by HardwareProbe::run() at startup.
/// Used by apply_hardware_profile() to auto-tune defaults.
#[derive(Debug, Clone)]
pub struct HardwareProfile {
    // ---- CPU ----
    /// Number of logical CPU cores available to this process.
    pub available_cpus: usize,
    /// CPU architecture string (e.g. "x86_64", "aarch64").
    pub cpu_arch: &'static str,

    // ---- Memory ----
    /// Total system RAM in megabytes. 0 if detection failed.
    pub total_ram_mb: usize,
    /// Available (free + reclaimable) RAM in megabytes.
    pub available_ram_mb: usize,

    // ---- NUMA ----
    /// NUMA topology. is_numa=false on single-socket or non-Linux.
    pub numa: NumaTopology,

    // ---- Capture ----
    /// Best capture backend available on this platform.
    pub capture: CaptureBackendAvailability,

    // ---- Timestamps ----
    /// NIC hardware timestamp capability for the selected interface.
    pub timestamp_capability: TimestampCapability,

    // ---- Recommendations ----
    /// Recommended worker_threads for this hardware and mode.
    pub recommended_threads: usize,
    /// Recommended packet_batch_size for the selected backend.
    pub recommended_batch_size: usize,
    /// Recommended ring_buffer_slots scaled to available RAM.
    pub recommended_ring_buffer_slots: usize,
    /// Whether zero_copy_rx should be enabled.
    pub recommended_zero_copy_rx: bool,
    /// Whether numa_enabled should be set.
    pub recommended_numa: bool,
    /// Whether hw_timestamps_enabled should be set.
    pub recommended_hw_timestamps: bool,
}

impl HardwareProfile {
    /// Format a one-line summary for the startup log.
    pub fn summary(&self) -> String {
        format!(
            "Hardware: {} CPUs ({arch}), {ram} MB RAM, NUMA={numa}, \
             backend={backend} ({throughput}), timestamps={ts} \
             → {threads} workers / batch={batch} / ring={ring} / zero_copy={zc}",
            self.available_cpus,
            arch      = self.cpu_arch,
            ram       = self.total_ram_mb,
            numa      = if self.numa.is_numa { "yes" } else { "no" },
            backend   = self.capture.best.as_str(),
            throughput = self.capture.best.throughput_hint(),
            ts        = self.timestamp_capability.description(),
            threads   = self.recommended_threads,
            batch     = self.recommended_batch_size,
            ring      = self.recommended_ring_buffer_slots,
            zc        = self.recommended_zero_copy_rx,
        )
    }
}

// ── HardwareProbe ─────────────────────────────────────────────────────────────

/// Probes hardware capabilities and produces a HardwareProfile.
///
/// All probe methods are infallible — they return safe defaults on failure.
pub struct HardwareProbe;

impl HardwareProbe {
    /// Run a full hardware probe and return a HardwareProfile.
    ///
    /// Called once at the start of ConfigBuilder::validate_and_build().
    ///
    /// # Arguments
    /// * `config` — current config (used to read interface name for NIC probes)
    /// * `mode`   — operation mode (affects thread recommendation)
    pub fn run(config: &EngineConfig, mode: &OperationMode) -> HardwareProfile {
        // ---- CPU ----
        let available_cpus = Self::probe_cpu_count();
        let cpu_arch       = std::env::consts::ARCH;

        // ---- Memory ----
        let (total_ram_mb, available_ram_mb) = Self::probe_memory();

        // ---- NUMA ----
        let numa = NumaTopology::detect();

        // ---- Capture backend ----
        let interface_name = config.capture.interface_name
            .as_deref()
            .unwrap_or("eth0");
        let (best_backend, reason, kernel_version) =
            Self::probe_capture_backend(config, interface_name);

        let capture = CaptureBackendAvailability {
            best: best_backend,
            reason,
            kernel_version,
        };

        // ---- Timestamps ----
        let ts_config = HwTimestampConfig {
            enabled:         config.performance.hw_timestamps_enabled,
            interface_name:  interface_name.to_string(),
            prefer_hardware: true,
        };
        let timestamp_capability = ts_config.probe();

        // ---- Derive recommendations ----
        let recommended_threads           = Self::recommend_threads(available_cpus, mode);
        let recommended_batch_size        = Self::recommend_batch_size(&best_backend);
        let recommended_ring_buffer_slots = Self::recommend_ring_buffer_slots(available_ram_mb);
        let recommended_zero_copy_rx      = best_backend == CaptureBackendKind::AfXdp;
        let recommended_numa              = numa.is_numa;
        let recommended_hw_timestamps     = matches!(
            timestamp_capability,
            TimestampCapability::HardwareNic | TimestampCapability::KernelSoftware
        );

        HardwareProfile {
            available_cpus,
            cpu_arch,
            total_ram_mb,
            available_ram_mb,
            numa,
            capture,
            timestamp_capability,
            recommended_threads,
            recommended_batch_size,
            recommended_ring_buffer_slots,
            recommended_zero_copy_rx,
            recommended_numa,
            recommended_hw_timestamps,
        }
    }

    // ── CPU ────────────────────────────────────────────────────────────────

    fn probe_cpu_count() -> usize {
        #[cfg(target_os = "linux")]
        {
            // Reads /sys/devices/system/cpu/online — e.g. "0-7" = 8 cores.
            get_available_cores().len().max(1)
        }
        #[cfg(target_os = "windows")]
        {
            // GetSystemInfo fills a SYSTEM_INFO struct (48 bytes on x86_64).
            // dwNumberOfProcessors is at byte offset 32 (u32 little-endian).
            //
            // SYSTEM_INFO layout (x86_64 Windows):
            //   offset  0: union  (4 bytes) processor architecture
            //   offset  4: DWORD  dwPageSize
            //   offset  8: LPVOID lpMinimumApplicationAddress  (8 bytes)
            //   offset 16: LPVOID lpMaximumApplicationAddress  (8 bytes)
            //   offset 24: DWORD_PTR dwActiveProcessorMask     (8 bytes)
            //   offset 32: DWORD  dwNumberOfProcessors  ← want this
            //   offset 36: DWORD  dwProcessorType
            //   offset 40: DWORD  dwAllocationGranularity
            //   offset 44: WORD   wProcessorLevel
            //   offset 46: WORD   wProcessorRevision
            unsafe extern "system" {
                fn GetSystemInfo(lpSystemInfo: *mut u8);
            }
            let mut info = [0u8; 48];
            unsafe { GetSystemInfo(info.as_mut_ptr()) };
            let num_cpus = u32::from_le_bytes(
                info[32..36].try_into().unwrap_or([1, 0, 0, 0])
            );
            (num_cpus as usize).max(1)
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            1
        }
    }

    // ── Memory ────────────────────────────────────────────────────────────

    fn probe_memory() -> (usize, usize) {
        #[cfg(target_os = "linux")]
        {
            Self::probe_memory_linux().unwrap_or((0, 0))
        }
        #[cfg(target_os = "windows")]
        {
            Self::probe_memory_windows().unwrap_or((0, 0))
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            (0, 0)
        }
    }

    #[cfg(target_os = "linux")]
    fn probe_memory_linux() -> Result<(usize, usize), String> {
        // /proc/meminfo format:
        //   MemTotal:       16384000 kB
        //   MemAvailable:    8192000 kB
        let content = std::fs::read_to_string("/proc/meminfo")
            .map_err(|e| format!("cannot read /proc/meminfo: {}", e))?;

        let mut total_kb:     u64 = 0;
        let mut available_kb: u64 = 0;

        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 { continue; }
            match parts[0] {
                "MemTotal:"     => { total_kb     = parts[1].parse().unwrap_or(0); }
                "MemAvailable:" => { available_kb = parts[1].parse().unwrap_or(0); }
                _ => {}
            }
        }

        Ok((
            (total_kb     / 1024) as usize,
            (available_kb / 1024) as usize,
        ))
    }

    #[cfg(target_os = "windows")]
    fn probe_memory_windows() -> Result<(usize, usize), String> {
        // MEMORYSTATUSEX layout (64 bytes, little-endian):
        //   offset 0:  DWORD  dwLength (must = 64)
        //   offset 4:  DWORD  dwMemoryLoad
        //   offset 8:  DWORDLONG ullTotalPhys  ← total RAM bytes
        //   offset 16: DWORDLONG ullAvailPhys  ← available RAM bytes
        //   (remaining 40 bytes not needed)

        unsafe extern "system" {
            fn GlobalMemoryStatusEx(lpBuffer: *mut u8) -> i32;
        }

        let mut buf = [0u8; 64];
        // Set dwLength = 64 (required by the API)
        buf[0] = 64;

        let ret = unsafe { GlobalMemoryStatusEx(buf.as_mut_ptr()) };
        if ret == 0 {
            return Err("GlobalMemoryStatusEx returned 0".to_string());
        }

        let total_bytes = u64::from_le_bytes(
            buf[8..16].try_into().unwrap_or([0u8; 8])
        );
        let avail_bytes = u64::from_le_bytes(
            buf[16..24].try_into().unwrap_or([0u8; 8])
        );

        Ok((
            (total_bytes / (1024 * 1024)) as usize,
            (avail_bytes / (1024 * 1024)) as usize,
        ))
    }

    // ── Capture backend ────────────────────────────────────────────────────

    /// Probe the best available capture backend.
    ///
    /// Returns (backend, reason, kernel_version).
    ///
    /// Selection priority (highest to lowest):
    ///   1. AF_XDP  — Linux 4.18+ AND zero_copy_rx=true in config
    ///   2. AF_PACKET TPACKET_V3 — Linux 3.2+ AND zero_copy_rx=true
    ///   3. pcap   — always available (cross-platform fallback)
    ///
    /// DPDK is not auto-selected — it requires a compile-time feature flag
    /// and hugepage setup that cannot be detected at runtime safely.
    fn probe_capture_backend(
        config: &EngineConfig,
        interface: &str,
    ) -> (CaptureBackendKind, String, (u32, u32, u32)) {
        let kernel = Self::probe_kernel_version();

        #[cfg(target_os = "linux")]
        {
            if config.performance.zero_copy_rx {
                if kernel >= (4, 18, 0) {
                    return (
                        CaptureBackendKind::AfXdp,
                        format!(
                            "AF_XDP: kernel {}.{}.{} >= 4.18, zero_copy_rx=true, iface='{}'",
                            kernel.0, kernel.1, kernel.2, interface
                        ),
                        kernel,
                    );
                } else if kernel >= (3, 2, 0) {
                    return (
                        CaptureBackendKind::AfPacketTpacketV3,
                        format!(
                            "AF_PACKET TPACKET_V3: kernel {}.{}.{}, zero_copy_rx=true \
                             but AF_XDP requires 4.18+",
                            kernel.0, kernel.1, kernel.2
                        ),
                        kernel,
                    );
                }
            }
        }

        let _ = interface; // suppress unused warning on non-Linux

        (
            CaptureBackendKind::Pcap,
            format!(
                "pcap: zero_copy_rx={}, platform={}",
                config.performance.zero_copy_rx,
                std::env::consts::OS
            ),
            kernel,
        )
    }

    fn probe_kernel_version() -> (u32, u32, u32) {
        #[cfg(target_os = "linux")]
        {
            Self::probe_kernel_version_linux().unwrap_or((0, 0, 0))
        }
        #[cfg(not(target_os = "linux"))]
        {
            (0, 0, 0)
        }
    }

    #[cfg(target_os = "linux")]
    fn probe_kernel_version_linux() -> Result<(u32, u32, u32), String> {
        // /proc/version: "Linux version 5.15.0-91-generic ..."
        let content = std::fs::read_to_string("/proc/version")
            .map_err(|e| format!("cannot read /proc/version: {}", e))?;

        let version_str = content.split_whitespace().nth(2).unwrap_or("");
        let parts: Vec<&str> = version_str.split('.').collect();

        let major: u32 = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
        let minor: u32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let patch: u32 = parts.get(2)
            .and_then(|s| s.split('-').next())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        Ok((major, minor, patch))
    }

    // ── Recommendations ────────────────────────────────────────────────────

    /// Recommend worker_threads.
    ///
    /// Replay/Stealth: always 1.
    /// Others: max(1, cpus - 1), capped at 8.
    ///   Reserve 1 CPU for capture thread + OS.
    ///   Examples: 1 CPU→1, 2 CPUs→1, 4 CPUs→3, 8 CPUs→7, 16 CPUs→8
    fn recommend_threads(available_cpus: usize, mode: &OperationMode) -> usize {
    match mode {
        OperationMode::Replay  => 1,
        OperationMode::Stealth => 1,
        _ => {
            // ── Uncapped auto-scaling ─────────────────────────────────────────
            // Reserve 1 core for the capture thread and OS housekeeping.
            // Scale workers across all remaining cores with no upper bound.
            //
            // Scaling tiers (empirically tuned):
            //   1-2  cores  → 1 worker  (capture thread shares the core)
            //   3-4  cores  → cores - 1 (leave 1 for capture)
            //   5-8  cores  → cores - 1 (sweet spot for most hardware)
            //   9-16 cores  → cores - 2 (leave 2: capture + OS IRQ handling)
            //   17+  cores  → cores - 4 (leave 4: capture + IRQ + NUMA balance)
            //
            // Why no cap: on a 32-core server with an X710 NIC, all 28+ workers
            // can be fed by RSS multi-queue capture (one queue per worker).
            // Artificially capping at 8 wastes 20 cores on high-end hardware.
            //
            // Replay and Stealth are always forced to 1 above — determinism
            // and minimal footprint are non-negotiable for those modes.
            if available_cpus <= 2 {
                1
            } else if available_cpus <= 8 {
                available_cpus.saturating_sub(1)
            } else if available_cpus <= 16 {
                available_cpus.saturating_sub(2)
            } else {
                available_cpus.saturating_sub(4)
            }
        }
    }
}

    /// Recommend packet_batch_size for the selected backend.
    fn recommend_batch_size(backend: &CaptureBackendKind) -> usize {
    // Batch size determines how many packets each worker processes per loop.
    // Larger batches = better throughput (amortize scheduling overhead).
    // These are per-worker values — total system throughput = batch × workers.
    match backend {
        CaptureBackendKind::Pcap              =>  64,  // was 32 — pcap can handle larger batches
        CaptureBackendKind::AfPacketTpacketV3 => 256,  // ring buffer delivers in bulk naturally
        CaptureBackendKind::AfXdp             => 256,  // zero-copy, bulk delivery from UMEM
        CaptureBackendKind::Dpdk              => 512,  // DPDK polling mode, no syscall cost
    }
}

    /// Recommend ring_buffer_slots scaled to available RAM.
    ///
    /// Conservative scaling ensures SNF never exhausts system RAM.
    fn recommend_ring_buffer_slots(available_ram_mb: usize) -> usize {
        if available_ram_mb == 0 { return 4096; }
        match available_ram_mb {
            0..=1999    =>  4096,   // <2 GB  — VM / embedded
            2000..=3999 =>  8192,   // 2–4 GB — small server
            4000..=7999 => 16384,   // 4–8 GB — standard server
            _           => 32768,   // >8 GB  — high-throughput server
        }
    }
}

// ── apply_hardware_profile ────────────────────────────────────────────────────

/// Apply a HardwareProfile to an EngineConfig's performance and capture settings.
///
/// Only overwrites fields still at their factory defaults — operator CLI
/// overrides (applied before this call) are never overwritten.
///
/// Fields tuned:
///   - config.performance.worker_threads     (Replay/Stealth always forced to 1)
///   - config.performance.packet_batch_size
///   - config.performance.zero_copy_rx
///   - config.performance.numa_enabled
///   - config.performance.hw_timestamps_enabled
///   - config.capture.ring_buffer_slots      (lives on CaptureConfig, not Performance)
///
/// # Arguments
/// * `threads_explicit` — true when `--threads` was explicitly passed via CLI.
///   When true, worker_threads is never auto-scaled (operator's choice is final).
pub fn apply_hardware_profile(
    config:           &mut EngineConfig,
    profile:          &HardwareProfile,
    mode:             &OperationMode,
    threads_explicit: bool,
    no_auto_scale:    bool,
) {
    let perf    = &mut config.performance;
    let capture = &mut config.capture;

    // --- no_auto_scale: skip all probe tuning, use defaults as-is ---
    // Replay and Stealth still enforce single-threaded regardless.
    if no_auto_scale {
        match mode {
            OperationMode::Replay | OperationMode::Stealth => {
                perf.worker_threads = 1;
            }
            _ => {}
        }
        return;
    }

    // --- worker_threads ---
    // Replay and Stealth must always be 1 — enforce unconditionally.
    match mode {
        OperationMode::Replay | OperationMode::Stealth => {
            perf.worker_threads = 1;
        }
        _ => {
            // Only auto-scale if operator did NOT explicitly pass --threads.
            // If threads_explicit=true, the operator's value is final.
            if !threads_explicit && profile.recommended_threads > perf.worker_threads {
                perf.worker_threads = profile.recommended_threads;
            }
        }
    }

    // --- packet_batch_size --- (factory default = 32)
    if perf.packet_batch_size == 32 {
        perf.packet_batch_size = profile.recommended_batch_size;
    }

    // --- ring_buffer_slots --- (factory default = 4096, lives on CaptureConfig)
    if capture.ring_buffer_slots == 4096 {
        capture.ring_buffer_slots = profile.recommended_ring_buffer_slots;
    }

    // --- zero_copy_rx --- (factory default = false)
    if !perf.zero_copy_rx && profile.recommended_zero_copy_rx {
        perf.zero_copy_rx = true;
    }

    // --- numa_enabled --- (factory default = false)
    if !perf.numa_enabled && profile.recommended_numa {
        perf.numa_enabled = true;
    }

    // --- hw_timestamps_enabled --- (factory default = false)
    if !perf.hw_timestamps_enabled && profile.recommended_hw_timestamps {
        perf.hw_timestamps_enabled = true;
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recommend_threads_replay_always_one() {
        assert_eq!(HardwareProbe::recommend_threads(16, &OperationMode::Replay), 1);
        assert_eq!(HardwareProbe::recommend_threads(1,  &OperationMode::Replay), 1);
    }

    #[test]
    fn test_recommend_threads_stealth_always_one() {
        assert_eq!(HardwareProbe::recommend_threads(8, &OperationMode::Stealth), 1);
    }

    #[test]
    fn test_recommend_threads_scales_with_cpus() {
        assert_eq!(HardwareProbe::recommend_threads(1,  &OperationMode::Forensic), 1);
        assert_eq!(HardwareProbe::recommend_threads(2,  &OperationMode::Forensic), 1);
        assert_eq!(HardwareProbe::recommend_threads(4,  &OperationMode::Forensic), 3);
        assert_eq!(HardwareProbe::recommend_threads(8,  &OperationMode::Forensic), 7);
        assert_eq!(HardwareProbe::recommend_threads(16, &OperationMode::Forensic), 8);
    }

    #[test]
    fn test_recommend_ring_buffer_slots() {
        assert_eq!(HardwareProbe::recommend_ring_buffer_slots(0),     4096);
        assert_eq!(HardwareProbe::recommend_ring_buffer_slots(1024),  4096);
        assert_eq!(HardwareProbe::recommend_ring_buffer_slots(3000),  8192);
        assert_eq!(HardwareProbe::recommend_ring_buffer_slots(6000),  16384);
        assert_eq!(HardwareProbe::recommend_ring_buffer_slots(16000), 32768);
    }

    #[test]
    fn test_recommend_batch_size_per_backend() {
        assert_eq!(HardwareProbe::recommend_batch_size(&CaptureBackendKind::Pcap),              32);
        assert_eq!(HardwareProbe::recommend_batch_size(&CaptureBackendKind::AfPacketTpacketV3), 128);
        assert_eq!(HardwareProbe::recommend_batch_size(&CaptureBackendKind::AfXdp),             128);
        assert_eq!(HardwareProbe::recommend_batch_size(&CaptureBackendKind::Dpdk),              256);
    }

    #[test]
    fn test_apply_hardware_profile_replay_stays_one() {
        use crate::config::engine_config::EngineConfig;

        let mut config = EngineConfig::default();
        config.performance.worker_threads = 4; // somehow set to 4

        let profile = make_test_profile(8);

       apply_hardware_profile(&mut config, &profile, &OperationMode::Replay, false, false);

        assert_eq!(config.performance.worker_threads, 1);
    }

    #[test]
    fn test_apply_hardware_profile_scales_threads() {
        use crate::config::engine_config::EngineConfig;

        let mut config = EngineConfig::default();
        // forensic preset default = 1 worker
        config.performance.worker_threads = 1;

        let profile = make_test_profile(8); // 8 CPUs → 7 recommended

        apply_hardware_profile(&mut config, &profile, &OperationMode::Forensic, false, false);
        assert_eq!(config.performance.worker_threads, 7);
    }

    #[test]
    fn test_apply_hardware_profile_scales_ring_buffer() {
        use crate::config::engine_config::EngineConfig;

        let mut config = EngineConfig::default();
        // factory default ring_buffer_slots = 4096

        let mut profile = make_test_profile(4);
        profile.recommended_ring_buffer_slots = 16384;

        apply_hardware_profile(&mut config, &profile, &OperationMode::Monitor, false, false);
        assert_eq!(config.capture.ring_buffer_slots, 16384);
    }

    // ── Test helper ──────────────────────────────────────────────────────

    fn make_test_profile(cpus: usize) -> HardwareProfile {
        HardwareProfile {
            available_cpus:                cpus,
            cpu_arch:                      "x86_64",
            total_ram_mb:                  8192,
            available_ram_mb:              6000,
            numa:                          NumaTopology::detect(),
            capture:                       CaptureBackendAvailability {
                best:           CaptureBackendKind::Pcap,
                reason:         "test".to_string(),
                kernel_version: (0, 0, 0),
            },
            timestamp_capability:          TimestampCapability::PcapSoftware,
            recommended_threads:           cpus.saturating_sub(1).max(1).min(8),
            recommended_batch_size:        32,
            recommended_ring_buffer_slots: 16384,
            recommended_zero_copy_rx:      false,
            recommended_numa:              false,
            recommended_hw_timestamps:     false,
        }
    }

}
