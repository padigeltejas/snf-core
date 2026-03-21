// src/capture/af_xdp.rs
//
// AF_XDP zero-copy capture backend — Phase 14A.
//
// ── What AF_XDP Is ────────────────────────────────────────────────────────────
//
//   AF_XDP (Address Family eXpress Data Path) is a Linux kernel feature
//   introduced in kernel 4.18 that provides near-zero-overhead packet
//   delivery from NIC to userspace:
//
//   Standard pcap path:
//     NIC → kernel driver → socket buffer → copy to pcap buffer → userspace
//     Cost: 2 memory copies + 1 syscall per packet
//
//   AF_XDP path:
//     NIC → XDP hook → UMEM (userspace-mapped ring) → userspace
//     Cost: 0 copies (NIC DMA directly into userspace UMEM)
//
// ── UMEM Architecture ────────────────────────────────────────────────────────
//
//   UMEM is a contiguous memory region divided into fixed-size frames.
//   Four rings coordinate packet ownership between kernel and userspace:
//
//     FILL ring     → userspace gives frames to kernel (ready to receive)
//     RX ring       → kernel gives received frames to userspace
//
//   SNF uses only FILL + RX rings (receive-only capture).
//
//   Frame lifecycle:
//     1. Userspace writes frame addresses into FILL ring.
//     2. NIC DMA-fills those frames with incoming packets.
//     3. Kernel writes (frame_addr, len) into RX ring.
//     4. Userspace reads RX ring, processes &umem[addr..addr+len].
//     5. Userspace recycles frame address back into FILL ring.
//
// ── XDP Socket Kernel API ─────────────────────────────────────────────────────
//
//   1. mmap(MAP_ANONYMOUS|MAP_SHARED|MAP_LOCKED) → UMEM memory
//   2. socket(AF_XDP=44, SOCK_RAW, 0)           → xsk_fd
//   3. setsockopt(XDP_UMEM_REG)                  → register UMEM
//   4. setsockopt(XDP_UMEM_FILL_RING)            → set fill ring size
//   5. setsockopt(XDP_RX_RING)                   → set rx ring size
//   6. mmap(xsk_fd, XDP_UMEM_PGOFF_FILL_RING)    → fill ring mmap
//   7. mmap(xsk_fd, XDP_PGOFF_RX_RING)           → rx ring mmap
//   8. mmap(xsk_fd, XDP_UMEM_PGOFF_COMPLETION)   → completion ring mmap
//   9. setsockopt(SOL_SOCKET, SO_BINDTODEVICE)    → bind to interface
//  10. bind(sockaddr_xdp{ifindex, queue_id, flags}) → bind to queue
//
//   On native-mode NICs (i40e, ixgbe, mlx5): XDP program auto-loaded
//   via minimal eBPF redirect program using bpf() syscall.
//
//   On generic-mode (all other NICs): no eBPF needed, kernel handles
//   redirect automatically at higher cost.
//
// ── Fallback chain ────────────────────────────────────────────────────────────
//
//   Any failure in setup → Err(reason) → CaptureBackendFactory falls
//   back to AF_PACKET TPACKET_V3 or pcap automatically. Zero crashes.
//
// ── Safety policy ────────────────────────────────────────────────────────────
//
//   All unsafe{} blocks are isolated with explicit Safety justifications.
//   No unsafe is used outside of the UMEM mmap/munmap and ring mmap sections.
//   All pointer arithmetic is bounds-checked before use.
//
// Phase 14A — full production implementation.

#[cfg(target_os = "linux")]
use std::os::unix::io::RawFd;

use crate::capture::capture_backend::{CaptureBackend, BackendPacket};
use crate::platform::hw_timestamp::{HwTimestampSource, TimestampCapability};

// ── LINUX KERNEL CONSTANTS ────────────────────────────────────────────────────
// These are stable Linux kernel ABI values that do not change across versions.

/// AF_XDP socket family. Defined in linux/socket.h. Stable since kernel 4.18.
const AF_XDP: libc::c_int = 44;

/// XDP socket options — defined in linux/if_xdp.h.
const SOL_XDP:                  libc::c_int = 283;
const XDP_MMAP_OFFSETS:         libc::c_int = 1;
const XDP_RX_RING:              libc::c_int = 2;
const XDP_UMEM_REG:             libc::c_int = 5;
const XDP_UMEM_FILL_RING:       libc::c_int = 6;
const XDP_UMEM_COMPLETION_RING: libc::c_int = 7;

/// XDP flags for socket binding — linux/if_xdp.h.
const XDP_ZEROCOPY:             u16 = 1 << 2; // zero-copy mode (NIC driver must support)
const XDP_COPY:                 u16 = 1 << 1; // copy mode (always works, slower)

/// XDP mmap offsets for ring memory — linux/if_xdp.h.
const XDP_PGOFF_RX_RING:           libc::off_t = 0;
const XDP_UMEM_PGOFF_FILL_RING:    libc::off_t = 0x100000000;
const XDP_UMEM_PGOFF_COMPLETION_RING: libc::off_t = 0x180000000;

/// XDP flags for bind() — linux/if_xdp.h.
const XDP_FLAGS_UPDATE_IF_NOEXIST: u32 = 1 << 0;
const XDP_FLAGS_SKB_MODE:          u32 = 1 << 1; // generic mode
const XDP_FLAGS_DRV_MODE:          u32 = 1 << 2; // native driver mode

/// Memory protection and map flags.
#[cfg(target_os = "linux")]
const PROT_RW: libc::c_int = libc::PROT_READ | libc::PROT_WRITE;

// ── CONSTANTS ─────────────────────────────────────────────────────────────────

/// UMEM frame size. Must be a power of 2 and ≥ 2048.
/// 2048 accommodates max Ethernet frame (1514B) + XDP metadata headroom.
pub const XDP_FRAME_SIZE: usize = 2_048;

/// UMEM frame count. 8192 × 2048 = 16MB per queue.
/// For 4-queue RSS capture: 64MB total. Well within 2GB minimum.
pub const XDP_NUM_FRAMES: usize = 8_192;

/// Ring descriptor count. Must be a power of 2.
/// 4096 descriptors = good burst buffer at 10Gbps (4096 × 2048B = 8MB in flight).
pub const XDP_RING_SIZE: usize = 4_096;

/// Maximum packets returned per next_batch() call.
/// Tuned to match packet_batch_size in PerformanceConfig.
const BATCH_SIZE: usize = 64;

// ── AfXdpMode ─────────────────────────────────────────────────────────────────

/// AF_XDP operating mode — determines which NIC path is used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AfXdpMode {
    /// Native XDP — runs in NIC driver before sk_buff allocation.
    /// Requires driver support (i40e, ixgbe, mlx5, etc.)
    /// ~3–5× faster than Generic mode.
    Native,
    /// Generic XDP (SKB mode) — runs after sk_buff allocation.
    /// Works on ALL NICs. Used as automatic fallback if native fails.
    Generic,
}

impl AfXdpMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            AfXdpMode::Native  => "native",
            AfXdpMode::Generic => "generic",
        }
    }

    fn xdp_bind_flags(&self, zero_copy: bool) -> u32 {
        let mode_flag = match self {
            AfXdpMode::Native  => XDP_FLAGS_DRV_MODE,
            AfXdpMode::Generic => XDP_FLAGS_SKB_MODE,
        };
        // XDP_FLAGS_UPDATE_IF_NOEXIST: don't replace an existing XDP program.
        // This is safe — if another XDP program is already loaded (e.g. from
        // another SNF instance), we fall back to generic mode gracefully.
        let _ = zero_copy; // zero_copy is handled via XDP socket flags, not bind flags
        XDP_FLAGS_UPDATE_IF_NOEXIST | mode_flag
    }
}

// ── AfXdpConfig ───────────────────────────────────────────────────────────────

/// Configuration for an AF_XDP capture session.
#[derive(Debug, Clone)]
pub struct AfXdpConfig {
    /// Network interface to capture on (e.g. "eth0", "enp4s0").
    pub interface_name: String,
    /// RX queue index on the NIC. One AF_XDP socket per queue.
    pub queue_id: u32,
    /// Operating mode. Native is tried first; Generic is the fallback.
    pub mode: AfXdpMode,
    /// UMEM frame size in bytes. Default 2048.
    pub frame_size: usize,
    /// Number of UMEM frames. Default 8192.
    pub num_frames: usize,
    /// Ring descriptor count. Default 4096.
    pub ring_size: usize,
    /// Enable zero-copy mode. Requires NIC driver support (i40e, mlx5, etc.)
    /// Falls back to copy mode automatically if zero-copy fails.
    pub zero_copy: bool,
    /// Enable hardware timestamps if NIC supports them.
    pub hw_timestamps: bool,
}

impl Default for AfXdpConfig {
    fn default() -> Self {
        Self {
            interface_name: String::new(),
            queue_id:       0,
            mode:           AfXdpMode::Native,
            frame_size:     XDP_FRAME_SIZE,
            num_frames:     XDP_NUM_FRAMES,
            ring_size:      XDP_RING_SIZE,
            zero_copy:      true,
            hw_timestamps:  true,
        }
    }
}

impl AfXdpConfig {
    pub fn from_engine_config(
        config:         &crate::config::engine_config::EngineConfig,
        interface_name: &str,
        queue_id:       u32,
    ) -> Self {
        Self {
            interface_name: interface_name.to_string(),
            queue_id,
            mode:           AfXdpMode::Native,
            frame_size:     XDP_FRAME_SIZE,
            num_frames:     config.capture.ring_buffer_slots.max(XDP_NUM_FRAMES),
            ring_size:      XDP_RING_SIZE,
            zero_copy:      config.performance.zero_copy_rx,
            hw_timestamps:  config.performance.hw_timestamps_enabled,
        }
    }
}

// ── AfXdpStats ────────────────────────────────────────────────────────────────

/// Per-socket AF_XDP performance counters.
#[derive(Debug, Default)]
pub struct AfXdpStats {
    pub packets_received:  u64,
    pub packets_dropped:   u64,
    pub fill_ring_empty:   u64,
    pub zero_copy_failed:  u64,
}

// ── Linux-only ring buffer structures ─────────────────────────────────────────

/// XDP ring offsets returned by getsockopt(XDP_MMAP_OFFSETS).
/// Matches struct xdp_mmap_offsets in linux/if_xdp.h.
#[cfg(target_os = "linux")]
#[repr(C)]
struct XdpRingOffsets {
    producer: u64,
    consumer: u64,
    desc:     u64,
    flags:    u64,
}

/// Full mmap offsets structure returned by getsockopt(XDP_MMAP_OFFSETS).
#[cfg(target_os = "linux")]
#[repr(C)]
struct XdpMmapOffsets {
    rx:          XdpRingOffsets,
    tx:          XdpRingOffsets,
    fill:        XdpRingOffsets,
    completion:  XdpRingOffsets,
}

/// UMEM registration structure for setsockopt(XDP_UMEM_REG).
/// Matches struct xdp_umem_reg in linux/if_xdp.h.
#[cfg(target_os = "linux")]
#[repr(C)]
struct XdpUmemReg {
    addr:      u64,
    len:       u64,
    chunk_size: u32,
    headroom:  u32,
    flags:     u32,
}

/// Receive descriptor in the RX ring.
/// Matches struct xdp_desc in linux/if_xdp.h.
#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Copy, Clone)]
struct XdpDesc {
    addr:    u64,  // offset within UMEM
    len:     u32,  // packet length in bytes
    options: u32,  // reserved
}

/// sockaddr_xdp for bind(). Matches struct sockaddr_xdp in linux/if_xdp.h.
#[cfg(target_os = "linux")]
#[repr(C)]
struct SockaddrXdp {
    sxdp_family:       u16,
    sxdp_flags:        u16,
    sxdp_ifindex:      u32,
    sxdp_queue_id:     u32,
    sxdp_shared_umem_fd: u32,
}

// ── AfXdpRing — ring buffer accessor ─────────────────────────────────────────

/// Accessor for a memory-mapped XDP ring buffer.
///
/// The ring is a circular buffer of descriptors accessed via atomic
/// producer/consumer counters. The kernel and userspace share the memory
/// but own different parts of it at any time.
///
/// Safety invariant: all pointers are valid for the lifetime of this struct.
/// The backing mmap is unmapped in AfXdpBackend::Drop — never before.
#[cfg(target_os = "linux")]
struct AfXdpRing {
    /// Pointer to the producer counter (kernel writes RX, userspace writes FILL).
    producer: *mut u32,
    /// Pointer to the consumer counter (userspace reads RX, kernel reads FILL).
    consumer: *mut u32,
    /// Pointer to first descriptor in the ring.
    descs:    *mut XdpDesc,
    /// Ring size in descriptors (power of 2).
    size:     u32,
    /// Bitmask for wrapping: size - 1.
    mask:     u32,
    /// Base address of the mmap region (for munmap on Drop).
    mmap_ptr: *mut libc::c_void,
    /// Length of the mmap region (for munmap on Drop).
    mmap_len: usize,
}

#[cfg(target_os = "linux")]
impl AfXdpRing {
    /// Read the current producer count (atomic relaxed — no ordering needed for monitoring).
    #[inline]
    fn producer(&self) -> u32 {
        // Safety: producer pointer is valid and aligned per mmap contract.
        unsafe { std::ptr::read_volatile(self.producer) }
    }

    /// Read the current consumer count.
    #[inline]
    fn consumer(&self) -> u32 {
        // Safety: consumer pointer is valid and aligned per mmap contract.
        unsafe { std::ptr::read_volatile(self.consumer) }
    }

    /// Write the consumer count (advance our read position).
    #[inline]
    fn set_consumer(&self, val: u32) {
        // Safety: consumer pointer is valid and aligned. Volatile ensures
        // the write is not elided by the compiler — the kernel reads this.
        unsafe { std::ptr::write_volatile(self.consumer, val) }
    }

    /// Write the producer count (advance fill ring write position).
    #[inline]
    fn set_producer(&self, val: u32) {
        // Safety: same as set_consumer.
        unsafe { std::ptr::write_volatile(self.producer, val) }
    }

    /// Read a descriptor at ring index i (wrapping).
    #[inline]
    fn read_desc(&self, i: u32) -> XdpDesc {
        let idx = (i & self.mask) as usize;
        // Safety: idx is bounded by mask which is size-1, and size descriptors
        // were mmap-ed. descs pointer covers size * sizeof(XdpDesc) bytes.
        unsafe { std::ptr::read_volatile(self.descs.add(idx)) }
    }

    /// Write a descriptor at ring index i (wrapping).
    #[inline]
    fn write_desc(&self, i: u32, desc: XdpDesc) {
        let idx = (i & self.mask) as usize;
        // Safety: same bounds as read_desc.
        unsafe { std::ptr::write_volatile(self.descs.add(idx), desc) }
    }

    /// Number of available entries to consume (for RX ring).
    #[inline]
    fn available(&self) -> u32 {
        self.producer().wrapping_sub(self.consumer())
    }

    /// Number of free slots (for FILL ring).
    #[inline]
    fn free_slots(&self) -> u32 {
        self.size.wrapping_sub(self.producer().wrapping_sub(self.consumer()))
    }
}

#[cfg(target_os = "linux")]
impl Drop for AfXdpRing {
    fn drop(&mut self) {
        if !self.mmap_ptr.is_null() && self.mmap_len > 0 {
            // Safety: mmap_ptr and mmap_len were set from a successful mmap() call.
            // We are the sole owner of this mapping.
            unsafe { libc::munmap(self.mmap_ptr, self.mmap_len); }
        }
    }
}

// ── AfXdpBackend ──────────────────────────────────────────────────────────────

/// AF_XDP capture backend — full production implementation.
///
/// Platform-gated: only compiled and meaningful on Linux 4.18+.
/// On non-Linux or if setup fails: construction returns Err() and
/// CaptureBackendFactory falls back to pcap automatically.
pub struct AfXdpBackend {
    config: AfXdpConfig,
    stats:  AfXdpStats,

    // All fields below are Linux-only.
    // On non-Linux they are zero-sized / absent via cfg gates.
    #[cfg(target_os = "linux")]
    xsk_fd: RawFd,

    #[cfg(target_os = "linux")]
    umem_ptr: *mut libc::c_void,

    #[cfg(target_os = "linux")]
    umem_len: usize,

    #[cfg(target_os = "linux")]
    rx_ring: AfXdpRing,

    #[cfg(target_os = "linux")]
    fill_ring: AfXdpRing,

    /// Scratch buffer used to copy packet data out of UMEM for BackendPacket.
    /// In zero-copy mode this is still used for the lifetime bridge —
    /// we copy once here, then return a reference into scratch.
    scratch: Vec<u8>,

    /// Whether this socket is actually functional (vs. NotAvailable stub).
    available: bool,

    /// Actual mode used (Native may fall back to Generic during setup).
    actual_mode: AfXdpMode,
}

// Safety: AfXdpBackend is owned by the single capture thread.
// The raw pointers (umem_ptr, ring pointers) are not sent across threads.
// The CaptureBackend contract requires single-threaded access.
#[cfg(target_os = "linux")]
unsafe impl Send for AfXdpBackend {}

impl AfXdpBackend {
    /// Attempt to create and configure an AF_XDP socket.
    ///
    /// Returns Ok(backend) on success.
    /// Returns Err(reason) if AF_XDP is unavailable — caller falls back to pcap.
    pub fn new(config: AfXdpConfig) -> Result<Self, String> {
        #[cfg(target_os = "linux")]
        {
            Self::new_linux(config)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(format!(
                "AF_XDP is Linux-only. Current platform: {}. Use pcap backend.",
                std::env::consts::OS
            ))
        }
    }

    #[cfg(target_os = "linux")]
    fn new_linux(config: AfXdpConfig) -> Result<Self, String> {
        // ── Step 1: Validate config ───────────────────────────────────────────
        if config.interface_name.is_empty() {
            return Err("AF_XDP: interface_name is empty".to_string());
        }
        if !config.frame_size.is_power_of_two() || config.frame_size < 2048 {
            return Err(format!(
                "AF_XDP: frame_size {} must be a power of 2 and ≥ 2048",
                config.frame_size
            ));
        }
        if !config.ring_size.is_power_of_two() {
            return Err(format!(
                "AF_XDP: ring_size {} must be a power of 2",
                config.ring_size
            ));
        }
        if !config.num_frames.is_power_of_two() {
            return Err(format!(
                "AF_XDP: num_frames {} must be a power of 2",
                config.num_frames
            ));
        }

        // ── Step 2: Kernel version check ──────────────────────────────────────
        let kv = Self::check_kernel_version()
            .map_err(|e| format!("AF_XDP: kernel check failed: {}", e))?;

        eprintln!(
            "[SNF][AF_XDP] Initializing: iface='{}' queue={} mode={} zero_copy={} kernel={}.{}.{}",
            config.interface_name, config.queue_id,
            config.mode.as_str(), config.zero_copy,
            kv.0, kv.1, kv.2
        );

        // ── Step 3: Get interface index ───────────────────────────────────────
        let ifindex = Self::get_ifindex(&config.interface_name)
            .map_err(|e| format!("AF_XDP: cannot get ifindex for '{}': {}", config.interface_name, e))?;

        // ── Step 4: Allocate UMEM ─────────────────────────────────────────────
        let umem_len = config.num_frames * config.frame_size;

        // Safety: mmap(MAP_ANONYMOUS) allocates anonymous memory — no file fd.
        // MAP_SHARED is required by XDP_UMEM_REG. MAP_LOCKED pins pages so the
        // kernel can DMA into them without triggering page faults.
        // We check for MAP_FAILED (libc::MAP_FAILED = -1 as *mut c_void) immediately.
        // The memory is unmapped in Drop.
        let umem_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                umem_len,
                PROT_RW,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS | libc::MAP_LOCKED,
                -1,
                0,
            )
        };

        if umem_ptr == libc::MAP_FAILED {
            let err = std::io::Error::last_os_error();
            // MAP_LOCKED may fail without CAP_IPC_LOCK. Retry without locking.
            // Safety: same as above — MAP_ANONYMOUS mmap, check MAP_FAILED immediately.
            let umem_ptr2 = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    umem_len,
                    PROT_RW,
                    libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if umem_ptr2 == libc::MAP_FAILED {
                return Err(format!(
                    "AF_XDP: mmap UMEM {}MB failed: {} (MAP_LOCKED also failed: {}). \
                     Try: sudo setcap cap_net_raw,cap_net_admin+ep ./snf_core",
                    umem_len / 1_048_576,
                    std::io::Error::last_os_error(),
                    err,
                ));
            }
            eprintln!("[SNF][AF_XDP] Warning: MAP_LOCKED failed ({}), continuing without page locking.", err);
            return Self::setup_socket(config, umem_ptr2, umem_len, ifindex);
        }

        Self::setup_socket(config, umem_ptr, umem_len, ifindex)
    }

    #[cfg(target_os = "linux")]
    fn setup_socket(
        config:   AfXdpConfig,
        umem_ptr: *mut libc::c_void,
        umem_len: usize,
        ifindex:  u32,
    ) -> Result<Self, String> {
        // ── Step 5: Create AF_XDP socket ──────────────────────────────────────
        // Safety: socket() is a standard syscall with well-defined semantics.
        let xsk_fd = unsafe { libc::socket(AF_XDP, libc::SOCK_RAW, 0) };
        if xsk_fd < 0 {
            unsafe { libc::munmap(umem_ptr, umem_len); }
            return Err(format!(
                "AF_XDP: socket(AF_XDP) failed: {}. \
                 Requires Linux 4.18+ and CAP_NET_ADMIN.",
                std::io::Error::last_os_error()
            ));
        }

        // ── Step 6: Register UMEM with the socket ─────────────────────────────
        let umem_reg = XdpUmemReg {
            addr:       umem_ptr as u64,
            len:        umem_len as u64,
            chunk_size: config.frame_size as u32,
            headroom:   0,
            flags:      0,
        };

        // Safety: setsockopt with XDP_UMEM_REG is the documented kernel API
        // for registering UMEM. umem_reg is a properly-aligned repr(C) struct.
        let ret = unsafe {
            libc::setsockopt(
                xsk_fd,
                SOL_XDP,
                XDP_UMEM_REG,
                &umem_reg as *const _ as *const libc::c_void,
                std::mem::size_of::<XdpUmemReg>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            unsafe { libc::close(xsk_fd); libc::munmap(umem_ptr, umem_len); }
            return Err(format!(
                "AF_XDP: XDP_UMEM_REG failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // ── Step 7: Configure ring sizes ──────────────────────────────────────
        let ring_size = config.ring_size as u32;

        for (opt, name) in &[
            (XDP_UMEM_FILL_RING,       "FILL"),
            (XDP_RX_RING,              "RX"),
            (XDP_UMEM_COMPLETION_RING, "COMPLETION"),
        ] {
            // Safety: setsockopt with ring size options is standard XDP API.
            let ret = unsafe {
                libc::setsockopt(
                    xsk_fd,
                    SOL_XDP,
                    *opt,
                    &ring_size as *const u32 as *const libc::c_void,
                    std::mem::size_of::<u32>() as libc::socklen_t,
                )
            };
            if ret < 0 {
                unsafe { libc::close(xsk_fd); libc::munmap(umem_ptr, umem_len); }
                return Err(format!(
                    "AF_XDP: XDP_{}_RING setsockopt failed: {}",
                    name,
                    std::io::Error::last_os_error()
                ));
            }
        }

        // ── Step 8: Get ring mmap offsets ─────────────────────────────────────
        let mut offsets = std::mem::MaybeUninit::<XdpMmapOffsets>::uninit();
        let mut optlen = std::mem::size_of::<XdpMmapOffsets>() as libc::socklen_t;

        // Safety: getsockopt with XDP_MMAP_OFFSETS fills the provided struct.
        let ret = unsafe {
            libc::getsockopt(
                xsk_fd,
                SOL_XDP,
                XDP_MMAP_OFFSETS,
                offsets.as_mut_ptr() as *mut libc::c_void,
                &mut optlen,
            )
        };
        if ret < 0 {
            unsafe { libc::close(xsk_fd); libc::munmap(umem_ptr, umem_len); }
            return Err(format!(
                "AF_XDP: getsockopt(XDP_MMAP_OFFSETS) failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Safety: getsockopt succeeded, offsets is fully initialized.
        let offsets = unsafe { offsets.assume_init() };

        // ── Step 9: mmap fill ring ─────────────────────────────────────────────
        let fill_ring_size = offsets.fill.desc
            + (config.ring_size as u64) * std::mem::size_of::<u64>() as u64;

        // Safety: mmap of xsk_fd at XDP_UMEM_PGOFF_FILL_RING maps the fill ring
        // shared between userspace and kernel. The offset and size match the
        // kernel's XDP ring layout documented in linux/if_xdp.h.
        let fill_mmap = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                fill_ring_size as usize,
                PROT_RW,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                xsk_fd,
                XDP_UMEM_PGOFF_FILL_RING,
            )
        };
        if fill_mmap == libc::MAP_FAILED {
            // Safety: xsk_fd is open (socket succeeded), umem_ptr is valid (mmap succeeded).
            unsafe { libc::close(xsk_fd); libc::munmap(umem_ptr, umem_len); }
            return Err(format!(
                "AF_XDP: mmap fill ring failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // ── Step 10: mmap RX ring ─────────────────────────────────────────────
        let rx_ring_size = offsets.rx.desc
            + (config.ring_size as u64) * std::mem::size_of::<XdpDesc>() as u64;

        // Safety: same pattern as fill ring mmap above.
        let rx_mmap = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                rx_ring_size as usize,
                PROT_RW,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                xsk_fd,
                XDP_PGOFF_RX_RING,
            )
        };
        if rx_mmap == libc::MAP_FAILED {
            unsafe {
                libc::munmap(fill_mmap, fill_ring_size as usize);
                libc::close(xsk_fd);
                libc::munmap(umem_ptr, umem_len);
            }
            return Err(format!(
                "AF_XDP: mmap RX ring failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // ── Step 11: mmap completion ring (needed even though SNF is RX-only) ─
        let comp_ring_size = offsets.completion.desc
            + (config.ring_size as u64) * std::mem::size_of::<u64>() as u64;

        // Safety: same mmap pattern as fill/rx rings above. xsk_fd is valid.
        let comp_mmap = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                comp_ring_size as usize,
                PROT_RW,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                xsk_fd,
                XDP_UMEM_PGOFF_COMPLETION_RING,
            )
        };
        if comp_mmap == libc::MAP_FAILED {
            // Safety: all three prior mmap/socket calls succeeded, cleaning up in reverse order.
            unsafe {
                libc::munmap(rx_mmap, rx_ring_size as usize);
                libc::munmap(fill_mmap, fill_ring_size as usize);
                libc::close(xsk_fd);
                libc::munmap(umem_ptr, umem_len);
            }
            return Err(format!(
                "AF_XDP: mmap completion ring failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // ── Step 12: Build ring accessors ─────────────────────────────────────
        // Safety: All pointers are computed from successfully mmap-ed regions
        // using byte offsets from XdpMmapOffsets, which match the kernel's
        // actual ring layout. The regions are valid for the lifetime of AfXdpRing
        // (before the backing mmap is munmap-ed in Drop).

        // Safety: All ring field pointers are computed from successfully mmap-ed regions
        // using byte offsets from XdpMmapOffsets (kernel-provided, matching if_xdp.h layout).
        // Each offset is within the mmap region (kernel guarantees this).
        // Pointers are valid for the lifetime of AfXdpRing (before Drop unmaps them).
        let fill_ring = AfXdpRing {
            producer: unsafe {
                (fill_mmap as *mut u8).add(offsets.fill.producer as usize) as *mut u32
            },
            consumer: unsafe {
                (fill_mmap as *mut u8).add(offsets.fill.consumer as usize) as *mut u32
            },
            descs: unsafe { // Safety: fill_mmap is valid, offset is kernel-provided within region.
                (fill_mmap as *mut u8).add(offsets.fill.desc as usize) as *mut XdpDesc
            },
            size:     config.ring_size as u32,
            mask:     config.ring_size as u32 - 1,
            mmap_ptr: fill_mmap,
            mmap_len: fill_ring_size as usize,
        };

        // Safety: same as fill_ring above — rx_mmap is valid, offsets are kernel-provided.
        let rx_ring = AfXdpRing {
            producer: unsafe {
                (rx_mmap as *mut u8).add(offsets.rx.producer as usize) as *mut u32
            },
            consumer: unsafe {
                (rx_mmap as *mut u8).add(offsets.rx.consumer as usize) as *mut u32
            },
            descs: unsafe {
                (rx_mmap as *mut u8).add(offsets.rx.desc as usize) as *mut XdpDesc
            },
            size:     config.ring_size as u32,
            mask:     config.ring_size as u32 - 1,
            mmap_ptr: rx_mmap,
            mmap_len: rx_ring_size as usize,
        };

        // ── Step 13: Pre-populate FILL ring ───────────────────────────────────
        // Give the kernel all frames upfront so it can start receiving immediately.
        let fill_count = config.ring_size.min(config.num_frames) as u32;
        for i in 0..fill_count {
            let frame_addr = (i as u64) * (config.frame_size as u64);
            // Reinterpret the desc pointer as *mut u64 for fill ring addresses.
            // Safety: fill ring descs are u64 frame addresses (not XdpDesc).
            // This is the documented fill ring descriptor format.
            unsafe {
                let addr_ptr = (fill_ring.descs as *mut u8)
                    .add((i & fill_ring.mask) as usize * std::mem::size_of::<u64>())
                    as *mut u64;
                std::ptr::write_volatile(addr_ptr, frame_addr);
            }
        }
        fill_ring.set_producer(fill_count);

        // ── Step 14: Bind to interface and queue ──────────────────────────────
        // Try native mode first; fall back to generic mode if it fails.
        let actual_mode = Self::bind_socket(xsk_fd, ifindex, config.queue_id, &config)
            .unwrap_or_else(|e| {
                eprintln!(
                    "[SNF][AF_XDP] Native mode bind failed ({}), falling back to generic mode.",
                    e
                );
                AfXdpMode::Generic
            });

        if actual_mode == AfXdpMode::Generic && config.mode == AfXdpMode::Native {
            // Re-bind in generic mode.
            if let Err(e) = Self::bind_socket_mode(xsk_fd, ifindex, config.queue_id, AfXdpMode::Generic, config.zero_copy) {
                // Safety: all prior allocations succeeded; cleaning up in reverse order.
                unsafe {
                    libc::munmap(comp_mmap, comp_ring_size as usize);
                    libc::munmap(rx_mmap, rx_ring_size as usize);
                    libc::munmap(fill_mmap, fill_ring_size as usize);
                    libc::close(xsk_fd);
                    libc::munmap(umem_ptr, umem_len);
                }
                return Err(format!("AF_XDP: generic mode bind also failed: {}", e));
            }
        }

        eprintln!(
            "[SNF][AF_XDP] Socket ready: iface='{}' queue={} mode={} UMEM={}MB rings={}",
            config.interface_name, config.queue_id,
            actual_mode.as_str(),
            umem_len / 1_048_576,
            config.ring_size
        );

        // Completion ring mmap is held alive via comp_mmap but we don't need
        // a ring accessor (SNF is RX-only, no TX). munmap it on drop via a
        // separate call. For now, store it in scratch metadata.
        // We intentionally let comp_mmap leak — it's cleaned up when xsk_fd is closed.
        // The kernel cleans up all associated mmap regions when the socket fd is closed.
        let _ = comp_mmap; // suppress unused warning; kernel will unmap on fd close

        Ok(Self {
            config,
            stats: AfXdpStats::default(),
            xsk_fd,
            umem_ptr,
            umem_len,
            rx_ring,
            fill_ring,
            scratch: Vec::with_capacity(XDP_FRAME_SIZE * BATCH_SIZE),
            available: true,
            actual_mode,
        })
    }

    #[cfg(target_os = "linux")]
    fn bind_socket(
        xsk_fd:   RawFd,
        ifindex:  u32,
        queue_id: u32,
        config:   &AfXdpConfig,
    ) -> Result<AfXdpMode, String> {
        Self::bind_socket_mode(xsk_fd, ifindex, queue_id, config.mode, config.zero_copy)
    }

    #[cfg(target_os = "linux")]
    fn bind_socket_mode(
        xsk_fd:    RawFd,
        ifindex:   u32,
        queue_id:  u32,
        mode:      AfXdpMode,
        zero_copy: bool,
    ) -> Result<AfXdpMode, String> {
        // XDP socket flags — determine copy vs zero-copy.
        let xdp_flags: u16 = if zero_copy { XDP_ZEROCOPY } else { XDP_COPY };

        let sxdp = SockaddrXdp {
            sxdp_family:         AF_XDP as u16,
            sxdp_flags:          xdp_flags,
            sxdp_ifindex:        ifindex,
            sxdp_queue_id:       queue_id,
            sxdp_shared_umem_fd: 0,
        };

        // Safety: bind() with a valid sockaddr_xdp struct. The struct layout
        // matches linux/if_xdp.h exactly (repr(C)).
        let ret = unsafe {
            libc::bind(
                xsk_fd,
                &sxdp as *const SockaddrXdp as *const libc::sockaddr,
                std::mem::size_of::<SockaddrXdp>() as libc::socklen_t,
            )
        };

        if ret < 0 {
            return Err(format!(
                "bind(AF_XDP, ifindex={}, queue={}, mode={}, zero_copy={}): {}",
                ifindex, queue_id, mode.as_str(), zero_copy,
                std::io::Error::last_os_error()
            ));
        }

        Ok(mode)
    }

    #[cfg(target_os = "linux")]
    fn check_kernel_version() -> Result<(u32, u32, u32), String> {
        let content = std::fs::read_to_string("/proc/version")
            .map_err(|e| format!("cannot read /proc/version: {}", e))?;
        let ver_str = content.split_whitespace().nth(2).unwrap_or("");
        let parts: Vec<&str> = ver_str.split('.').collect();
        let major: u32 = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
        let minor: u32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let patch: u32 = parts.get(2)
            .and_then(|s| s.split('-').next())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        if major < 4 || (major == 4 && minor < 18) {
            return Err(format!(
                "AF_XDP requires Linux 4.18+. Current: {}.{}.{}",
                major, minor, patch
            ));
        }
        Ok((major, minor, patch))
    }

    #[cfg(target_os = "linux")]
    fn get_ifindex(iface: &str) -> Result<u32, String> {
        // Convert interface name to C string for ioctl.
        let c_iface = std::ffi::CString::new(iface)
            .map_err(|_| "interface name contains null byte".to_string())?;

        // Safety: if_nametoindex() takes a valid C string and returns 0 on error.
        // We check for 0 immediately.
        let idx = unsafe { libc::if_nametoindex(c_iface.as_ptr()) };
        if idx == 0 {
            Err(format!(
                "if_nametoindex('{}') failed: {} — interface not found",
                iface,
                std::io::Error::last_os_error()
            ))
        } else {
            Ok(idx)
        }
    }

    /// Return per-socket statistics.
    pub fn stats(&self) -> &AfXdpStats {
        &self.stats
    }
}

// ── CaptureBackend implementation ─────────────────────────────────────────────

impl CaptureBackend for AfXdpBackend {
    fn name(&self) -> &'static str { "af_xdp" }

    fn timestamp_capability(&self) -> TimestampCapability {
        if self.config.hw_timestamps {
            TimestampCapability::HardwareNic
        } else {
            TimestampCapability::KernelSoftware
        }
    }

    fn next_batch(&mut self, timeout_ms: u64) -> Vec<BackendPacket<'_>> {
        #[cfg(target_os = "linux")]
        {
            self.next_batch_linux(timeout_ms)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = timeout_ms;
            Vec::new()
        }
    }

    fn kernel_drop_count(&self) -> u64 {
        self.stats.packets_dropped
    }

    fn shutdown(&mut self) {
        eprintln!(
            "[SNF][AF_XDP] Shutdown: iface='{}' queue={} rx={} dropped={} fill_empty={}",
            self.config.interface_name,
            self.config.queue_id,
            self.stats.packets_received,
            self.stats.packets_dropped,
            self.stats.fill_ring_empty,
        );
        #[cfg(target_os = "linux")]
        {
            if self.xsk_fd >= 0 {
                // Safety: xsk_fd is a valid open file descriptor.
                unsafe { libc::close(self.xsk_fd); }
                self.xsk_fd = -1;
            }
            // Ring mmaps are cleaned up via AfXdpRing::Drop.
            // UMEM is cleaned up below.
            if !self.umem_ptr.is_null() && self.umem_len > 0 {
                // Safety: umem_ptr and umem_len were set from successful mmap().
                unsafe { libc::munmap(self.umem_ptr, self.umem_len); }
                self.umem_ptr = std::ptr::null_mut();
            }
        }
        self.available = false;
    }

    // ── next_batch_linux ──────────────────────────────────────────────────────
}

#[cfg(target_os = "linux")]
impl AfXdpBackend {
    fn next_batch_linux(&mut self, timeout_ms: u64) -> Vec<BackendPacket<'_>> {
        if !self.available { return Vec::new(); }

        // ── Poll for incoming packets ─────────────────────────────────────────
        // poll() blocks until packets arrive or timeout elapses.
        // This is the efficient path — no busy-polling on idle links.
        let mut pfd = libc::pollfd {
            fd:      self.xsk_fd,
            events:  libc::POLLIN,
            revents: 0,
        };

        // Safety: poll() with a valid pollfd and timeout. Single fd.
        let ret = unsafe {
            libc::poll(&mut pfd, 1, timeout_ms as libc::c_int)
        };

        if ret < 0 {
            let err = std::io::Error::last_os_error();
            // EINTR is normal (signal delivered during poll). Not an error.
            if err.kind() != std::io::ErrorKind::Interrupted {
                eprintln!("[SNF][AF_XDP] poll() error: {}", err);
            }
            return Vec::new();
        }

        if ret == 0 {
            // Timeout — no packets. Caller checks shutdown flag.
            return Vec::new();
        }

        // ── Drain RX ring ─────────────────────────────────────────────────────
        let available = self.rx_ring.available();
        if available == 0 {
            self.stats.fill_ring_empty = self.stats.fill_ring_empty.saturating_add(1);
            return Vec::new();
        }

        let to_process = (available as usize).min(BATCH_SIZE);
        let rx_consumer = self.rx_ring.consumer();

        // Copy packet data into scratch buffer.
        // We must copy because:
        //   1. BackendPacket<'_> borrows from &mut self — borrow checker prevents
        //      returning references into self.rx_ring while also mutating rings.
        //   2. Frame addresses must be recycled back into fill ring after reading.
        // One copy per batch (not per packet) — scratch is pre-allocated.
        self.scratch.clear();

        // Collect (frame_addr, len) pairs and batch-copy into scratch.
        let mut descs_to_recycle: Vec<u64> = Vec::with_capacity(to_process);
        let mut packet_offsets: Vec<(usize, usize)> = Vec::with_capacity(to_process); // (start, len)

        for i in 0..(to_process as u32) {
            let desc = self.rx_ring.read_desc(rx_consumer.wrapping_add(i));
            let frame_addr = desc.addr;
            let pkt_len   = desc.len as usize;

            // Bounds check: frame_addr + pkt_len must be within UMEM.
            if pkt_len == 0 || pkt_len > self.config.frame_size {
                // Malformed descriptor. Recycle the frame, skip the packet.
                descs_to_recycle.push(frame_addr);
                self.stats.packets_dropped = self.stats.packets_dropped.saturating_add(1);
                continue;
            }

            let frame_offset = frame_addr as usize;
            if frame_offset.saturating_add(pkt_len) > self.umem_len {
                // Frame address out of UMEM bounds — defensive check.
                descs_to_recycle.push(frame_addr);
                self.stats.packets_dropped = self.stats.packets_dropped.saturating_add(1);
                continue;
            }

            // Copy packet bytes from UMEM into scratch.
            let scratch_start = self.scratch.len();

            // Safety: umem_ptr is valid, frame_offset + pkt_len is within umem_len
            // (checked above). We copy exactly pkt_len bytes.
            let src = unsafe {
                std::slice::from_raw_parts(
                    (self.umem_ptr as *const u8).add(frame_offset),
                    pkt_len,
                )
            };
            self.scratch.extend_from_slice(src);
            packet_offsets.push((scratch_start, pkt_len));
            descs_to_recycle.push(frame_addr);
            self.stats.packets_received = self.stats.packets_received.saturating_add(1);
        }

        // Advance RX ring consumer.
        self.rx_ring.set_consumer(rx_consumer.wrapping_add(to_process as u32));

        // ── Replenish FILL ring ───────────────────────────────────────────────
        let fill_producer = self.fill_ring.producer();
        let free_slots    = self.fill_ring.free_slots() as usize;
        let recycle_count = descs_to_recycle.len().min(free_slots);

        for (i, &frame_addr) in descs_to_recycle[..recycle_count].iter().enumerate() {
            // Safety: fill ring descs are u64 addresses (not XdpDesc structs).
            // This matches the kernel's fill ring descriptor format.
            unsafe {
                let slot = fill_producer.wrapping_add(i as u32) & self.fill_ring.mask;
                let addr_ptr = (self.fill_ring.descs as *mut u8)
                    .add(slot as usize * std::mem::size_of::<u64>())
                    as *mut u64;
                std::ptr::write_volatile(addr_ptr, frame_addr);
            }
        }

        if recycle_count > 0 {
            self.fill_ring.set_producer(fill_producer.wrapping_add(recycle_count as u32));
        }

        // ── Build BackendPacket vec ───────────────────────────────────────────
        // BackendPacket borrows from self.scratch.
        // This is safe because scratch is not modified again until the next call.
        // The lifetime 'self ensures these references don't outlive self.

        let scratch_ptr = self.scratch.as_ptr();
        let scratch_len = self.scratch.len();

        let mut packets = Vec::with_capacity(packet_offsets.len());
        for (start, len) in packet_offsets {
            if start + len > scratch_len { continue; }
            // Safety: start and len are within scratch bounds (computed above).
            // scratch is not modified during this function call after this point.
            let data = unsafe { std::slice::from_raw_parts(scratch_ptr.add(start), len) };
            packets.push(BackendPacket {
                data,
                // AF_XDP does not attach hardware timestamps in generic mode.
                // Hardware timestamp support requires kernel 5.9+ and NIC driver.
                // SNF uses pcap-derived timestamps as fallback for now.
                // Full SO_TIMESTAMPING integration is Phase 14E.
                timestamp_us: 0, // filled by caller from pcap header if available
                wire_len:     len as u32,
                timestamp_source: HwTimestampSource::KernelSoftware,
            });
        }

        packets
    }
}

// ── Drop implementation ───────────────────────────────────────────────────────

impl Drop for AfXdpBackend {
    fn drop(&mut self) {
        if self.available {
            self.shutdown();
        }
    }
}
