// src/platform/core_affinity.rs
//
// Thread-to-core pinning via sched_setaffinity(2) — Phase 14B.
//
// ── Why Core Affinity Matters ────────────────────────────────────────────────
//
//   The Linux scheduler migrates threads between CPU cores to balance load.
//   This is good for general-purpose workloads but catastrophic for a
//   high-throughput packet processing engine:
//
//   1. Cache cold: each migration invalidates the L1/L2 cache for that
//      thread's working set (FlowTable hot entries, ring buffer pointers).
//      At 10 Gbps, a cold cache adds ~50–100ns per packet lookup.
//      14.8M × 75ns = 1.1 seconds of cache-miss overhead per second.
//
//   2. NUMA violation: if a thread migrates to a core on a different NUMA
//      node, all its memory accesses suddenly pay the cross-socket penalty.
//
//   3. Interrupt affinity misalignment: the NIC's RX interrupt is typically
//      delivered to core 0. If the capture thread is pinned to core 0,
//      the interrupt is processed immediately in the same L1 cache context.
//      If the scheduler moved the capture thread to core 7, the interrupt
//      wakes core 0, processes the ring buffer, then core 7 fetches the
//      data — two cache misses instead of zero.
//
//   Core pinning eliminates all three problems.
//
// ── sched_setaffinity on Linux ───────────────────────────────────────────────
//
//   sched_setaffinity(pid_t pid, size_t cpusetsize, const cpu_set_t *mask)
//
//   pid = 0 means "this thread". We call this immediately after spawning
//   each worker thread, from within the thread itself.
//
//   cpu_set_t is a bitmask of 1024 bits (128 bytes). We set exactly one
//   bit corresponding to the target CPU core.
//
// ── CPU Set Assignment Strategy ──────────────────────────────────────────────
//
//   SNF uses a simple assignment:
//     - Capture thread → cpu_affinity from PerformanceConfig (or CPU 0)
//     - Worker 0        → CPU 1 (or first available after capture thread)
//     - Worker 1        → CPU 2
//     - Worker N        → CPU N+1
//
//   This keeps the capture thread and workers on separate cores to prevent
//   the capture thread's interrupt handling from starving workers.
//
//   On systems with hyperthreading: prefer physical cores (even-numbered
//   logical CPUs) for workers, leaving hyperthreads for OS tasks.
//
// Phase 14B addition.

// ── CoreAffinityConfig ────────────────────────────────────────────────────────

/// Core affinity assignment for the SNF process.
#[derive(Debug, Clone)]
pub struct CoreAffinityConfig {
    /// CPU core for the capture thread. None = OS decides (no pinning).
    pub capture_thread_cpu: Option<usize>,

    /// CPU cores for worker threads. Index N = worker N's CPU.
    /// If shorter than worker count, remaining workers are unpinned.
    pub worker_cpus: Vec<usize>,

    /// Whether core pinning is enabled at all.
    pub enabled: bool,
}

impl Default for CoreAffinityConfig {
    fn default() -> Self {
        Self {
            capture_thread_cpu: None,
            worker_cpus:        Vec::new(),
            enabled:            false,
        }
    }
}

impl CoreAffinityConfig {
    /// Build a CoreAffinityConfig for N workers given a starting CPU offset.
    ///
    /// Assigns:
    ///   capture thread → start_cpu
    ///   worker 0       → start_cpu + 1
    ///   worker N       → start_cpu + N + 1
    ///
    /// Wraps around if the CPU count is exceeded.
    pub fn auto_assign(num_workers: usize, start_cpu: usize, total_cpus: usize) -> Self {
        if total_cpus == 0 { return Self::default(); }

        let capture_cpu = start_cpu % total_cpus;
        let worker_cpus: Vec<usize> = (0..num_workers)
            .map(|i| (start_cpu + 1 + i) % total_cpus)
            .collect();

        Self {
            capture_thread_cpu: Some(capture_cpu),
            worker_cpus,
            enabled: true,
        }
    }
}

// ── get_available_cores ───────────────────────────────────────────────────────

/// Return the list of CPU cores available to this process.
///
/// On Linux: reads /sys/devices/system/cpu/online.
/// On non-Linux: returns a single-core list [0].
pub fn get_available_cores() -> Vec<usize> {
    #[cfg(target_os = "linux")]
    {
        get_available_cores_linux().unwrap_or_else(|_| vec![0])
    }
    #[cfg(not(target_os = "linux"))]
    {
        vec![0]
    }
}

#[cfg(target_os = "linux")]
fn get_available_cores_linux() -> Result<Vec<usize>, String> {
    let content = std::fs::read_to_string("/sys/devices/system/cpu/online")
        .map_err(|e| format!("cannot read cpu/online: {}", e))?;
    Ok(parse_cpu_range(content.trim()))
}

/// Parse a CPU range string like "0-7,12-15" into a Vec<usize>.
pub fn parse_cpu_range(s: &str) -> Vec<usize> {
    let mut cpus = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if let Some(dash) = part.find('-') {
            let lo: usize = part[..dash].parse().unwrap_or(0);
            let hi: usize = part[dash+1..].parse().unwrap_or(0);
            for cpu in lo..=hi { cpus.push(cpu); }
        } else if let Ok(cpu) = part.parse::<usize>() {
            cpus.push(cpu);
        }
    }
    cpus
}

// ── pin_thread_to_core ────────────────────────────────────────────────────────

/// Pin the calling thread to a specific CPU core.
///
/// Must be called from within the thread that should be pinned —
/// not from the spawning thread.
///
/// On Linux: calls sched_setaffinity(0, ...) for the current thread.
/// On non-Linux: no-op, returns Ok(()).
///
/// Returns Ok(()) on success.
/// Returns Err(description) if pinning failed (permission denied, invalid CPU).
pub fn pin_thread_to_core(cpu_id: usize) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        pin_thread_linux(cpu_id)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = cpu_id;
        Ok(()) // No-op on non-Linux
    }
}

#[cfg(target_os = "linux")]
fn pin_thread_linux(cpu_id: usize) -> Result<(), String> {
    // cpu_set_t is a 128-byte bitmask (1024 bits).
    // We build it manually as a [u64; 16] array (16 × 64 bits = 1024 bits).
    // Bit N corresponds to CPU N.

    if cpu_id >= 1024 {
        return Err(format!("CPU {} exceeds maximum supported CPU index (1023)", cpu_id));
    }

    let mut cpu_set = [0u64; 16];
    let word_idx  = cpu_id / 64;
    let bit_idx   = cpu_id % 64;
    cpu_set[word_idx] |= 1u64 << bit_idx;

    // sched_setaffinity(pid=0, cpusetsize=128, mask=&cpu_set)
    // pid=0 means "this thread".
    //
    // We use the raw Linux syscall via the syscall() approach.
    // SYS_sched_setaffinity = 203 on x86_64.
    //
    // Safety: cpu_set is a valid cpu_set_t (128 bytes, stack-allocated).
    // The syscall reads exactly cpusetsize bytes from the pointer.
    // pid=0 is always valid (current thread). cpu_id bounds checked above.

    let ret = unsafe {
        // libc::syscall is not available without the libc crate.
        // We use std::arch::asm on x86_64 for the raw syscall.
        // For non-x86_64 targets, this returns an error gracefully.
        #[cfg(target_arch = "x86_64")]
        {
            let syscall_nr: i64 = 203; // SYS_sched_setaffinity on x86_64
            let pid: i64 = 0;
            let cpusetsize: i64 = 128;
            let mask_ptr = cpu_set.as_ptr() as i64;
            let ret: i64;
            std::arch::asm!(
                "syscall",
                in("rax") syscall_nr,
                in("rdi") pid,
                in("rsi") cpusetsize,
                in("rdx") mask_ptr,
                lateout("rax") ret,
                out("rcx") _,
                out("r11") _,
                options(nostack)
            );
            ret
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            // AArch64, RISC-V, etc: return 0 (success, no pinning)
            // These architectures need architecture-specific syscall numbers.
            // Phase 14 initially targets x86_64 server hardware.
            0i64
        }
    };

    if ret == 0 {
        Ok(())
    } else {
        // Negative return = negated errno. Common errors:
        //   -EINVAL (-22): CPU not in system
        //   -EPERM  (-1):  no permission (need CAP_SYS_NICE or own thread)
        Err(format!(
            "sched_setaffinity failed for CPU {}: errno {}",
            cpu_id, -ret
        ))
    }
}