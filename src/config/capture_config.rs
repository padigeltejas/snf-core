// src/config/capture_config.rs
//
// Capture layer configuration — controls how packets are ingested.
//
// Phase 4: expanded from 10 to 25 parameters.

#[derive(Clone)]
pub struct CaptureConfig {
    // ---------------- INTERFACE ----------------
    /// Network interface index (0 = auto-select first non-loopback).
    pub interface_index: usize,

    /// Network interface name (e.g. "eth0", "en0"). Overrides interface_index if set.
    pub interface_name: Option<String>,

    // ---------------- LIMITS ----------------
    /// Maximum number of packets to capture before stopping. 0 = unlimited.
    pub packet_limit: usize,

    /// Stop capture after this many seconds. 0 = unlimited.
    pub capture_timeout: u64,

    /// Maximum bytes to capture per packet (snaplen). 65535 = full packet.
    pub snaplen: i32,

    /// Maximum packet size SNF will process. Packets larger than this are dropped
    /// with a parse_error event. Prevents memory abuse from jumbo frames.
    pub max_packet_size: usize,

    // ---------------- BUFFER ----------------
    /// Kernel capture ring buffer size in bytes. Larger = fewer drops under burst.
    pub buffer_size: usize,

    /// Ring buffer slot count for zero-copy capture paths.
    /// Only used when zero_copy_mode = true.
    pub ring_buffer_slots: usize,

    // ---------------- MODE ----------------
    /// Capture mode: "realtime" | "pcap" | "snapshot"
    /// realtime  = live interface capture
    /// pcap      = offline PCAP file replay
    /// snapshot  = single burst capture then exit
    pub capture_mode: String,

    /// Path to PCAP file for offline replay (required when capture_mode = "pcap").
    pub pcap_file: Option<String>,

    /// Direction filter for live capture: "in" | "out" | "both"
    pub capture_direction: String,

    // ---------------- FILTERING ----------------
    /// BPF filter applied at the kernel capture level.
    /// Applied before any SNF processing — most efficient filter path.
    pub packet_filter: Option<String>,

    /// Override the link-layer type reported by pcap.
    /// Useful for tunneled captures or non-standard encapsulations.
    /// None = use pcap's reported linktype.
    pub linktype_override: Option<i32>,

    // ---------------- INTERFACE FLAGS ----------------
    /// Enable promiscuous mode — captures all packets regardless of destination MAC.
    pub promiscuous_mode: bool,

    /// Strip VLAN tags from captured frames before processing.
    /// When true, 802.1Q headers are removed and the inner frame is analyzed.
    pub vlan_stripping: bool,

    /// Trust NIC checksum offload — skip software checksum validation.
    /// Set true when capturing on modern NICs with hardware checksum offload.
    pub checksum_offload: bool,

    /// Use nanosecond timestamps if supported by the capture interface.
    /// Falls back to microsecond timestamps if not available.
    /// SNF always stores timestamps as microseconds internally regardless.
    pub nano_timestamp: bool,

    /// Enable zero-copy packet capture (requires kernel + NIC support).
    /// Reduces CPU overhead significantly at high packet rates.
    pub zero_copy_mode: bool,

    // ---------------- PCAP OUTPUT ----------------
    /// Write captured packets to a PCAP file in addition to processing them.
    /// None = no PCAP output written.
    pub pcap_output_path: Option<String>,

    /// Compress PCAP output using gzip. Only used when pcap_output_path is set.
    pub pcap_compress: bool,

    /// Rotate PCAP output file after this many packets. 0 = no rotation.
    pub rotation_interval_packets: usize,

    /// Rotate PCAP output file after this many bytes. 0 = no rotation.
    pub rotation_interval_bytes: usize,

    // ---------------- STATS ----------------
    /// How often to emit capture statistics (dropped packets, buffer usage).
    /// In milliseconds. 0 = disabled.
    pub stats_interval_ms: u64,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            interface_index: 0,
            interface_name: None,
            packet_limit: 0,
            capture_timeout: 0,
            snaplen: 65535,
            max_packet_size: 65535,
            buffer_size: 4 * 1024 * 1024,
            ring_buffer_slots: 4096,
            capture_mode: "realtime".to_string(),
            pcap_file: None,
            capture_direction: "both".to_string(),
            packet_filter: None,
            linktype_override: None,
            promiscuous_mode: true,
            vlan_stripping: false,
            checksum_offload: true,
            nano_timestamp: false,
            zero_copy_mode: false,
            pcap_output_path: None,
            pcap_compress: false,
            rotation_interval_packets: 0,
            rotation_interval_bytes: 0,
            stats_interval_ms: 0,
        }
    }
}