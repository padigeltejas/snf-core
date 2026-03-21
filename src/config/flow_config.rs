// src/config/flow_config.rs
//
// Flow engine configuration — controls flow tracking, timeouts, and eviction.
//
// Phase 4: expanded from 3 to 15 parameters.

#[derive(Clone)]
pub struct FlowConfig {
    // ---------------- TIMEOUTS ----------------
    /// General flow idle timeout in seconds. A flow not seen for this long is expired.
    /// Applied to protocols not covered by a specific timeout below.
    pub flow_timeout: u64,

    /// TCP-specific flow idle timeout in seconds.
    /// TCP flows are often longer-lived than UDP — default is higher.
    pub tcp_stream_timeout: u64,

    /// UDP flow idle timeout in seconds.
    /// UDP has no connection state — short timeout is appropriate.
    pub udp_flow_timeout: u64,

    /// ICMP flow timeout in seconds.
    /// ICMP flows are typically very short (single echo pair).
    pub icmp_flow_timeout: u64,

    // ---------------- LIMITS ----------------
    /// Maximum number of simultaneous tracked flows across all protocols.
    /// When limit is hit, eviction_policy determines which flows are dropped.
    pub max_flows: usize,

    /// Maximum number of simultaneous TCP reassembly streams.
    /// Each stream holds buffered out-of-order segments.
    pub max_tcp_streams: usize,

    /// Maximum number of simultaneous UDP flows.
    /// Separate limit from max_flows to prevent UDP floods from consuming
    /// all flow table slots and starving TCP tracking.
    pub max_udp_flows: usize,

    /// Minimum number of packets a flow must have to be exported/reported.
    /// Flows with fewer packets than this are silently discarded on expiry.
    /// 1 = export all flows (default). Increase to reduce noise from scanners.
    pub min_flow_packets: usize,

    // ---------------- EVICTION ----------------
    /// Flow eviction policy when max_flows is reached.
    /// "lru"  = evict least recently updated flow
    /// "fifo" = evict oldest flow (first inserted)
    pub flow_eviction_policy: String,

    // ---------------- TRACKING ----------------
    /// Track both directions of a flow as a single bidirectional flow.
    /// When false, each direction is tracked as a separate unidirectional flow.
    pub track_bidirectional: bool,

    /// Track byte counts per flow (sent + received separately).
    pub track_flow_bytes: bool,

    /// Track packet counts per flow.
    pub track_flow_packets: bool,

    /// Export expired flows as flow.expired events to the EventBus.
    /// When false, expired flows are silently removed.
    pub export_expired_flows: bool,

    /// Seed for flow table hash function.
    /// Changing this changes the flow key hash distribution.
    /// Fixed seed = deterministic flow ordering across runs (Replay mode).
    pub flow_hash_seed: u64,

    /// How flow keys are labelled in events.
    /// "5tuple"   = src_ip:src_port-dst_ip:dst_port-proto (default)
    /// "normalized" = always lower IP first regardless of direction
    pub flow_label_mode: String,
}

impl Default for FlowConfig {
    fn default() -> Self {
        Self {
            flow_timeout: 120,
            tcp_stream_timeout: 300,
            udp_flow_timeout: 30,
            icmp_flow_timeout: 10,
            max_flows: 100_000,
            max_tcp_streams: 50_000,
            max_udp_flows: 50_000,
            min_flow_packets: 1,
            flow_eviction_policy: "lru".to_string(),
            track_bidirectional: true,
            track_flow_bytes: true,
            track_flow_packets: true,
            export_expired_flows: true,
            flow_hash_seed: 0,
            flow_label_mode: "normalized".to_string(),
        }
    }
}