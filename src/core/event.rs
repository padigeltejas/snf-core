// src/core/event.rs
//
// Canonical SNF event model.
//
// Phase 5: SnfEvent struct, EventType enum, AttrValue enum, serialization.
// Phase 12: GraphSummary, GraphNode, GraphEdge, TimelineSummary, TimelineDevice,
//            TimelineFlow, StealthPortScan, StealthDnsTunnel, StealthExfil,
//            StealthProtocolAbuse, StealthLotl variants added to EventType.
//
// Architecture rules (non-negotiable):
//   - SnfEvent.attributes is HashMap<String, AttrValue>. Determinism is achieved
//     by to_json_line() sorting keys before serialization â€” NOT by BTreeMap here.
//   - AttrValue has NO Int variant. Use U64 for counts/IDs, Str(format!()) for floats.
//   - event_type field is EventType enum, never a plain String.
//   - All timestamps are integer microseconds UTC from pcap headers only.

use std::collections::HashMap;
use std::net::IpAddr;

// â”€â”€ EventType â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Canonical SNF event type identifiers.
/// Every observable network finding is represented as one of these variants.
/// New variants must be added here before being emitted anywhere in the codebase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventType {
    // --- Flow lifecycle ---
    FlowNew,
    FlowUpdate,
    FlowExpired,

    // --- Protocol findings ---
    DnsQuery,
    DnsResponse,
    TlsClientHello,
    TlsServerHello,
    QuicSni,
    HttpRequest,
    HttpResponse,
    DohDetected,
    DotDetected,

    // --- Intelligence findings ---
    Ja3Fingerprint,
    Ja3sFingerprint,
    Ja4Fingerprint,
    TlsRiskScored,

    // --- Device discovery ---
    DeviceDiscovered,

    // --- New protocol findings ---
    DhcpMessage,
    IcmpMessage,
    SmbSession,
    MdnsRecord,

    // --- Parse / engine errors ---
    ParseError,
    CaptureError,
        /// Phase 11E: emitted when packets are dropped anywhere in the pipeline.
    // --- Anomaly engine findings ---
    /// Volume spike: device traffic exceeds baseline by configured multiplier.
    AnomalyVolumeSpike,
    /// Connection rate spike: new flow rate exceeds baseline.
    AnomalyConnectionSpike,
    /// Protocol ratio anomaly: one protocol dominates device traffic.
    AnomalyProtocolRatio,
    /// Geographic anomaly: device contacted a new country for the first time.
    AnomalyNewCountry,
        /// Attributes: reason (Str), drop_count (U64), location (Str).
    CaptureDropped,
    /// Phase 14F: NIC ring buffer overrun â€” packets dropped at hardware level.
    CaptureOverrun,
    /// Phase 14F: worker thread stalled â€” no packets processed in timeout window.
    WorkerStall,

    // --- Phase 18: ICS/SCADA protocol events ---
    /// Modbus/TCP request or exception response.
    IcsModbus,
    /// DNP3 application layer event (function code + IIN flags).
    IcsDnp3,
    /// Siemens S7comm PDU (READ_VAR, WRITE_VAR, PLC_STOP, etc.).
    IcsS7comm,
    /// EtherNet/IP encapsulation + CIP service event.
    IcsEtherNetIp,
    /// PROFINET DCP Identify Request/Response.
    IcsProfinet,

    // --- Phase 18: LAN Discovery protocol events ---
    /// LLDP neighbor advertisement (system name, chassis, port, capabilities).
    LanLldp,
    /// CDP (Cisco Discovery Protocol) neighbor advertisement.
    LanCdp,

    // --- Behavior findings ---
    BehaviorBeacon,
    BehaviorDga,
    BehaviorIcmpFlood,
    BehaviorIcmpSweep,
    BehaviorSmbLateral,
    BehaviorSmbAuthStorm,

    // --- Phase 12: Graph engine events ---
    /// One emitted per session: overall graph statistics summary.
    GraphSummary,
    /// One emitted per unique graph node at session end.
    GraphNode,
    /// One emitted per unique graph edge at session end.
    GraphEdge,

    // --- Phase 12: Timeline engine events ---
    /// One emitted per session: overall timeline statistics summary.
    TimelineSummary,
    /// One emitted per device timeline entry at session end.
    TimelineDevice,
    /// One emitted per flow timeline entry at session end.
    TimelineFlow,

    // --- Phase 12: Stealth detection events ---
    /// Port scan detection (horizontal or vertical). Sub-type in "scan_type" attr.
    StealthPortScan,
    /// DNS tunneling detection. Sub-type in "finding_type" attr.
    StealthDnsTunnel,
    /// Data exfiltration detection. Sub-type in "finding_type" attr.
    StealthExfil,
    /// Protocol observed on non-standard port.
    StealthProtocolAbuse,
    /// Living-off-the-land detection. Sub-type in "detail" attr.
    StealthLotl,
}

impl EventType {
    /// Returns the canonical string identifier for this event type.
    /// Used as the "event_type" field value in JSON output.
    pub fn as_str(&self) -> &'static str {
        match self {
            EventType::FlowNew               => "flow.new",
            EventType::FlowUpdate            => "flow.update",
            EventType::FlowExpired           => "flow.expired",
            EventType::DnsQuery              => "dns.query",
            EventType::DnsResponse           => "dns.response",
            EventType::TlsClientHello        => "tls.client_hello",
            EventType::TlsServerHello        => "tls.server_hello",
            EventType::QuicSni               => "quic.sni",
            EventType::HttpRequest           => "http.request",
            EventType::HttpResponse          => "http.response",
            EventType::DohDetected           => "doh.detected",
            EventType::DotDetected           => "dot.detected",
            EventType::Ja3Fingerprint        => "intel.ja3",
            EventType::Ja3sFingerprint       => "intel.ja3s",
            EventType::Ja4Fingerprint        => "intel.ja4",
            EventType::TlsRiskScored         => "intel.tls_risk",
            EventType::DeviceDiscovered      => "discovery.device",
            EventType::ParseError            => "engine.parse_error",
            EventType::CaptureError          => "engine.capture_error",
            EventType::AnomalyVolumeSpike    => "anomaly.volume_spike",
            EventType::AnomalyConnectionSpike => "anomaly.connection_spike",
            EventType::AnomalyProtocolRatio  => "anomaly.protocol_ratio",
            EventType::AnomalyNewCountry     => "anomaly.new_country",
            EventType::CaptureDropped        => "capture.drop",
            EventType::CaptureOverrun        => "capture.overrun",
            EventType::WorkerStall           => "engine.worker_stall",
            EventType::DhcpMessage           => "dhcp.message",
            EventType::IcmpMessage           => "icmp.message",
            EventType::SmbSession            => "smb.session",
            EventType::MdnsRecord            => "mdns.record",
            EventType::BehaviorBeacon        => "behavior.beacon",
            EventType::BehaviorDga           => "behavior.dga",
            EventType::BehaviorIcmpFlood     => "behavior.icmp_flood",
            EventType::BehaviorIcmpSweep     => "behavior.icmp_sweep",
            EventType::BehaviorSmbLateral    => "behavior.smb_lateral",
            EventType::BehaviorSmbAuthStorm  => "behavior.smb_auth_storm",
            // Phase 12 â€” graph engine
            EventType::GraphSummary          => "graph.summary",
            EventType::GraphNode             => "graph.node",
            EventType::GraphEdge             => "graph.edge",
            // Phase 12 â€” timeline engine
            EventType::TimelineSummary       => "timeline.summary",
            EventType::TimelineDevice        => "timeline.device",
            EventType::TimelineFlow          => "timeline.flow",
            // Phase 12 â€” stealth detection
            EventType::StealthPortScan       => "stealth.port_scan",
            EventType::StealthDnsTunnel      => "stealth.dns_tunnel",
            EventType::StealthExfil          => "stealth.exfil",
            EventType::StealthProtocolAbuse  => "stealth.protocol_abuse",
            EventType::StealthLotl           => "stealth.lotl",
            // Phase 18 — ICS/SCADA
            EventType::IcsModbus             => "ics.modbus",
            EventType::IcsDnp3               => "ics.dnp3",
            EventType::IcsS7comm             => "ics.s7comm",
            EventType::IcsEtherNetIp         => "ics.enip",
            EventType::IcsProfinet           => "ics.profinet",
            // Phase 18 — LAN Discovery
            EventType::LanLldp               => "lan.lldp",
            EventType::LanCdp                => "lan.cdp",
        }
    }
}

// â”€â”€ AttrValue â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Attribute value â€” typed union covering all values that can appear
/// in a protocol event's attribute map.
///
/// IMPORTANT: There is NO Int variant. Use U64 for integer counts and IDs.
/// Use Str(format!("{:.4}", f)) for floating-point values.
/// Integer types preserve cross-platform determinism; floats would not.
#[derive(Debug, Clone)]
pub enum AttrValue {
    Str(String),
    U64(u64),
    U16(u16),
    U8(u8),
    Bool(bool),
    Ip(IpAddr),
    U16List(Vec<u16>),
    StrList(Vec<String>),
}

impl AttrValue {
    /// Serialize to a JSON-compatible string representation.
    /// Called by SnfEvent::to_json_line().
    pub fn to_json(&self) -> String {
        match self {
            AttrValue::Str(s)     => format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")),
            AttrValue::U64(n)     => n.to_string(),
            AttrValue::U16(n)     => n.to_string(),
            AttrValue::U8(n)      => n.to_string(),
            AttrValue::Bool(b)    => b.to_string(),
            AttrValue::Ip(ip)     => format!("\"{}\"", ip),
            AttrValue::U16List(v) => {
                let items: Vec<String> = v.iter().map(|n| n.to_string()).collect();
                format!("[{}]", items.join(","))
            }
            AttrValue::StrList(v) => {
                let items: Vec<String> = v.iter()
                    .map(|s| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")))
                    .collect();
                format!("[{}]", items.join(","))
            }
        }
    }
}

// â”€â”€ SnfEvent â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// The canonical SNF event structure.
///
/// Contract: F(dataset, config, version) = identical sequence of SnfEvents.
/// All timestamps are integer microseconds since Unix epoch from pcap headers.
/// No wall-clock values are ever stored here.
///
/// attributes is HashMap<String, AttrValue>. Determinism of JSON output is
/// achieved by to_json_line() sorting keys alphabetically before serialization.
/// This matches the design established in Phase 5 and must not be changed.
#[derive(Debug, Clone)]
pub struct SnfEvent {
    /// Monotonically increasing event counter within a single SNF session.
    /// Resets to 0 on each run. Used for ordering and deduplication.
    pub event_id: u64,

    /// The pcap packet sequence number that triggered this event.
    /// 1-indexed. Ties events back to specific packets for forensic tracing.
    pub packet_id: u64,

    /// Packet timestamp in microseconds since Unix epoch.
    /// Sourced exclusively from pcap packet header â€” never SystemTime or Instant.
    pub timestamp_us: u64,

    /// Canonical event type identifier.
    pub event_type: EventType,

    /// Protocol layer that generated this event (e.g. "DNS", "TLS", "QUIC").
    pub protocol: String,

    /// Flow identifier â€” canonical 5-tuple string:
    /// "{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
    /// Normalized so lower IP is always src. Matches FlowKey normalization.
    pub flow_id: String,

    /// Protocol-specific key-value attributes.
    /// Keys are snake_case strings. Values are typed AttrValues.
    /// Serialized as a flat JSON object in output.
    /// Determinism guaranteed by to_json_line() sorting keys â€” not by BTreeMap.
    pub attributes: HashMap<String, AttrValue>,
}

impl SnfEvent {
    /// Create a new event with empty attributes.
    pub fn new(
        event_id:     u64,
        packet_id:    u64,
        timestamp_us: u64,
        event_type:   EventType,
        protocol:     impl Into<String>,
        flow_id:      impl Into<String>,
    ) -> Self {
        Self {
            event_id,
            packet_id,
            timestamp_us,
            event_type,
            protocol:   protocol.into(),
            flow_id:    flow_id.into(),
            attributes: HashMap::new(),
        }
    }

    /// Insert a string attribute.
    pub fn attr_str(&mut self, key: &str, value: impl Into<String>) {
        self.attributes.insert(key.to_string(), AttrValue::Str(value.into()));
    }

    /// Insert a u64 attribute.
    pub fn attr_u64(&mut self, key: &str, value: u64) {
        self.attributes.insert(key.to_string(), AttrValue::U64(value));
    }

    /// Insert a u16 attribute.
    pub fn attr_u16(&mut self, key: &str, value: u16) {
        self.attributes.insert(key.to_string(), AttrValue::U16(value));
    }

    /// Insert a u8 attribute.
    pub fn attr_u8(&mut self, key: &str, value: u8) {
        self.attributes.insert(key.to_string(), AttrValue::U8(value));
    }

    /// Insert a bool attribute.
    pub fn attr_bool(&mut self, key: &str, value: bool) {
        self.attributes.insert(key.to_string(), AttrValue::Bool(value));
    }

    /// Insert an IP address attribute.
    pub fn attr_ip(&mut self, key: &str, value: IpAddr) {
        self.attributes.insert(key.to_string(), AttrValue::Ip(value));
    }

    /// Insert a u16 list attribute (e.g. cipher suites).
    pub fn attr_u16_list(&mut self, key: &str, value: Vec<u16>) {
        self.attributes.insert(key.to_string(), AttrValue::U16List(value));
    }

    /// Insert a string list attribute (e.g. DNS CNAME chain).
    pub fn attr_str_list(&mut self, key: &str, value: Vec<String>) {
        self.attributes.insert(key.to_string(), AttrValue::StrList(value));
    }

    /// Serialize this event as a single compact JSON line.
    ///
    /// Output is DETERMINISTIC: attribute keys are sorted alphabetically before
    /// serialization. This is the canonical output format for SNF forensic logs.
    /// Key sorting here is the mechanism â€” not BTreeMap storage.
    pub fn to_json_line(&self) -> String {
        // Sort attribute keys for deterministic output across runs.
        let mut keys: Vec<&String> = self.attributes.keys().collect();
        keys.sort();

        let attrs: Vec<String> = keys.iter()
            .map(|k| format!("\"{}\":{}", k, self.attributes[*k].to_json()))
            .collect();

        format!(
            "{{\"event_id\":{},\"packet_id\":{},\"timestamp_us\":{},\"event_type\":\"{}\",\"protocol\":\"{}\",\"flow_id\":\"{}\",\"attributes\":{{{}}}}}",
            self.event_id,
            self.packet_id,
            self.timestamp_us,
            self.event_type.as_str(),
            self.protocol,
            self.flow_id,
            attrs.join(",")
        )
    }
}