// src/config/filter_config.rs
//
// Filter layer configuration — controls which packets/flows are processed.
//
// Phase 4: expanded from 4 to 20 parameters.
//
// Filter evaluation order:
//   1. BPF filter (kernel level — most efficient, applied before userspace)
//   2. exclude_loopback / exclude_multicast / exclude_broadcast
//   3. vlan_filter
//   4. ip_filter / src_ip_filter / dst_ip_filter / ip_subnet_filter
//   5. port_filter / src_port_filter / dst_port_filter
//   6. protocol_filter
//   7. mac_filter
//   8. min/max packet size filters
//   9. dscp_filter
//  10. flow_direction_filter
//  11. exclude_ips / exclude_ports lists

#[derive(Clone)]
pub struct FilterConfig {
    // ---------------- BPF ----------------
    /// Berkeley Packet Filter expression applied at kernel capture level.
    /// Most efficient filter — applied before any userspace processing.
    /// Example: "tcp port 443 or udp port 53"
    pub bpf_filter: Option<String>,

    // ---------------- IP FILTERS ----------------
    /// Filter to packets involving this IP (src OR dst). Legacy single-IP filter.
    pub ip_filter: Option<String>,

    /// Filter to packets with this specific source IP only.
    pub src_ip_filter: Option<String>,

    /// Filter to packets with this specific destination IP only.
    pub dst_ip_filter: Option<String>,

    /// Filter to packets within this CIDR subnet (e.g. "192.168.1.0/24").
    /// Matches if src OR dst IP is within the subnet.
    pub ip_subnet_filter: Option<String>,

    /// List of IPs to completely exclude from all processing.
    /// Packets where src or dst matches any entry are dropped silently.
    pub exclude_ips: Vec<String>,

    // ---------------- PORT FILTERS ----------------
    /// Filter to packets involving this port (src OR dst). Legacy single-port filter.
    pub port_filter: Option<u16>,

    /// Filter to packets with this specific source port only.
    pub src_port_filter: Option<u16>,

    /// Filter to packets with this specific destination port only.
    pub dst_port_filter: Option<u16>,

    /// List of ports to completely exclude from all processing.
    pub exclude_ports: Vec<u16>,

    // ---------------- PROTOCOL FILTER ----------------
    /// Filter to this protocol only (e.g. "TCP", "UDP", "ICMP").
    pub protocol_filter: Option<String>,

    // ---------------- MAC FILTER ----------------
    /// Filter to packets from/to this MAC address (format: "aa:bb:cc:dd:ee:ff").
    pub mac_filter: Option<String>,

    // ---------------- SIZE FILTERS ----------------
    /// Drop packets smaller than this size in bytes. 0 = no minimum.
    pub min_packet_size: usize,

    /// Drop packets larger than this size in bytes. 0 = no maximum.
    pub max_packet_size_filter: usize,

    // ---------------- TRAFFIC CLASS FILTERS ----------------
    /// Exclude loopback traffic (src or dst is 127.x.x.x or ::1).
    pub exclude_loopback: bool,

    /// Exclude multicast traffic (dst is 224.x.x.x/4 or ff00::/8).
    pub exclude_multicast: bool,

    /// Exclude broadcast traffic (dst is 255.255.255.255 or layer-2 broadcast).
    pub exclude_broadcast: bool,

    // ---------------- VLAN FILTER ----------------
    /// Only process traffic on this VLAN ID. None = process all VLANs.
    /// Requires vlan_stripping = false in CaptureConfig to see VLAN tags.
    pub vlan_filter: Option<u16>,

    // ---------------- DSCP FILTER ----------------
    /// Only process packets with this DSCP value in the IP header.
    /// None = process all DSCP values.
    pub dscp_filter: Option<u8>,

    // ---------------- FLOW DIRECTION ----------------
    /// Only emit events for flows in this direction.
    /// "both" = all flows, "inbound" = dst is local, "outbound" = src is local.
    pub flow_direction_filter: String,
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            bpf_filter: None,
            ip_filter: None,
            src_ip_filter: None,
            dst_ip_filter: None,
            ip_subnet_filter: None,
            exclude_ips: Vec::new(),
            port_filter: None,
            src_port_filter: None,
            dst_port_filter: None,
            exclude_ports: Vec::new(),
            protocol_filter: None,
            mac_filter: None,
            min_packet_size: 0,
            max_packet_size_filter: 0,
            exclude_loopback: true,
            exclude_multicast: false,
            exclude_broadcast: false,
            vlan_filter: None,
            dscp_filter: None,
            flow_direction_filter: "both".to_string(),
        }
    }
}