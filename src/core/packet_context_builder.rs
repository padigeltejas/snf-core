// src/core/packet_context_builder.rs
//
// Constructs a PacketContext from raw parsed packet fields.
//
// Phase 15 Part 1: All new Phase 15Aâ€“15E fields added here.
// The builder is the single place where PacketContext is created â€”
// adding a field to PacketContext requires adding it here, which prevents
// silent omissions at compile time.

use crate::core::packet_context::PacketContext;

pub struct PacketContextBuilder;

impl PacketContextBuilder {
    /// Build a PacketContext from parsed packet fields.
    ///
    /// `timestamp_us` must be the packet's own timestamp in microseconds since
    /// Unix epoch, derived from the pcap packet header:
    ///   `(header.ts.tv_sec as u64) * 1_000_000 + (header.ts.tv_usec as u64)`
    ///
    /// Never pass `std::time::SystemTime` or `Instant` here. Wall-clock time
    /// breaks determinism and is forbidden in all SNF timing paths.
    pub fn build(
        src_ip: String,
        dst_ip: String,
        src_port: u16,
        dst_port: u16,
        protocol: String,
        packet_size: usize,
        timestamp_us: u64,
    ) -> PacketContext {
        let src_ip = match src_ip.parse() {
            Ok(ip) => ip,
            Err(_) => {
                // Malformed IP in packet header â€” use unspecified as safe fallback.
                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
            }
        };
        let dst_ip = match dst_ip.parse() {
            Ok(ip) => ip,
            Err(_) => {
                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
            }
        };

        PacketContext {
            // ---------------- NETWORK LAYER ----------------
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            packet_size,
            timestamp_us,

            // ---------------- FLOW ----------------
            flow_id: None,
            flow_packets: 0,

            // ---------------- DNS ----------------
            dns_query_name: None,
            dns_resolved_ip: None,
            dns_domain: None,
            dns_record_type: None,
            dns_ttl: None,
            dns_cname_chain: Vec::new(),
            dns_mx_records: Vec::new(),
            dns_txt_records: Vec::new(),
            dns_ns_records: Vec::new(),
            dns_ptr_record: None,
            dns_srv_records: Vec::new(),
            dns_is_response: false,
            // Phase 15A
            dns_truncated: false,
            dns_dnssec_present: false,
            dns_rrsig_type_covered: None,
            dns_transport: None,

            // ---------------- TLS ----------------
            tls_sni: None,
            tls_version: None,
            tls_cipher_suites: Vec::new(),
            tls_alpn: None,
            tls_alpn_protocols: Vec::new(),
            tls_session_resumed: false,

            // ---------------- TLS CERTIFICATE ----------------
            tls_cert_cn: None,
            tls_cert_sans: Vec::new(),
            tls_cert_issuer: None,
            tls_cert_not_after: None,
            tls_cert_self_signed: false,
            tls_cert_expired: false,
            // Phase 15B
            tls_early_data: false,
            tls_ocsp_stapling: false,
            tls_ech_present: false,
            tls_cert_chain_len: 0,

            // ---------------- JA3 / JA4 ----------------
            ja3_fingerprint: None,
            ja3_string: None,
            ja3_hash: None,
            ja3s_hash: None,
            ja4: None,
            ja4_hash: None,
            ja3s_fingerprint: None,    
            ja4_fingerprint: None,
            // ---------------- HTTP ----------------
            http_host: None,
            http_method: None,
            http_uri: None,
            http_version: None,
            http_status_code: None,
            http_user_agent: None,
            http_content_type: None,
            http_content_length: None,
            // Phase 15C
            http_websocket: false,
            http_upgrade: None,
            http_referer: None,
            http_xff: None,
            http_status_class: None,

            // ---------------- QUIC ----------------
            quic_version: None,
            // Phase 15D
            quic_0rtt: false,
            quic_short_header: false,

            // ---------------- DHCP ----------------
            dhcp_msg_type: None,
            dhcp_client_mac: None,
            dhcp_requested_ip: None,
            dhcp_assigned_ip: None,
            dhcp_hostname: None,
            dhcp_vendor_class: None,
            // Phase 15E
            dhcp_version: 4,
            dhcp_relay_present: false,
            dhcp_relay_circuit_id: None,
            dhcp_relay_remote_id: None,

            // ---------------- ICMP ----------------
            icmp_type: None,
            icmp_code: None,
            icmp_description: None,

            // ---------------- SMB ----------------
            smb_command: None,
            smb_version: None,
            smb_status: None,

            // ---------------- mDNS ----------------
            mdns_query_name: None,
            mdns_record_type: None,
            mdns_is_response: false,

            // ---------------- NETWORK ATTRIBUTION (Phase 10B) ----------------
            src_asn: 0,
            src_asn_org: None,
            src_country: None,
            dst_asn: 0,
            dst_asn_org: None,
            dst_country: None,
            // 15F SMB
            smb_dialect: None,
            smb_share_path: None,
            smb_admin_share: false,
            smb_pth_indicator: false,
            smb_encrypted: false,

//  ICMP
            icmp_tunnel_suspected: false,
            icmp_nd_type: None,
            icmp_nd_target: None,
            icmp_nd_flags: None,

//  mDNS
            mdns_service_type: None,
            mdns_ptr_target: None,
            mdns_instance_name: None,
            mdns_srv_target: None,
            mdns_srv_port: None,

// ICS
            ics_protocol: None,
            modbus_function_code: None,
            modbus_unit_id: None,
            modbus_exception: false,
            modbus_register_addr: None,
            modbus_register_count: None,
            dnp3_function_code: None,
            dnp3_iin_flags: None,
            dnp3_objects: Vec::new(),

            // Phase 18 — S7comm
            s7_pdu_type:            None,
            s7_function:            None,
            s7_data_len:            None,
            // Phase 18 — EtherNet/IP + CIP
            enip_command:           None,
            enip_session_handle:    None,
            cip_service:            None,
            cip_class:              None,
            cip_instance:           None,
            cip_status:             None,
            // Phase 18 — PROFINET
            profinet_frame_id:      None,
            profinet_service:       None,
            profinet_station_name:  None,
            profinet_ip_addr:       None,
            profinet_mac:           None,
            // Phase 18 — LLDP
            lldp_chassis_id:        None,
            lldp_port_id:           None,
            lldp_ttl:               None,
            lldp_system_name:       None,
            lldp_system_desc:       None,
            lldp_port_desc:         None,
            lldp_mgmt_addr:         None,
            lldp_capabilities:      None,
            lldp_vlan_id:           None,
            // Phase 18 — CDP
            cdp_device_id:          None,
            cdp_port_id:            None,
            cdp_platform:           None,
            cdp_version:            None,
            cdp_capabilities:       None,
            cdp_vtp_domain:         None,
            cdp_native_vlan:        None,
            cdp_addresses:          Vec::new(),


//  Enterprise
            krb_msg_type: None,
            krb_realm: None,
            krb_principal: None,
            krb_error_code: None,
            ldap_msg_type: None,
            ldap_base_dn: None,
            ldap_bind_dn: None,
            rdp_version: None,
            rdp_cookie: None,
            rdp_security: None,

// Discovery
            ssdp_method: None,
            ssdp_st: None,
            ssdp_usn: None,
            upnp_location: None,
            upnp_device_type: None,
            ftp_command: None,
            ftp_response_code: None,
            ftp_passive_addr: None,
            ftp_auth_seen: false,

        }
    }
}