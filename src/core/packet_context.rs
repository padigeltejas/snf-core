// src/core/packet_context.rs
//
// PacketContext â€” per-packet analysis scratchpad.
//
// This struct is populated incrementally as a packet moves through the pipeline:
//   capture â†’ context builder â†’ flow engine â†’ protocol analyzers â†’ event emitter
//
// It is NOT persisted â€” a fresh PacketContext is created for every packet.
// Long-lived state lives in Flow (flow_struct.rs) and the DNS/RDNS caches.
//
// Phase 15 Part 1 additions (15Aâ€“15E):
//   15A DNS:  dns_truncated, dns_dnssec_present, dns_rrsig_type_covered, dns_transport
//   15B TLS:  tls_early_data, tls_ocsp_stapling, tls_ech_present, tls_cert_chain_len
//   15C HTTP: http_websocket, http_upgrade, http_referer, http_xff, http_status_class
//   15D QUIC: quic_0rtt, quic_short_header
//   15E DHCP: dhcp_relay_present, dhcp_relay_circuit_id, dhcp_relay_remote_id, dhcp_version
//
// Phase 10B (preserved): src_asn, src_asn_org, src_country, dst_asn, dst_asn_org, dst_country
// Phase 3A/3B (preserved): all DNS, TLS, HTTP, QUIC, DHCP, ICMP, SMB, mDNS fields

use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct PacketContext {
    // ---------------- NETWORK LAYER ----------------
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub packet_size: usize,

    /// Packet timestamp in microseconds since Unix epoch.
    /// In live capture: from pcap packet header (ts_sec * 1_000_000 + ts_usec).
    /// In PCAP replay: packet header timestamp drives all flow timing â€” never wall-clock.
    pub timestamp_us: u64,

    // ---------------- FLOW ----------------
    pub flow_id: Option<String>,
    /// Cumulative packet count for this flow at time of this packet.
    pub flow_packets: u64,

    // ---------------- DNS ----------------
    /// The query name extracted from the DNS question section.
    pub dns_query_name: Option<String>,
    /// The first resolved IP address from DNS answer records (A or AAAA).
    pub dns_resolved_ip: Option<IpAddr>,
    /// The domain name bound to this packet's flow via DNS resolution.
    pub dns_domain: Option<String>,
    /// The DNS record type of the first answer (e.g. "A", "AAAA", "CNAME", "MX").
    pub dns_record_type: Option<String>,
    /// TTL of the first DNS answer record, in seconds.
    pub dns_ttl: Option<u32>,
    /// CNAME chain encountered during answer parsing.
    pub dns_cname_chain: Vec<String>,
    /// MX record targets extracted from DNS answers.
    pub dns_mx_records: Vec<String>,
    /// TXT record values extracted from DNS answers.
    pub dns_txt_records: Vec<String>,
    /// NS record values extracted from DNS answers.
    pub dns_ns_records: Vec<String>,
    /// PTR record target (reverse DNS answer). Single value â€” PTR is 1:1.
    pub dns_ptr_record: Option<String>,
    /// SRV record targets: "priority weight port target" formatted strings.
    pub dns_srv_records: Vec<String>,
    /// True if this DNS packet is a response (QR bit set), false if a query.
    pub dns_is_response: bool,

    // Phase 15A DNS fields
    /// True if the TC (Truncation) bit is set â€” response was truncated.
    /// Client will typically retry over TCP.
    pub dns_truncated: bool,
    /// True if any DNSSEC record type (DS/RRSIG/NSEC/DNSKEY/NSEC3) was present.
    pub dns_dnssec_present: bool,
    /// Type covered by the first RRSIG record, if present (e.g. "A", "AAAA").
    pub dns_rrsig_type_covered: Option<String>,
    /// Transport used for this DNS packet: "DNS", "DNS-TCP", or "DoQ".
    pub dns_transport: Option<String>,

    // ---------------- TLS ----------------
    /// TLS SNI from ClientHello extension 0x0000.
    pub tls_sni: Option<String>,
    /// TLS record-layer version string (e.g. "TLS1.2", "TLS1.3").
    pub tls_version: Option<String>,
    /// Cipher suites advertised in ClientHello (or selected in ServerHello).
    pub tls_cipher_suites: Vec<u16>,
    /// First ALPN protocol from ClientHello extension 0x0010.
    pub tls_alpn: Option<String>,
    /// All ALPN protocols advertised in ClientHello extension 0x0010.
    pub tls_alpn_protocols: Vec<String>,
    /// True if this TLS handshake is a session resumption (session ticket or PSK).
    pub tls_session_resumed: bool,

    // ---------------- TLS CERTIFICATE ----------------
    /// Subject Common Name from the leaf certificate.
    pub tls_cert_cn: Option<String>,
    /// DNS Subject Alternative Names from the leaf certificate.
    pub tls_cert_sans: Vec<String>,
    /// Issuer Common Name from the leaf certificate.
    pub tls_cert_issuer: Option<String>,
    /// Certificate notAfter validity date as ISO-8601 string.
    pub tls_cert_not_after: Option<String>,
    /// True if the certificate is self-signed (Subject DN == Issuer DN).
    pub tls_cert_self_signed: bool,
    /// True if the certificate has expired (notAfter < packet timestamp).
    pub tls_cert_expired: bool,

    // Phase 15B TLS fields
    /// True if TLS 1.3 0-RTT Early Data extension (0x002a) was present in ClientHello.
    /// 0-RTT data is not forward-secret and is potentially replayable.
    pub tls_early_data: bool,
    /// True if the client requested OCSP stapling (status_request extension 0x0012).
    pub tls_ocsp_stapling: bool,
    /// True if Encrypted Client Hello (ECH) extension was present.
    /// ECH hides the real SNI â€” the visible SNI is only the ECH provider domain.
    pub tls_ech_present: bool,
    /// Total number of certificates in the chain (leaf + intermediates + root).
    pub tls_cert_chain_len: u8,

    // ---------------- JA3 / JA4 FINGERPRINTS ----------------
pub ja3_fingerprint: Option<String>,
pub ja3_string: Option<String>,
pub ja3_hash: Option<String>,
pub ja3s_hash: Option<String>,
pub ja3s_fingerprint: Option<String>,   
pub ja4: Option<String>,
pub ja4_hash: Option<String>,
pub ja4_fingerprint: Option<String>,    

    // ---------------- HTTP ----------------
    /// HTTP Host header (HTTP/1.x) or :authority pseudo-header (HTTP/2).
    pub http_host: Option<String>,
    /// HTTP request method.
    pub http_method: Option<String>,
    /// HTTP request URI.
    pub http_uri: Option<String>,
    /// HTTP version string: "HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/3".
    pub http_version: Option<String>,
    /// HTTP response status code (e.g. 200, 301, 404, 500).
    pub http_status_code: Option<u16>,
    /// User-Agent header value.
    pub http_user_agent: Option<String>,
    /// Content-Type header value.
    pub http_content_type: Option<String>,
    /// Content-Length header value in bytes.
    pub http_content_length: Option<u64>,

    // Phase 15C HTTP fields
    /// True if an HTTPâ†’WebSocket upgrade was detected (Upgrade: websocket).
    pub http_websocket: bool,
    /// Value of the Upgrade header (e.g. "websocket", "h2c").
    pub http_upgrade: Option<String>,
    /// Referer header value (bounded to 1024 bytes).
    pub http_referer: Option<String>,
    /// X-Forwarded-For header value â€” identifies real client behind proxy.
    pub http_xff: Option<String>,
    /// HTTP status class: "1xx", "2xx", "3xx", "4xx", "5xx", or "unknown".
    pub http_status_class: Option<String>,

    // ---------------- QUIC ----------------
    /// Human-readable QUIC version string (e.g. "QUIC v1", "QUIC v2", "draft-29").
    pub quic_version: Option<String>,

    // Phase 15D QUIC fields
    /// True if a QUIC 0-RTT packet (long header type 0x01) was detected.
    pub quic_0rtt: bool,
    /// True if a QUIC short header packet was observed on this flow.
    /// Short headers appear after handshake completion and during connection migration.
    pub quic_short_header: bool,

    // ---------------- DHCP ----------------
    /// DHCP message type string (e.g. "DISCOVER", "OFFER", "ACK").
    pub dhcp_msg_type: Option<String>,
    /// Client hardware address (MAC) formatted as "aa:bb:cc:dd:ee:ff",
    /// or DHCPv6 Client DUID as hex string.
    pub dhcp_client_mac: Option<String>,
    /// Requested IP address from DHCP Option 50.
    pub dhcp_requested_ip: Option<String>,
    /// IP address assigned by the server (yiaddr or DHCPv6 IA_NA address).
    pub dhcp_assigned_ip: Option<String>,
    /// Client hostname from DHCP Option 12.
    pub dhcp_hostname: Option<String>,
    /// Vendor class identifier from DHCP Option 60.
    pub dhcp_vendor_class: Option<String>,

    // Phase 15E DHCP fields
    /// DHCP protocol version: 4 for DHCPv4, 6 for DHCPv6.
    pub dhcp_version: u8,
    /// True if DHCP Relay Agent Information (Option 82) was present.
    pub dhcp_relay_present: bool,
    /// Circuit ID from Option 82 sub-option 1 â€” identifies ingress port/VLAN.
    pub dhcp_relay_circuit_id: Option<String>,
    /// Remote ID from Option 82 sub-option 2 â€” identifies the relay agent.
    pub dhcp_relay_remote_id: Option<String>,

    // ---------------- ICMP ----------------
    /// ICMP type field (e.g. 8 = echo request, 0 = echo reply).
    pub icmp_type: Option<u8>,
    /// ICMP code field (subtype within the type).
    pub icmp_code: Option<u8>,
    /// Human-readable ICMP description (e.g. "echo-request", "port-unreachable").
    pub icmp_description: Option<String>,

    // ---------------- SMB ----------------
    /// SMB command name (e.g. "NEGOTIATE", "SESSION_SETUP", "TREE_CONNECT").
    pub smb_command: Option<String>,
    /// SMB protocol version detected: "SMB1", "SMB2", "SMB3".
    pub smb_version: Option<String>,
    /// SMB NT status code as human-readable string (e.g. "STATUS_SUCCESS").
    pub smb_status: Option<String>,

    // ---------------- mDNS ----------------
    /// Query name from mDNS question section.
    pub mdns_query_name: Option<String>,
    /// Record type from mDNS answer.
    pub mdns_record_type: Option<String>,
    /// True if this mDNS packet is a response.
    pub mdns_is_response: bool,

    // ---------------- NETWORK ATTRIBUTION (Phase 10B) ----------------
    /// ASN number of the source IP.
    pub src_asn: u32,
    /// ASN organization name for the source IP.
    pub src_asn_org: Option<String>,
    /// Country code for the source IP (ISO 3166-1 alpha-2).
    pub src_country: Option<String>,
    /// ASN number of the destination IP.
    pub dst_asn: u32,
    /// ASN organization name for the destination IP.
    pub dst_asn_org: Option<String>,
    /// Country code for the destination IP.
    pub dst_country: Option<String>,
        /// SMB dialect negotiated: "SMB2.0","SMB2.1","SMB3.0","SMB3.0.2","SMB3.1.1".
    pub smb_dialect: Option<String>,
    /// Share path from TREE_CONNECT request (e.g. "\\\\server\\C$").
    pub smb_share_path: Option<String>,
    /// True if the connected share is an administrative share (path ends with $).
    pub smb_admin_share: bool,
    /// Pass-the-hash heuristic: NTLMSSP AUTHENTICATE with NTChallengeResponse detected.
    pub smb_pth_indicator: bool,
    /// True if SMB3 encryption flag was detected in SMB2 header flags.
    pub smb_encrypted: bool,

// ===== 15G â€” ICMP EXTENDED (add to ICMP section) =====

    /// True if ICMP echo payload exceeds tunnel detection threshold.
    pub icmp_tunnel_suspected: bool,
    /// ICMPv6 Neighbor Discovery message type: "NS","NA","RS","RA","REDIRECT".
    pub icmp_nd_type: Option<String>,
    /// Target IPv6 address from ICMPv6 NS/NA/Redirect messages.
    pub icmp_nd_target: Option<String>,
    /// ICMPv6 NA flags string: "R=1 S=0 O=1" (Router/Solicited/Override).
    pub icmp_nd_flags: Option<String>,

// ===== 15H â€” mDNS EXTENDED (add to mDNS section) =====

    /// DNS-SD service type from mDNS PTR/SRV record (e.g. "_http._tcp").
    pub mdns_service_type: Option<String>,
    /// PTR record rdata â€” the full instance name.
    pub mdns_ptr_target: Option<String>,
    /// Instance name portion of PTR rdata (e.g. "My Printer").
    pub mdns_instance_name: Option<String>,
    /// SRV record target hostname.
    pub mdns_srv_target: Option<String>,
    /// SRV record port number.
    pub mdns_srv_port: Option<u16>,

// ===== 15I â€” ICS/SCADA (new section) =====

    /// ICS protocol detected on this packet: "Modbus" or "DNP3".
    pub ics_protocol: Option<String>,
    /// Modbus function code name (e.g. "READ_HOLDING_REGISTERS").
    pub modbus_function_code: Option<String>,
    /// Modbus unit identifier (slave device address).
    pub modbus_unit_id: Option<u8>,
    /// True if this Modbus response is an exception (error) response.
    pub modbus_exception: bool,
    /// Modbus register/coil starting address from read/write request.
    pub modbus_register_addr: Option<u16>,
    /// Modbus register/coil quantity from read/write request.
    pub modbus_register_count: Option<u16>,
    /// DNP3 application layer function code name.
    pub dnp3_function_code: Option<String>,
    /// DNP3 Internal Indication (IIN) flag string from response.
    pub dnp3_iin_flags: Option<String>,
    /// DNP3 object headers parsed: list of "gXvY" strings (group+variation).
    pub dnp3_objects: Vec<String>,

// ===== Phase 18 — S7comm (Siemens) =====

    /// S7comm PDU type: "JOB", "ACK", "ACK_DATA", "USERDATA", "CR", "CC", "DR".
    pub s7_pdu_type: Option<String>,
    /// S7comm function name (e.g. "READ_VAR", "WRITE_VAR", "PLC_STOP").
    pub s7_function: Option<String>,
    /// S7comm data section length in bytes.
    pub s7_data_len: Option<u16>,

// ===== Phase 18 — EtherNet/IP + CIP =====

    /// EtherNet/IP encapsulation command name (e.g. "SEND_RR_DATA", "LIST_IDENTITY").
    pub enip_command: Option<String>,
    /// EtherNet/IP session handle (non-zero after successful registration).
    pub enip_session_handle: Option<u32>,
    /// CIP service name extracted from the encapsulated CIP request/response.
    pub cip_service: Option<String>,
    /// CIP object class ID from the EPATH.
    pub cip_class: Option<u16>,
    /// CIP object instance ID from the EPATH.
    pub cip_instance: Option<u16>,
    /// CIP status string from the response (e.g. "SUCCESS", "PATH_DEST_UNKNOWN").
    pub cip_status: Option<String>,

// ===== Phase 18 — PROFINET DCP =====

    /// PROFINET DCP frame ID (e.g. 0xFEFE = Identify Request).
    pub profinet_frame_id: Option<u16>,
    /// PROFINET DCP service description string.
    pub profinet_service: Option<String>,
    /// PROFINET station name (from DCP Identify Response block 0x0201).
    pub profinet_station_name: Option<String>,
    /// PROFINET IP address from DCP block 0x0101.
    pub profinet_ip_addr: Option<String>,
    /// PROFINET MAC address from DCP block 0x0102.
    pub profinet_mac: Option<String>,

// ===== Phase 18 — LLDP =====

    /// LLDP Chassis ID (subtype-decoded: MAC, IP, or string).
    pub lldp_chassis_id: Option<String>,
    /// LLDP Port ID (subtype-decoded).
    pub lldp_port_id: Option<String>,
    /// LLDP Time-to-Live in seconds.
    pub lldp_ttl: Option<u16>,
    /// LLDP System Name TLV.
    pub lldp_system_name: Option<String>,
    /// LLDP System Description TLV.
    pub lldp_system_desc: Option<String>,
    /// LLDP Port Description TLV.
    pub lldp_port_desc: Option<String>,
    /// LLDP Management Address (IPv4, IPv6, or MAC).
    pub lldp_mgmt_addr: Option<String>,
    /// LLDP system capabilities string (e.g. "Router(enabled),Bridge(disabled)").
    pub lldp_capabilities: Option<String>,
    /// LLDP 802.1 Port VLAN ID (from org-specific TLV OUI=00:80:C2 subtype=1).
    pub lldp_vlan_id: Option<u16>,

// ===== Phase 18 — CDP =====

    /// CDP Device ID TLV (hostname of the advertising Cisco device).
    pub cdp_device_id: Option<String>,
    /// CDP Port ID TLV (interface name on the advertising device).
    pub cdp_port_id: Option<String>,
    /// CDP Platform TLV (hardware platform string).
    pub cdp_platform: Option<String>,
    /// CDP Version TLV (software version string).
    pub cdp_version: Option<String>,
    /// CDP Capabilities TLV decoded string (e.g. "Router,Switch").
    pub cdp_capabilities: Option<String>,
    /// CDP VTP Management Domain TLV.
    pub cdp_vtp_domain: Option<String>,
    /// CDP Native VLAN TLV.
    pub cdp_native_vlan: Option<u16>,
    /// CDP Addresses TLV — list of IP addresses of the advertising device.
    pub cdp_addresses: Vec<String>,


// ===== 15J â€” ENTERPRISE (new section) =====

    /// Kerberos message type: "AS-REQ","AS-REP","TGS-REQ","TGS-REP","AP-REQ","KRB-ERROR".
    pub krb_msg_type: Option<String>,
    /// Kerberos realm extracted from the message (e.g. "CORP.EXAMPLE.COM").
    pub krb_realm: Option<String>,
    /// Kerberos principal name (e.g. username or service principal).
    pub krb_principal: Option<String>,
    /// Kerberos error code string if this is a KRB-ERROR message.
    pub krb_error_code: Option<String>,
    /// LDAP operation type: "BIND_REQ","SEARCH_REQ","ADD_REQ", etc.
    pub ldap_msg_type: Option<String>,
    /// LDAP search base DN from SearchRequest.
    pub ldap_base_dn: Option<String>,
    /// LDAP bind DN from BindRequest.
    pub ldap_bind_dn: Option<String>,
    /// RDP protocol version label: "RDP".
    pub rdp_version: Option<String>,
    /// RDP routing token / mstshash cookie value.
    pub rdp_cookie: Option<String>,
    /// RDP security protocol: "TLS","CredSSP-NLA","RDP-STANDARD", etc.
    pub rdp_security: Option<String>,

// ===== 15K â€” DISCOVERY (new section) =====

    /// SSDP method: "M-SEARCH", "NOTIFY", or HTTP/1.1 response.
    pub ssdp_method: Option<String>,
    /// SSDP Search Target (ST) or Notification Type (NT) field value.
    pub ssdp_st: Option<String>,
    /// SSDP Unique Service Name (USN) field value.
    pub ssdp_usn: Option<String>,
    /// UPnP device description LOCATION URL.
    pub upnp_location: Option<String>,
    /// UPnP device type from NT/ST (e.g. "urn:schemas-upnp-org:device:MediaServer:1").
    pub upnp_device_type: Option<String>,
    /// FTP command extracted from client request (e.g. "RETR filename.txt").
    /// PASS command value is NEVER stored â€” only "PASS" label.
    pub ftp_command: Option<String>,
    /// FTP server response code (e.g. 220, 230, 550).
    pub ftp_response_code: Option<u16>,
    /// FTP passive mode (PASV) data connection address: "ip:port".
    pub ftp_passive_addr: Option<String>,
    /// True if FTP AUTH or PASS command was observed on this flow.
    pub ftp_auth_seen: bool,
}

impl PacketContext {
    /// Create a new PacketContext with required network fields.
    /// All optional/list fields are initialized to None/empty/false.
    pub fn new(
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: impl Into<String>,
        packet_size: usize,
        timestamp_us: u64,
    ) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol: protocol.into(),
            packet_size,
            timestamp_us,
            flow_id: None,
            flow_packets: 0,

            // DNS
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

            // TLS
            tls_sni: None,
            tls_version: None,
            tls_cipher_suites: Vec::new(),
            tls_alpn: None,
            tls_alpn_protocols: Vec::new(),
            tls_session_resumed: false,

            // TLS cert
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

            // JA3/JA4
            ja3_fingerprint: None,
            ja3_string: None,
            ja3_hash: None,
            ja3s_hash: None,
            ja4: None,
            ja4_hash: None,
            ja3s_fingerprint: None,    
            ja4_fingerprint: None,
            // HTTP
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

            // QUIC
            quic_version: None,
            // Phase 15D
            quic_0rtt: false,
            quic_short_header: false,

            // DHCP
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

            // ICMP
            icmp_type: None,
            icmp_code: None,
            icmp_description: None,

            // SMB
            smb_command: None,
            smb_version: None,
            smb_status: None,

            // mDNS
            mdns_query_name: None,
            mdns_record_type: None,
            mdns_is_response: false,

            // Network attribution
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

// mDNS
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