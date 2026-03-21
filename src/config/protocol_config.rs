// src/config/protocol_config.rs
//
// Protocol layer configuration â€” controls which analyzers run and their limits.
//
// Phase 15 Part 1 additions:
//   15A DNS:  dns_dnssec_track (enable DNSSEC record extraction),
//             dns_doq_port (configurable DoQ port, default 853)
//   15B TLS:  tls_track_ech (log ECH presence), tls_track_ocsp (log OCSP requests),
//             tls_track_early_data (log 0-RTT)
//   15C HTTP: http_track_websocket, http_track_referer, http_track_xff
//   15D QUIC: quic_track_0rtt, quic_v2_enabled (parse QUIC v2 frames)
//   15E DHCP: dhcp_track_relay (parse Option 82), enable_dhcpv6
//
// Phase 4 (preserved): 200+ params, 7 layers, all prior config fields.

#[derive(Clone)]
pub struct ProtocolConfig {
    // ---------------- PROTOCOL GATES ----------------
    pub enable_dns: bool,
    pub enable_tls: bool,
    pub enable_quic: bool,
    pub enable_icmp: bool,
    pub enable_http: bool,
    pub enable_dhcp: bool,
    pub enable_smb: bool,
    pub enable_mdns: bool,
    /// Enable FTP command channel analysis (port 21).
    pub enable_ftp: bool,
    /// Enable SSH version string extraction (port 22).
    pub enable_ssh: bool,
    /// Phase 15E: Enable DHCPv6 analysis on ports 546/547.
    pub enable_dhcpv6: bool,

    // ---------------- PORT LISTS ----------------
    /// List of ports on which HTTP/1.x and HTTP/2 analysis is attempted.
    pub http_ports: Vec<u16>,
    /// List of ports on which TLS analysis is attempted.
    pub tls_ports: Vec<u16>,
    /// List of ports on which QUIC analysis is attempted.
    pub quic_ports: Vec<u16>,
    /// Ports on which SMB analysis is attempted.
    pub smb_ports: Vec<u16>,
    /// Ports on which DHCP analysis is attempted.
    pub dhcp_ports: Vec<u16>,
    /// mDNS port (always 5353 per RFC 6762, configurable for non-standard deployments).
    pub mdns_port: u16,
    /// FTP command channel port.
    pub ftp_port: u16,
    /// SSH port.
    pub ssh_port: u16,

    // ---------------- INTELLIGENCE ----------------
    pub enable_dns_resolution: bool,
    pub enable_flow_domain_binding: bool,
    pub tls_intelligence_enabled: bool,

    // ---------------- PROTOCOL CONSTANTS ----------------
    pub dns_port: u16,
    pub dns_payload_offset: usize,
    pub dns_header_length: usize,
    pub tls_record_handshake: u8,
    pub tls_client_hello: u8,

    // ---------------- DNS LIMITS ----------------
    /// Maximum questions to parse per DNS packet.
    pub dns_max_questions: u16,
    /// Maximum answer records to parse per DNS response.
    pub dns_max_answers: u16,
    /// Phase 15A: enable extraction of DNSSEC record types (DS/RRSIG/NSEC/DNSKEY/NSEC3).
    pub dns_dnssec_track: bool,
    /// Phase 15A: DNS-over-QUIC port. Default 853 per RFC 9250.
    pub dns_doq_port: u16,

    // ---------------- TLS LIMITS ----------------
    /// Maximum TLS record body size in bytes.
    pub tls_max_record_size: usize,
    /// Extract and store X.509 certificate fields from TLS handshakes.
    pub tls_cert_extraction: bool,
    /// Phase 15B: log when ECH extension is detected in ClientHello.
    pub tls_track_ech: bool,
    /// Phase 15B: log when client requests OCSP stapling.
    pub tls_track_ocsp: bool,
    /// Phase 15B: log when TLS 1.3 0-RTT Early Data is attempted.
    pub tls_track_early_data: bool,

    // ---------------- HTTP LIMITS ----------------
    /// Maximum number of bytes from HTTP response body to preview/store.
    pub http_max_body_preview: usize,
    /// Track HTTP cookies (Cookie / Set-Cookie headers).
    pub http_track_cookies: bool,
    /// Phase 15C: extract and store WebSocket upgrade events.
    pub http_track_websocket: bool,
    /// Phase 15C: extract and store Referer header values.
    pub http_track_referer: bool,
    /// Phase 15C: extract and store X-Forwarded-For header values.
    pub http_track_xff: bool,

    // ---------------- QUIC LIMITS ----------------
    /// Maximum bytes to scan in QUIC CRYPTO frames for TLS ClientHello.
    pub quic_max_crypto_scan: usize,
    /// Phase 15D: emit events on QUIC 0-RTT packet detection.
    pub quic_track_0rtt: bool,
    /// Phase 15D: enable QUIC v2 (RFC 9369) frame parsing.
    /// QUIC v2 uses the same Initial packet structure as v1.
    pub quic_v2_enabled: bool,

    // ---------------- ICMP ----------------
    pub icmp_track_flood: bool,
    pub icmp_flood_threshold: u32,

    // ---------------- SMB ----------------
    pub smb_track_auth: bool,

    // ---------------- DHCP ----------------
    pub dhcp_track_leases: bool,
    /// Phase 15E: parse DHCP Option 82 (Relay Agent Information) sub-options.
    pub dhcp_track_relay: bool,

    // ---------------- JA3 ----------------
    pub ja3_enabled: bool,
    pub ja3_strip_grease: bool,
    pub ja3_normalize_version: bool,
    pub ja3_strict_parsing: bool,

    // ---------------- JA3S ----------------
    pub ja3s_enabled: bool,

    // ---------------- JA4 ----------------
    pub ja4_enabled: bool,
    pub ja4_quic_support: bool,
    pub ja4_extension_normalization: bool,
    pub ja4_alpn_normalization: bool,
    pub ja4_cipher_normalization: bool,

    // ---------------- DoH DETECTION ----------------
    pub doh_detection: bool,
    /// Enable Modbus/TCP and DNP3 protocol analysis.
    pub enable_ics: bool,
    /// Enable LLDP and CDP LAN discovery protocol analysis.
    pub enable_lan: bool,
    /// Modbus/TCP port (default 502).
    pub modbus_port: u16,
    /// DNP3 port (default 20000).
    pub dnp3_port: u16,

    // Phase 15J: Enterprise
    /// Enable Kerberos (port 88) analysis.
    pub enable_kerberos: bool,
    /// Enable LDAP (ports 389/636) analysis.
    pub enable_ldap: bool,
    /// Enable RDP (port 3389) analysis.
    pub enable_rdp: bool,

    // Phase 15K: Discovery
    /// Enable SSDP/UPnP analysis (port 1900).
    pub enable_ssdp: bool,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            // Protocol gates
            enable_dns: true,
            enable_tls: true,
            enable_quic: true,
            enable_icmp: true,
            enable_http: true,
            enable_dhcp: true,
            enable_smb: true,
            enable_mdns: true,
            enable_ftp: false,
            enable_ssh: false,
            enable_dhcpv6: true, // Phase 15E: on by default

            // Port lists
            http_ports: vec![80, 8080, 8000, 3000, 8008, 8888],
            tls_ports: vec![443, 8443, 853, 993, 465, 636, 995, 587],
            quic_ports: vec![443, 80],
            smb_ports: vec![445, 139],
            dhcp_ports: vec![67, 68],
            mdns_port: 5353,
            ftp_port: 21,
            ssh_port: 22,

            // Intelligence
            enable_dns_resolution: true,
            enable_flow_domain_binding: true,
            tls_intelligence_enabled: true,

            // Protocol constants
            dns_port: 53,
            dns_payload_offset: 42,
            dns_header_length: 12,
            tls_record_handshake: 0x16,
            tls_client_hello: 0x01,

            // DNS limits
            dns_max_questions: 16,
            dns_max_answers: 64,
            dns_dnssec_track: true,   // Phase 15A: on by default
            dns_doq_port: 853,        // Phase 15A: RFC 9250 default

            // TLS limits
            tls_max_record_size: 20_480,
            tls_cert_extraction: true,
            tls_track_ech: true,        // Phase 15B: on by default
            tls_track_ocsp: true,       // Phase 15B: on by default
            tls_track_early_data: true, // Phase 15B: on by default

            // HTTP limits
            http_max_body_preview: 0,
            http_track_cookies: false,
            http_track_websocket: true, // Phase 15C: on by default
            http_track_referer: false,  // Phase 15C: off by default (privacy-sensitive)
            http_track_xff: true,       // Phase 15C: on by default

            // QUIC limits
            quic_max_crypto_scan: 4096,
            quic_track_0rtt: true,    // Phase 15D: on by default
            quic_v2_enabled: true,    // Phase 15D: QUIC v2 parsing enabled

            // ICMP
            icmp_track_flood: false,
            icmp_flood_threshold: 100,

            // SMB
            smb_track_auth: true,

            // DHCP
            dhcp_track_leases: true,
            dhcp_track_relay: true, // Phase 15E: on by default

            // JA3
            ja3_enabled: true,
            ja3_strip_grease: true,
            ja3_normalize_version: true,
            ja3_strict_parsing: true,

            // JA3S
            ja3s_enabled: true,

            // JA4
            ja4_enabled: true,
            ja4_quic_support: true,
            ja4_extension_normalization: true,
            ja4_alpn_normalization: true,
            ja4_cipher_normalization: true,

            // DoH
            doh_detection: true,
            // ICS
            enable_ics: true,
            // LAN discovery
            enable_lan: true,
            modbus_port: 502,
            dnp3_port: 20000,

            // Enterprise
            enable_kerberos: true,
            enable_ldap: true,
            enable_rdp: true,

            // Discovery
            enable_ssdp: true,
        }
    }
}