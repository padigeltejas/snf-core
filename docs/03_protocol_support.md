# Protocol Support Reference

SNF-Core runs 18 protocol analyzers in a fixed, deterministic order on every packet. Each analyzer is independently config-gated — disable any analyzer without affecting others.

---

## Analyzer Execution Order

Analyzers execute in this exact sequence on every packet, regardless of protocol:

```
 1. DNS
 2. TLS (JA3/JA3S/JA4)
 3. HTTP/1.1
 4. HTTP/2
 5. QUIC
 6. DHCP
 7. ICMP
 8. SMB
 9. mDNS
10. DoH / DoT
11. ICS: Modbus
12. ICS: DNP3
13. ICS: S7comm
14. ICS: EtherNet/IP + CIP
15. ICS: PROFINET
16. LAN: LLDP
17. LAN: CDP
18. Enterprise: Kerberos / LDAP / RDP
19. Discovery: SSDP / UPnP / FTP
```

Fixed order ensures that upstream analyzers can set fields on `PacketContext` that downstream analyzers read — e.g., DNS resolving a domain before TLS processes the SNI from the same flow.

---

## Protocol Reference

### DNS
**Config gate:** `enable_dns = true`
**Ports:** UDP/TCP 53
**Events:** `DnsQuery`, `DnsResponse`

| Field | Type | Description |
|---|---|---|
| `query_name` | string | Queried domain name |
| `is_response` | bool | Query or response |
| `record_type` | string | A, AAAA, CNAME, MX, NS, TXT, SRV, PTR |
| `resolved_ip` | ip | Resolved IP address (A/AAAA responses) |
| `ttl` | u64 | Record TTL in seconds |
| `cname_chain` | string[] | Full CNAME resolution chain |
| `mx_records` | string[] | MX record hostnames |
| `ns_records` | string[] | NS record hostnames |
| `txt_records` | string[] | TXT record values |
| `srv_records` | string[] | SRV record values |
| `ptr_record` | string | PTR reverse lookup result |
| `dns_truncated` | bool | TC bit set (message truncated) |
| `dns_dnssec_present` | bool | DNSSEC records present |
| `dns_transport` | string | `udp` or `tcp` |

---

### TLS 1.0–1.3
**Config gate:** `enable_tls = true`
**Ports:** TCP 443, 8443, and any port with TLS traffic
**Events:** `TlsClientHello`, `TlsServerHello`

#### Client Hello fields
| Field | Type | Description |
|---|---|---|
| `sni` | string | Server Name Indication |
| `tls_version` | string | Negotiated TLS version |
| `cipher_suites` | u16[] | Offered cipher suites (GREASE filtered) |
| `alpn` | string | Primary ALPN protocol |
| `alpn_protocols` | string[] | Full ALPN list |
| `session_resumed` | bool | Session resumption detected |
| `tls_early_data` | bool | TLS 1.3 0-RTT early data |
| `tls_ech_present` | bool | Encrypted Client Hello extension present |
| `ja3` | string | JA3 fingerprint string |
| `ja3_hash` | string | JA3 MD5 hash |
| `ja3_label` | string | JA3 database label (if matched) |
| `ja4` | string | JA4 fingerprint string |
| `ja4_hash` | string | JA4 MD5 hash |
| `ja4_label` | string | JA4 database label (if matched) |

#### Server Hello / Certificate fields
| Field | Type | Description |
|---|---|---|
| `ja3s` | string | JA3S server fingerprint hash |
| `ja3s_label` | string | JA3S database label (if matched) |
| `cert_cn` | string | Certificate Common Name |
| `cert_sans` | string[] | Subject Alternative Names |
| `cert_issuer` | string | Certificate issuer |
| `cert_not_after` | string | Certificate expiry date |
| `cert_self_signed` | bool | Self-signed certificate |
| `cert_expired` | bool | Certificate is expired |
| `cert_chain_len` | u64 | Certificate chain depth |
| `tls_ocsp_stapling` | bool | OCSP stapling requested |

---

### HTTP/1.1
**Config gate:** `enable_http = true`
**Ports:** TCP 80, 8080, 8000, and detected HTTP on any port
**Events:** `HttpRequest`, `HttpResponse`

| Field | Type | Description |
|---|---|---|
| `method` | string | GET, POST, PUT, DELETE, etc. |
| `uri` | string | Request URI path |
| `http_version` | string | HTTP/1.0, HTTP/1.1 |
| `host` | string | Host header value |
| `user_agent` | string | User-Agent header |
| `content_type` | string | Content-Type header |
| `content_length` | u64 | Content-Length header value |
| `status_code` | u16 | Response status code |
| `http_websocket` | bool | WebSocket upgrade detected |
| `http_upgrade` | string | Upgrade header value |
| `http_referer` | string | Referer header value |
| `http_xff` | string | X-Forwarded-For header |
| `http_status_class` | string | `2xx`, `3xx`, `4xx`, `5xx` |

---

### HTTP/2
**Config gate:** `enable_http = true`
**Ports:** TCP 443 (via ALPN h2 negotiation)
**Events:** `HttpRequest`, `HttpResponse`

HPACK-decoded pseudo-headers and regular headers. Fields mirror HTTP/1.1 where applicable. `:authority` pseudo-header maps to `host`.

---

### QUIC v1/v2
**Config gate:** `enable_quic = true`
**Ports:** UDP 443
**Events:** `QuicSni`

| Field | Type | Description |
|---|---|---|
| `quic_version` | string | QUIC version identifier |
| `sni` | string | SNI from QUIC Client Initial |
| `quic_0rtt` | bool | 0-RTT early data attempted |
| `quic_short_header` | bool | Short header packet detected |

---

### DHCP v4/v6
**Config gate:** `enable_dhcp = true`
**Ports:** UDP 67/68 (v4), UDP 546/547 (v6)
**Events:** `DhcpMessage`

| Field | Type | Description |
|---|---|---|
| `dhcp_msg_type` | string | DISCOVER, OFFER, REQUEST, ACK, NAK, RELEASE |
| `dhcp_client_mac` | string | Client hardware address |
| `dhcp_requested_ip` | string | Requested IP address |
| `dhcp_assigned_ip` | string | Assigned IP address |
| `dhcp_hostname` | string | Client hostname option (option 12) |
| `dhcp_vendor_class` | string | Vendor class identifier (option 60) |
| `dhcp_version` | u64 | 4 or 6 |
| `dhcp_relay_present` | bool | DHCP relay agent detected |
| `dhcp_relay_circuit_id` | string | Relay agent circuit ID |
| `dhcp_relay_remote_id` | string | Relay agent remote ID |

---

### ICMPv4/v6
**Config gate:** `enable_icmp = true`
**Events:** `IcmpMessage`

| Field | Type | Description |
|---|---|---|
| `icmp_type` | u8 | ICMP type code |
| `icmp_code` | u8 | ICMP code |
| `icmp_description` | string | Human-readable type description |
| `icmp_tunnel_suspected` | bool | Payload size anomaly detected |
| `icmp_nd_type` | string | NDP message type (ICMPv6) |
| `icmp_nd_target` | string | NDP target address |
| `icmp_nd_flags` | string | NDP flags |

---

### SMB 1/2/3
**Config gate:** `enable_smb = true`
**Ports:** TCP 445, 139
**Events:** `SmbSession`

| Field | Type | Description |
|---|---|---|
| `smb_command` | string | SMB command name |
| `smb_version` | string | SMB1, SMB2, SMB3 |
| `smb_status` | string | NT status code |
| `smb_dialect` | string | Negotiated SMB dialect |
| `smb_share_path` | string | UNC share path |
| `smb_admin_share` | bool | Administrative share (C$, ADMIN$, IPC$) |
| `smb_pth_indicator` | bool | Pass-the-Hash pattern detected |
| `smb_encrypted` | bool | SMB3 encryption active |

---

### mDNS
**Config gate:** `enable_mdns = true`
**Ports:** UDP 5353
**Events:** `MdnsRecord`

| Field | Type | Description |
|---|---|---|
| `mdns_query_name` | string | Queried service/host name |
| `mdns_record_type` | string | A, AAAA, PTR, SRV, TXT |
| `mdns_is_response` | bool | Query or response |
| `mdns_service_type` | string | Service type (e.g., `_http._tcp`) |
| `mdns_ptr_target` | string | PTR record target |
| `mdns_instance_name` | string | Service instance name |
| `mdns_srv_target` | string | SRV target hostname |
| `mdns_srv_port` | u16 | SRV target port |

---

### DoH / DoT Detection
**Config gate:** `doh_detection = true`
**Events:** `DohDetected`, `DotDetected`

Detects DNS-over-HTTPS via HTTP/2 patterns and application/dns-message content types. Detects DNS-over-TLS via port 853 TLS sessions with DNS-pattern payloads. No deep payload inspection required.

---

### ICS/SCADA Protocols
**Config gate:** `enable_ics = true`

#### Modbus
**Port:** TCP 502
**Events:** `IcsModbus`

| Field | Type | Description |
|---|---|---|
| `modbus_function_code` | u8 | Function code (1–127) |
| `modbus_unit_id` | u8 | Unit/slave identifier |
| `modbus_exception` | bool | Exception response |
| `modbus_register_addr` | u16 | Register start address |
| `modbus_register_count` | u16 | Number of registers |

#### DNP3
**Port:** TCP 20000
**Events:** `IcsDnp3`

| Field | Type | Description |
|---|---|---|
| `dnp3_function_code` | u8 | Application layer function code |
| `dnp3_iin_flags` | string | Internal Indication Flags |
| `dnp3_objects` | string[] | Data object descriptors |

#### S7comm (Siemens)
**Port:** TCP 102 (via COTP/ISO-TSAP)
**Events:** `IcsS7`

| Field | Type | Description |
|---|---|---|
| `s7_pdu_type` | string | JOB, ACK, ACK_DATA, USERDATA |
| `s7_function` | string | Read/Write/Control function |
| `s7_data_len` | u64 | Data payload length |

#### EtherNet/IP + CIP
**Port:** TCP 44818 / UDP 2222
**Events:** `IcsEnip`

| Field | Type | Description |
|---|---|---|
| `enip_command` | string | EtherNet/IP command |
| `enip_session_handle` | u64 | Session handle |
| `cip_service` | string | CIP service code |
| `cip_class` | u64 | CIP object class |
| `cip_instance` | u64 | CIP object instance |
| `cip_status` | string | CIP status code |

#### PROFINET
**Events:** `IcsProfinet`

| Field | Type | Description |
|---|---|---|
| `profinet_frame_id` | string | Frame ID |
| `profinet_service` | string | DCP service |
| `profinet_station_name` | string | Station name |
| `profinet_ip_addr` | string | Station IP address |
| `profinet_mac` | string | Station MAC address |

---

### LAN Discovery

#### LLDP
**Events:** `LanLldp`

| Field | Type | Description |
|---|---|---|
| `lldp_chassis_id` | string | Chassis identifier |
| `lldp_port_id` | string | Port identifier |
| `lldp_ttl` | u64 | Time to live |
| `lldp_system_name` | string | System name |
| `lldp_system_desc` | string | System description |
| `lldp_capabilities` | string | System capabilities |
| `lldp_mgmt_addr` | string | Management address |
| `lldp_vlan_id` | u16 | Port VLAN ID |

#### CDP (Cisco Discovery Protocol)
**Events:** `LanCdp`

| Field | Type | Description |
|---|---|---|
| `cdp_device_id` | string | Device identifier |
| `cdp_port_id` | string | Port identifier |
| `cdp_platform` | string | Hardware platform |
| `cdp_version` | string | Software version |
| `cdp_capabilities` | string | Device capabilities |
| `cdp_vtp_domain` | string | VTP management domain |
| `cdp_native_vlan` | u16 | Native VLAN |
| `cdp_addresses` | string[] | IP addresses |

---

### Enterprise Protocols

#### Kerberos
**Config gate:** `enable_kerberos = true`
**Port:** TCP/UDP 88
**Events:** `EnterpriseKerberos`

| Field | Type | Description |
|---|---|---|
| `krb_msg_type` | string | AS-REQ, AS-REP, TGS-REQ, TGS-REP, KRB-ERROR |
| `krb_realm` | string | Kerberos realm |
| `krb_principal` | string | Client principal name |
| `krb_error_code` | string | Error code (on KRB-ERROR) |

#### LDAP
**Config gate:** `enable_ldap = true`
**Port:** TCP 389
**Events:** `EnterpriseLdap`

| Field | Type | Description |
|---|---|---|
| `ldap_msg_type` | string | BindRequest, SearchRequest, etc. |
| `ldap_base_dn` | string | Search base DN |
| `ldap_bind_dn` | string | Bind DN (authentication) |

#### RDP
**Config gate:** `enable_rdp = true`
**Port:** TCP 3389
**Events:** `EnterpriseRdp`

| Field | Type | Description |
|---|---|---|
| `rdp_version` | string | RDP protocol version |
| `rdp_cookie` | string | Connection cookie |
| `rdp_security` | string | Security protocol (TLS, NLA, RDP) |

---

### Discovery Protocols

#### SSDP / UPnP
**Config gate:** `enable_ssdp = true`
**Port:** UDP 1900
**Events:** `DiscoverySsdp`

| Field | Type | Description |
|---|---|---|
| `ssdp_method` | string | M-SEARCH, NOTIFY, HTTP |
| `ssdp_st` | string | Search target |
| `ssdp_usn` | string | Unique service name |
| `upnp_location` | string | UPnP device description URL |
| `upnp_device_type` | string | UPnP device type |

#### FTP
**Config gate:** `enable_ftp = true`
**Port:** TCP 21
**Events:** `DiscoveryFtp`

| Field | Type | Description |
|---|---|---|
| `ftp_command` | string | FTP command |
| `ftp_response_code` | u16 | FTP response code |
| `ftp_passive_addr` | string | PASV/EPSV address |
| `ftp_auth_seen` | bool | AUTH TLS/SSL detected |

---

## Threat Intelligence Events

These events are emitted when IOC matching or fingerprint matching produces a result.

### `intel.ioc_match`
Emitted when a packet's source or destination IP, or a DNS query domain, matches the offline IOC blocklist.

| Field | Type | Description |
|---|---|---|
| `ioc_type` | string | `ip` or `domain` |
| `matched_ip` | ip | Matched IP address (IP matches) |
| `matched_domain` | string | Matched domain (domain matches) |
| `direction` | string | `src` or `dst` (IP matches) |
| `label` | string | IOC label (e.g., `Emotet_C2`) |
| `confidence` | string | Confidence score 1–100 |
| `threat_actor` | string | Threat actor attribution |

### `intel.threat_match`
Emitted when a JA3 or JA4 fingerprint matches a known-malicious entry in the fingerprint database.

| Field | Type | Description |
|---|---|---|
| `fingerprint_type` | string | `ja3` or `ja4` |
| `hash` | string | Fingerprint hash |
| `label` | string | Database label |
| `threat_actor` | string | Threat actor attribution |

---

## Adding a Protocol

See [06_extending.md](06_extending.md) for step-by-step instructions on adding a new protocol analyzer.
