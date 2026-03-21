# Protocol Support Reference

14 analyzers run in fixed deterministic order on every packet.

| Analyzer | Port(s) | Config Gate | Event Type |
|---|---|---|---|
| DNS | UDP/TCP 53 | enable_dns | DnsQuery, DnsResponse |
| TLS | TCP 443+ | enable_tls | TlsClientHello, TlsServerHello |
| HTTP/1.1 | TCP 80/8080 | enable_http | HttpRequest, HttpResponse |
| HTTP/2 | TCP 443 | enable_http | HttpRequest, HttpResponse |
| QUIC | UDP 443 | enable_quic | QuicSni |
| DHCP | UDP 67/68 | enable_dhcp | DhcpMessage |
| ICMP | IP proto 1/58 | enable_icmp | IcmpMessage |
| SMB | TCP 445/139 | enable_smb | SmbSession |
| mDNS | UDP 5353 | enable_mdns | MdnsRecord |
| DoH | TCP 443 | enable_dns | DohDetected |
| DoT | TCP 853 | enable_tls | DotDetected |
| Kerberos/LDAP/RDP | TCP 88/389/3389 | enable_kerberos/ldap/rdp | (enterprise) |
| SSDP/UPnP/FTP | UDP 1900 / TCP 21 | enable_ssdp/ftp | (discovery) |

See source files in src/analyzers/ for full field documentation.
