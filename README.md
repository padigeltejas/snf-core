# SNF-Core

**Shadow Network Fingerprinting Engine — Open Source Core**

A deterministic, offline-first network protocol analysis engine written in Rust.

## Determinism Guarantee
```
F(dataset, config, version) → identical NDJSON output
```

Same PCAP + same config + same binary = SHA-256 identical output. Always.

## Protocol Support

| Protocol | Fields Extracted |
|---|---|
| DNS | Query/response, CNAME, MX/NS/TXT/SRV, resolved IPs, TTL, DNSSEC |
| TLS 1.0–1.3 | SNI, cipher suites, ALPN, ECH, certificate chain, JA3/JA4 |
| HTTP/1.1 | Method, URI, Host, status, User-Agent, Content-Type |
| HTTP/2 | HPACK headers, pseudo-headers |
| QUIC v1/v2 | Version, connection IDs, SNI |
| DHCPv4/v6 | Message type, client MAC, hostname, IP assignment |
| ICMPv4/v6 | Type, code, traceroute detection |
| SMB 1/2/3 | Command, NTLM auth, dialect |
| mDNS | Service type, PTR/SRV/TXT records |
| DoH / DoT | Detection via confidence scoring |
| Kerberos / LDAP / RDP | Enterprise protocol detection |
| SSDP / UPnP / FTP | Discovery and command parsing |

## Quick Start
```bash
git clone https://github.com/padigeltejas/snf-core
cd snf-core
cargo build --release

# Analyse a PCAP
./target/release/snf-core --forensic --pcap-file capture.pcap

# Live capture (requires root/Administrator)
sudo ./target/release/snf-core --monitor --interface 1  # use --help to find your interface index

# Verify determinism
./target/release/snf-core --determinism-check --pcap-file capture.pcap
```

## Documentation

- [Architecture](docs/01_architecture.md)
- [Determinism Contract](docs/02_determinism.md)
- [Protocol Support](docs/03_protocol_support.md)
- [Event Model](docs/04_event_model.md)
- [Deployment Guide](docs/05_deployment.md)
- [Extending SNF-Core](docs/06_extending.md)

## License

Apache 2.0 — Copyright 2026 Tejas Padigel
