# Changelog

## [1.0.0] — 2026

### Initial open source release

- Deterministic packet processing pipeline
- PCAP SHA-256 + config SHA-256 chain of custody
- Multi-threaded WorkerPool with flow-affinity routing
- Worker shard merge — single clean NDJSON per session
- AF_XDP zero-copy capture (falls back to pcap if hardware unsupported)
- Four operation modes: Forensic, Monitor, Stealth, Replay
- Hardware auto-scaling
- 14 protocol analyzers: DNS, TLS, HTTP/1.1, HTTP/2, QUIC, DHCP, ICMP,
  SMB, mDNS, DoH, DoT, Kerberos/LDAP/RDP, SSDP/UPnP/FTP
- FNV-1a FlowTable with LRU eviction
- TCP reassembly with explicit gap markers
- JA3/JA4 fingerprint databases (50 + 110 entries)
- IANA port/service name database (6,255 entries)
