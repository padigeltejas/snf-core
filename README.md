# SNF-Core

<div align="center">

**Shadow Network Fingerprinting Engine — Open Source Core**

*Passive. Deterministic. Offline. Written in Rust.*

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey.svg)]()
[![Build](https://img.shields.io/badge/Build-Passing-brightgreen.svg)]()

</div>

---

SNF-Core is a **passive network forensics engine** that fingerprints traffic, extracts protocol metadata, and matches against offline threat intelligence — with zero network calls, zero cloud dependency, and guaranteed deterministic output.

Same PCAP + same config + same binary = **SHA-256 identical NDJSON output. Always.**

```
F(dataset, config, version) → identical NDJSON output
```

---

## Why SNF-Core

Most network analysis tools phone home, require cloud subscriptions, or produce non-reproducible output. SNF-Core is built for environments where that is unacceptable:

- **Air-gapped networks** — ICS/SCADA, defense, critical infrastructure
- **Forensic investigations** — reproducible, court-admissible evidence chains
- **Threat hunting** — offline IOC matching against known malware C2 infrastructure
- **Research** — deterministic output enables reproducible experiments

---

## Detection in Action

Running SNF-Core against a real Emotet epoch-3 infection PCAP:

```
══════════════════════════════════════════════════════
  SNF — Shadow Network Fingerprinting Engine
  Session Report
══════════════════════════════════════════════════════

  Source      : emotet-epoch3-trickbot.pcap
  Duration    : 3213s
  SNF Version : 1.0.0

─── TRAFFIC SUMMARY ────────────────────────────────
  Packets        : 15,521
  Bytes          : 15,740,188
  Flows          : 278
  Events emitted : 15,521

─── PROTOCOL BREAKDOWN ─────────────────────────────
  DNS queries    : 18
  TLS handshakes : 16
  HTTP requests  : 20

─── THREAT INDICATORS ──────────────────────────────
  IOC hits       : 23        ← Emotet C2 IPs matched
  Threat matches : 52        ← JA3/JA4 fingerprints matched
  Behavior alerts: 0
  Parse errors   : 0
```

**23 Emotet C2 IP hits and 52 malicious TLS fingerprint matches — fully offline, no cloud lookup.**

---

## Features

### Protocol Analysis
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
| Modbus | Function code, unit ID, register address/count |
| DNP3 | Function code, IIN flags, object list |
| S7comm | PDU type, function, data length |
| EtherNet/IP | Command, session handle, CIP service/class/instance |
| PROFINET | Frame ID, service, station name |
| LLDP / CDP | Chassis ID, port, system name, capabilities |
| Kerberos / LDAP / RDP | Enterprise protocol detection |
| SSDP / UPnP / FTP | Discovery and command parsing |

### Threat Intelligence
- **JA3/JA4 fingerprinting** — TLS client fingerprints matched against known malware and threat actor databases
- **Offline IOC matching** — IP and domain blocklists loaded at startup, O(1) lookup per packet
- **Suffix-aware domain matching** — `sub.evil.com` matches an entry for `evil.com`
- **Threat actor attribution** — Cobalt Strike, Emotet, TrickBot, APT28/29/41, Lazarus Group, and more

### Behavioral Detection
- **Beacon detection** — periodic C2 communication patterns
- **DGA scoring** — n-gram entropy analysis for domain generation algorithms
- **DNS tunneling** — Shannon entropy + volume thresholds
- **Port scan detection** — horizontal and vertical sweep detection
- **ICMP flood tracking** — volumetric flood detection
- **SMB lateral movement** — authentication failure storms and fan-out

### Architecture
- **Multi-threaded** — configurable worker pool, auto-scales to hardware
- **Per-worker EvidenceBundle** — merged at session end for complete reports in all modes
- **Flow tracking** — stateful TCP/UDP flow table with LRU eviction
- **NDJSON output** — one event per line, streaming, machine-readable
- **Zero-copy paths** — AF_XDP and DPDK support in commercial edition

---

## Quick Start

**Requirements**
- Rust 1.75+
- Linux: `libpcap-dev` — Windows: [Npcap](https://npcap.com)

```bash
git clone https://github.com/padigeltejas/snf-core
cd snf-core
cargo build --release
```

**Analyse a PCAP**
```bash
./target/release/snf-core --forensic --pcap-file capture.pcap
```

**Live capture**
```bash
sudo ./target/release/snf-core --monitor --interface eth0
```

**Verify determinism**
```bash
./target/release/snf-core --determinism-check --pcap-file capture.pcap
```

**With custom config**
```bash
./target/release/snf-core --forensic --pcap-file capture.pcap --config snf.toml
```

---

## Output Format

SNF-Core emits structured NDJSON — one event per line. Every event includes a timestamp, flow ID, protocol, and typed attributes.

```json
{"snf_event":{"v":1,"pid":1234,"ts":1700000000000000,"type":"tls.client_hello","proto":"TLS","flow":"192.168.1.5:49200-185.220.101.1:443-TCP","attrs":{"sni":"c2.example.com","ja3":"abc123...","ja3_label":"CobaltStrike_default","tls_version":"TLS1.2"}}}
{"snf_event":{"v":1,"pid":1235,"ts":1700000000001000,"type":"intel.ioc_match","proto":"IOC","flow":"192.168.1.5:49200-185.220.101.1:443-TCP","attrs":{"ioc_type":"ip","matched_ip":"185.220.101.1","label":"Emotet_C2","confidence":"92","threat_actor":"Emotet"}}}
{"snf_event":{"v":1,"pid":1236,"ts":1700000000002000,"type":"intel.threat_match","proto":"TLS","flow":"192.168.1.5:49200-185.220.101.1:443-TCP","attrs":{"fingerprint_type":"ja3","hash":"abc123...","label":"CobaltStrike_default","threat_actor":"Cobalt Strike"}}}
```

---

## Configuration

Copy `snf.toml` from the repo root and edit as needed:

```toml
[output]
output_dir = "output"
verbosity  = 1

[protocol]
enable_tls  = true
enable_dns  = true
enable_http = true
ja3_enabled = true
ja4_enabled = true

[intelligence]
ioc_matching_enabled      = true
ioc_ip_blocklist_path     = "datasets/ioc/ip_blocklist.csv"
ioc_domain_blocklist_path = "datasets/ioc/domain_blocklist.csv"
```

Full configuration reference: [`docs/05_deployment.md`](docs/05_deployment.md)

---

## Documentation

- [Architecture Overview](docs/01_architecture.md)
- [Determinism Contract](docs/02_determinism.md)
- [Protocol Support](docs/03_protocol_support.md)
- [Event Model](docs/04_event_model.md)
- [Deployment Guide](docs/05_deployment.md)
- [Extending SNF-Core](docs/06_extending.md)

---

## Datasets

SNF-Core ships with curated datasets under `datasets/`:

```
datasets/
  ja3/   — JA3 fingerprint database with threat actor labels
  ja4/   — JA4 fingerprint database
  ioc/   — IP and domain blocklists (Emotet, TrickBot, Cobalt Strike, APT28/29/41, Lazarus...)
  ports/ — Port-to-service mapping
```

To add your own IOC feeds, append rows to the CSV files:
```
# datasets/ioc/ip_blocklist.csv
ip,label,confidence,threat_actor
1.2.3.4,CustomC2,85,Custom Actor
```

---

## Platform Support

| Platform | Capture | PCAP Replay | Tested |
|---|---|---|---|
| Linux (RHEL 9) | ✅ | ✅ | ✅ |
| Linux (Ubuntu 22+) | ✅ | ✅ | ✅ |
| Windows 10/11 | ✅ | ✅ | ✅ |
| macOS | ⚠️ untested | ⚠️ untested | ❌ |

---

## Open Core

SNF-Core is the open source protocol analysis layer of the Shadow Network Fingerprinting Engine. It is complete and production-ready as a standalone tool.

The **commercial edition** adds:

| Feature | Open Core | Commercial |
|---|---|---|
| Protocol analyzers | 18 | 18 |
| JA3/JA4 fingerprinting | ✅ | ✅ |
| Offline IOC matching | ✅ | ✅ |
| Behavioral detection | ✅ | ✅ |
| ICS/SCADA support | ✅ | ✅ |
| Beacon detection | ✅ | ✅ |
| Baseline comparison | ❌ | ✅ |
| Graph engine | ❌ | ✅ |
| Timeline engine | ❌ | ✅ |
| Stealth detection | ❌ | ✅ |
| AF_XDP / DPDK | ❌ | ✅ |
| Support & SLA | ❌ | ✅ |

Commercial inquiries: [snflabs.io@gmail.com](mailto:snflabs.io@gmail.com) · [SNF Labs](https://github.com/snflabsio)

---

## Contributing

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Areas where contributions are especially useful:
- Additional IOC feeds and JA3/JA4 fingerprint databases
- Protocol analyzer improvements
- Platform-specific capture backend testing
- Documentation and examples

---

## License

Apache 2.0 — Copyright 2026 Tejas Padigel

See [LICENSE](LICENSE) for full terms.
