File: README.md
````````markdown
# SNF-Core

<div align="center">

**Shadow Network Fingerprinting Engine — Open Source Core**

*Passive. Deterministic. Offline. Written in Rust.*

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)]()
[![Build](https://github.com/padigeltejas/snf-core/actions/workflows/ci.yml/badge.svg)](https://github.com/padigeltejas/snf-core/actions/workflows/ci.yml)

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
*How it works*: The `--determinism-check` flag forces SNF-Core to process the given PCAP twice under slightly different multithreaded orderings. For each pass, it normalizes timestamps, hashes the NDJSON objects independently of flow end time, and compares the final SHA-256 output hashes. If even one bit differs due to hash maps, thread races, or protocol parsing, the determinism check strictly fails. 

---

## Edge & Raspberry Pi Performance

SNF-Core's deterministic, lightweight architecture is engineered to run in highly constrained edge environments, such as OT/ICS network segments or distributed sensor networks on Raspberry Pi hardware.

**Benchmark Details (Raspberry Pi 4, 256MB RAM environment):**
- **Hardware:** Raspberry Pi 4 Model B (simulated 256MB memory cap via `cgroups`)
- **OS:** Raspberry Pi OS Lite (64-bit)
- **Input:** 1GB mixed enterprise and malicious PCAP (Emotet, TLS 1.3, complex protocols)
- **Results:** 
  - Maintained zero drop rate up to ~45,000 packets/sec.
  - Peak resident memory (RSS): 185 MB
  - Average latency per packet layer: <1.2 milliseconds

*Methodology*: To reproduce, compile in release mode and use the `stress` or standard offline PCAP replay mode against public PCAPs from malware-traffic-analysis.net.

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
