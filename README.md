<div align="center">

```
███████╗███╗   ██╗███████╗      ██████╗ ██████╗ ██████╗ ███████╗
██╔════╝████╗  ██║██╔════╝     ██╔════╝██╔═══██╗██╔══██╗██╔════╝
███████╗██╔██╗ ██║█████╗       ██║     ██║   ██║██████╔╝█████╗
╚════██║██║╚██╗██║██╔══╝       ██║     ██║   ██║██╔══██╗██╔══╝
███████║██║ ╚████║██║          ╚██████╗╚██████╔╝██║  ██║███████╗
╚══════╝╚═╝  ╚═══╝╚═╝           ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝
```

**Shadow Network Fingerprinting Engine — Open Source Core**

*Deterministic. Offline-first. Air-gap native. Written in Rust.*

---

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=for-the-badge)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-Edition_2024-orange?style=for-the-badge&logo=rust)](https://www.rust-lang.org/)
[![Build](https://img.shields.io/badge/Build-0_errors_·_0_warnings-brightgreen?style=for-the-badge)]()
[![Platforms](https://img.shields.io/badge/Platforms-Windows_·_Linux_RHEL9-lightgrey?style=for-the-badge)]()
[![Protocols](https://img.shields.io/badge/Protocols-14_Active_Analyzers-informational?style=for-the-badge)]()

</div>

---

## What is SNF-Core?

SNF-Core is the open-source protocol analysis layer of the **Shadow Network Fingerprinting Engine** — a 100% offline, air-gap-native passive network intelligence platform. It captures raw packets, reconstructs flows, and extracts deep protocol intelligence across 14 analyzers, emitting structured NDJSON for forensic analysis, toolchain integration, and downstream threat platforms.

It is the **only deterministic passive network analysis engine** that guarantees:

```
F(dataset, config, version) → SHA-256 identical NDJSON output
```

Same PCAP. Same config. Same binary. Identical output. Every run. Every machine. Every analyst.

---

## Why SNF-Core?

| Problem | Why Existing Tools Fail | How SNF-Core Solves It |
|---|---|---|
| **Non-reproducible analysis** | Wireshark is manual and analyst-dependent. No tool guarantees the same result twice. | Determinism contract — SHA-256 identical output across platforms, analysts, and time. |
| **Air-gapped environments** | Darktrace, Vectra, CrowdStrike — all cloud-dependent. Illegal in defense/classified/OT. | Offline-first by architecture. Zero internet dependency. Zero telemetry. |
| **Encrypted traffic blindness** | TLS 1.3 hides payload. DPI is useless. Decryption is illegal in many jurisdictions. | Intelligence from handshake metadata — SNI, JA3/JA4, cipher behavior — no decryption needed. |
| **Memory-unsafe forensic tools** | Zeek, Suricata, Snort, tcpdump are written in C/C++. Memory corruption is a known attack vector. | Rust: memory safety guaranteed at compile time. Zero crashes on 14.9M packet MAWI run. |

---

## Determinism Contract

```
┌──────────────────────────────────────────────────────────┐
│  input:   capture.pcap  +  snf.toml  +  snf-core v1.0.0 │
│  output:  snf_output.ndjson                              │
│                                                          │
│  SHA-256(run_1) == SHA-256(run_2)  ──  ALWAYS            │
│  SHA-256(analyst_A) == SHA-256(analyst_B)  ──  ALWAYS    │
│  SHA-256(windows) == SHA-256(linux)  ──  ALWAYS          │
└──────────────────────────────────────────────────────────┘
```

Every output embeds `pcap_sha256` + `config_sha256` + `snf_version` in the session header — a complete chain of custody record.

---

## Protocol Support

| Protocol | Extracted Fields |
|---|---|
| **DNS** | Query/response, CNAME chains, MX/NS/TXT/SRV, resolved IPs, TTL, NXDOMAIN, DNSSEC |
| **TLS 1.0–1.3** | SNI, cipher suites, ALPN, ECH detection, certificate CN/SANs, JA3/JA3S/JA4, 0-RTT, session resumption |
| **HTTP/1.1** | Method, URI, Host, status code, User-Agent, Content-Type, redirect detection |
| **HTTP/2** | HPACK headers, `:method` / `:path` / `:authority` pseudo-headers |
| **QUIC v1/v2** | Version, DCID/SCID, SNI from CRYPTO frames, packet number |
| **DHCPv4/v6** | Message type, client MAC, hostname, requested IP, Option 82 relay, DHCPv6 DUID |
| **ICMPv4/v6** | Type, code, payload size, traceroute detection |
| **SMB 1/2/3** | Command, NTLM auth type, session ID, dialect |
| **mDNS** | Service type, device name, PTR/SRV/TXT records |
| **DoH / DoT** | Confidence-scored detection — ALPN, path, content-type signals |
| **Kerberos / LDAP / RDP** | AS-REQ/TGS-REQ, NTLM negotiate/auth, LDAP bind, RDP connection |
| **SSDP / UPnP / FTP** | M-SEARCH/NOTIFY, FTP command parsing |

All 14 analyzers run in **fixed deterministic order** per packet — a core requirement of the SHA-256 determinism guarantee.

---

## Quick Start

```bash
git clone https://github.com/padigeltejas/snf-core
cd snf-core
cargo build --release
```

```bash
# Analyse a PCAP file
./target/release/snf_core --forensic --pcap-file capture.pcap

# Live capture (requires root / CAP_NET_RAW)
sudo ./target/release/snf_core --monitor --interface 1

# Verify determinism — runs two passes and compares SHA-256
./target/release/snf_core --determinism-check --pcap-file capture.pcap

# Dry-run config validation only
./target/release/snf_core --forensic --pcap-file capture.pcap --dry-run
```

Output is written to `output/snf_output.ndjson` by default (configured via `snf.toml`).

---

## Operation Modes

| Mode | Flag | Threading | Use Case |
|---|---|---|---|
| **Forensic** | `--forensic` | Auto-scale | PCAP post-mortem, DFIR |
| **Monitor** | `--monitor` | Auto-scale | Live 24/7 SOC sensor |
| **Replay** | `--replay` | Single (enforced) | Court-admissible reproducible replay |
| **Stealth** | `--stealth` | Single | Covert sensor — zero console output |

---

## Output Format

SNF-Core emits **NDJSON** — one JSON object per line, streamable, pipeable, and directly compatible with `jq`.

Every session begins with a session header:

```json
{
  "record_type": "snf_session_header",
  "snf_version": "1.0.0",
  "pcap_sha256": "a3f1c2...",
  "config_sha256": "9b4d7e...",
  "operating_mode": "forensic",
  "input_source": "capture.pcap",
  "session_start_us": 1706789400000000
}
```

Followed by typed events with 7 mandatory fields:

```json
{
  "event_id": 1,
  "packet_id": 42,
  "timestamp_us": 1706789401123456,
  "event_type": "tls.client_hello",
  "protocol": "tls",
  "flow_id": "10.0.0.1:54231-185.220.101.50:443-tcp",
  "attributes": {
    "sni": "example.com",
    "ja3_hash": "d4e12bfc...",
    "tls_version": "TLSv1.3",
    "cipher_count": 17
  }
}
```

---

## Architecture

```
  PCAP / Live Interface
          │
          ▼
  ┌───────────────────┐
  │   Capture Engine  │  ← AF_PACKET · AF_XDP · pcap · DPDK (scaffold)
  └────────┬──────────┘
           │  RawPacket
           ▼
  ┌───────────────────┐
  │  Worker Pool      │  ← Per-worker FlowTable · AnalyzerManager · EventBus
  └────────┬──────────┘
           │  PacketContext
           ▼
  ┌───────────────────────────────────────────────────────┐
  │  14 Protocol Analyzers  (fixed deterministic order)   │
  │  DNS · TLS · HTTP/1.1 · HTTP/2 · QUIC · DHCP · ICMP  │
  │  SMB · mDNS · DoH · DoT · Enterprise · Discovery · ICS│
  └────────┬──────────────────────────────────────────────┘
           │  SnfEvent (7 mandatory fields)
           ▼
  ┌───────────────────┐
  │  NDJSON Output    │  ← BufWriter · BTreeMap sort · session header first
  └───────────────────┘
           │
           ▼
    snf_output.ndjson
```

Worker shards (`.worker_N`) are merged at session end into a single deterministic NDJSON file. Worker 0's session header is canonical — headers from all other workers are discarded during merge.

---

## Configuration

SNF-Core is configured via `snf.toml` (optional) + CLI flags. CLI always wins.

```toml
# snf.toml
output_dir = "output"       # NDJSON output directory — created automatically if absent
# max_memory_mb = 0         # 0 = unlimited; triggers aggressive flow eviction when set
```

See [`snf.toml.example`](snf.toml.example) for the full reference.

---

## Performance

Validated on real-world PCAPs:

| Metric | Result | Test Conditions |
|---|---|---|
| Single-core throughput | **155,600 pps / 1.25 Gbps** | MAWI backbone, 14.9M packets, 1.07 GB, RHEL9 release build |
| 4-thread speedup | **2.3× faster** | Same MAWI PCAP, 4 vCPUs, WorkerPool with flow-affinity routing |
| Zero crashes | **14,937,089 packets** | Full MAWI backbone run — zero panics, zero memory errors |
| Determinism | **SHA-256 identical** | Two-pass AF_XDP replay: `6a76686f` PASS |

---

## Documentation

| Doc | Contents |
|---|---|
| [01 — Architecture](docs/01_architecture.md) | Engine internals, threading model, pipeline stages |
| [02 — Determinism](docs/02_determinism.md) | The `F(dataset,config,version)` contract, verification steps |
| [03 — Protocol Support](docs/03_protocol_support.md) | All 14 analyzers, field reference, detection logic |
| [04 — Event Model](docs/04_event_model.md) | `SnfEvent`, `AttrValue`, `EventType` complete reference |
| [05 — Deployment](docs/05_deployment.md) | Sensor setup, air-gap deployment, stealth mode |
| [06 — Extending](docs/06_extending.md) | Adding analyzers, custom event types, build integration |

---

## Open Core Model

SNF-Core is the **open-source protocol analysis layer** of the Shadow Network Fingerprinting Engine — complete and production-ready as a standalone tool.

| Component | SNF-Core (Open) | SNF Full Engine (Commercial) |
|---|---|---|
| Packet capture + flow tracking | ✓ | ✓ |
| 14 protocol analyzers | ✓ | ✓ |
| Deterministic NDJSON output | ✓ | ✓ |
| JA3 / JA3S / JA4 fingerprinting | ✓ | ✓ |
| Beacon / DGA / DNS tunnel detection | — | ✓ |
| Offline IOC matching | — | ✓ |
| ICS/SCADA protocol suite | — | ✓ |
| PCAP redaction engine | — | ✓ |
| Passive OS/hardware fingerprinting | — | ✓ |
| Multi-PCAP session correlation | — | ✓ |
| Forensic evidence bundles | — | ✓ |
| SIEM export (Splunk/Elastic/CEF/LEEF) | — | ✓ |

---

## Security

SNF-Core treats every PCAP as an adversarial input. The parser layer is the attack surface.

- **Memory safety** — Rust guarantees at compile time. Zero `unsafe` in the analysis path.
- **Bounds-checked** — all buffer reads validated before access. No unbounded allocation from packet data.
- **No silent drops** — every parse failure emits a `engine.parse_error` event. Determinism requires all malformed input to appear in output.
- **No panics** — zero `.unwrap()` or `.expect()` in any production code path. All errors handled explicitly.

See [SECURITY.md](SECURITY.md) for the full security policy.

---

## Contributing

Contributions are welcome for the open-source core. See [CONTRIBUTING.md](CONTRIBUTING.md).

**Hard requirements for all PRs:**
- `cargo build` → 0 errors, 0 warnings on both Windows and Linux
- `cargo test` → all tests passing
- No `.unwrap()` or `.expect()` anywhere in production paths
- All new `PacketContext` fields added to both `new()` and `Default()`

---

## License

Apache 2.0 — Copyright 2026 Tejas Padigel

---

<div align="center">

**SNF Labs** · [@snf_labs](https://x.com/snf_labs) · [snflabsio](https://github.com/snflabsio)

*Built in Rust. Runs anywhere. Trusts nothing.*

</div>
