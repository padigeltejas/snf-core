# Architecture Overview

SNF-Core is a deterministic, offline-first network packet analysis engine written in Rust. This document describes how it is structured, how packets flow through the system, and the design decisions behind each component.

---

## Design Philosophy

SNF-Core is built around three non-negotiable constraints:

1. **Determinism** — identical input always produces SHA-256 identical output, regardless of OS, hardware, or thread count
2. **Offline-first** — zero network calls during analysis; all intelligence is loaded from local files at startup
3. **Air-gap safe** — no telemetry, no cloud dependency, no external lookups of any kind

These constraints drive every architectural decision. When performance and determinism conflict, determinism wins.

---

## High-Level Structure

```
┌─────────────────────────────────────────────────────────────┐
│                        snf-core binary                       │
├─────────────────────────────────────────────────────────────┤
│  Capture Layer         PCAP file │ Live interface            │
│  (capture/mod.rs)      AF_PACKET │ AF_XDP                    │
├─────────────────────────────────────────────────────────────┤
│  Worker Pool           N independent workers                 │
│  (threading/)          Each with its own FlowTable,          │
│                        AnalyzerManager, EventBus             │
├─────────────────────────────────────────────────────────────┤
│  Packet Pipeline       Parse → Analyze → Emit                │
│  (pipeline/)           TCP reassembly, protocol dispatch     │
├─────────────────────────────────────────────────────────────┤
│  Protocol Analyzers    18 analyzers, fixed deterministic     │
│  (intelligence/)       order, config-gated                   │
├─────────────────────────────────────────────────────────────┤
│  Threat Intelligence   JA3/JA4 fingerprinting                │
│  (intelligence/)       Offline IOC matching                  │
│                        Threat actor attribution              │
├─────────────────────────────────────────────────────────────┤
│  Evidence Collection   Per-worker EvidenceBundle             │
│  (evidence/)           Merged at session end                 │
│                        ReportBuilder → session report        │
├─────────────────────────────────────────────────────────────┤
│  Output                NDJSON event stream                   │
│  (output/)             Session report (text + JSON)          │
└─────────────────────────────────────────────────────────────┘
```

---

## Packet Processing Pipeline

Every packet — regardless of protocol or operation mode — flows through this exact sequence:

```
Raw bytes (pcap / live)
        │
        ▼
PacketContextBuilder        Extract src/dst IP, ports, protocol
        │                   via etherparse — no allocation
        ▼
Userspace Packet Filters    min/max size, loopback, multicast,
        │                   protocol filter, IP filter, BPF
        ▼
FlowTable                   Stateful TCP/UDP flow lookup
        │                   LRU eviction, FNV-1a hashing
        ▼
TCP Reassembler              Segment ordering, stream reassembly
        │                   (TCP only, bounded buffer)
        ▼
AnalyzerManager             Dispatches to all 18 protocol analyzers
        │                   in fixed order — deterministic always
        ▼
Protocol Analyzers          DNS, TLS, HTTP, QUIC, DHCP, ICMP,
        │                   SMB, mDNS, DoH/DoT, ICS/SCADA,
        │                   Enterprise, Discovery, JA3/JA4
        ▼
Threat Intel                IOC IP/domain matching (O(1))
        │                   JA3/JA4 threat actor attribution
        ▼
BehaviorEngine              Beacon detection, DGA scoring,
        │                   DNS tunneling, port scan, floods
        ▼
EventBus                    Serialize SnfEvent → NDJSON line
        │                   BufWriter per worker, no locking
        ▼
EvidenceBundle              Accumulate session-level findings
                            Per-worker, merged at shutdown
```

---

## Operation Modes

| Mode | Flag | Threads | Use Case |
|---|---|---|---|
| Forensic | `--forensic` | Auto-scaled | Post-incident PCAP analysis |
| Monitor | `--monitor` | Auto-scaled | 24/7 live network monitoring |
| Stealth | `--stealth` | 1 | Covert sensor, zero console output |
| Replay | `--replay` | 1 (enforced) | Deterministic replay, testing |

**Forensic** and **Monitor** modes auto-scale workers to available hardware. **Replay** always runs single-threaded to guarantee byte-identical output across runs.

Use `--no-auto-scale` to force single-threaded mode in Forensic/Monitor (useful for constrained environments or when comparing output across machines).

---

## Multi-Threading Architecture

```
                    ┌─────────────────┐
                    │  Capture Thread  │
                    │  (main thread)   │
                    └────────┬────────┘
                             │ RawPackets via PacketQueue
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
        ┌──────────┐  ┌──────────┐  ┌──────────┐
        │ Worker 0 │  │ Worker 1 │  │ Worker N │
        │          │  │          │  │          │
        │FlowTable │  │FlowTable │  │FlowTable │
        │Analyzers │  │Analyzers │  │Analyzers │
        │EventBus  │  │EventBus  │  │EventBus  │
        │Evidence  │  │Evidence  │  │Evidence  │
        └────┬─────┘  └────┬─────┘  └────┬─────┘
             │             │             │
             ▼             ▼             ▼
        .worker_0      .worker_1      .worker_N
             │             │             │
             └─────────────┴─────────────┘
                           │
                    Shard merge
                           │
                    final.ndjson
                           │
                  EvidenceBundle merge
                           │
                    Session report
```

**Key design decisions:**
- Each worker is completely independent — no shared mutable state between workers
- Each worker writes to its own `.worker_N` output file during capture (prevents concurrent write contention)
- At shutdown, worker files are merged into one final NDJSON file — worker 0 goes first (it holds the canonical session header)
- Each worker maintains its own `EvidenceBundle` — merged at session end via `merge_from()` to produce the full session report
- Workers use lock-free `PacketQueue` (SPSC channel per worker) — no mutex contention in the hot path

---

## Hardware Auto-Scaling

SNF-Core probes available hardware at startup and recommends an optimal configuration:

| CPU Cores | Workers | Batch Size |
|---|---|---|
| 1–2 | 1 | 32 |
| 3–8 | cores − 1 | 64 |
| 9–16 | cores − 2 | 64 |
| 17+ | cores − 4 | 128 |

Override with:
```bash
./snf-core --forensic --pcap-file capture.pcap --threads 4
./snf-core --forensic --pcap-file capture.pcap --no-auto-scale  # force single-threaded
```

---

## Core Data Structures

### PacketContext
Per-packet workspace, stack-allocated, created fresh for every packet. Populated incrementally as the packet moves through the pipeline. Contains ~160 fields covering all supported protocols. Never persisted — discarded after event emission.

### FlowTable
`HashMap<FlowKey, Flow>` with FNV-1a hashing. Pre-allocated at 125% of `max_flows`. LRU eviction when full. Each worker has its own independent FlowTable — no cross-worker flow state.

### EventBus
`BufWriter`-backed NDJSON emitter, one per worker. Events are serialized to a line buffer and flushed at configurable intervals. Flushed and dropped at worker shutdown — Drop impl guarantees all buffered events reach disk.

### EvidenceBundle
Session-level evidence accumulator. Tracks packet/flow/protocol counters, discovered devices, IOC hits, threat matches, behavioral alerts, top talkers, DGA candidates. One per worker, merged into a single bundle at session end via `merge_from()`.

### SnfEvent
Universal output record. 7 mandatory fields + a typed attribute map (`BTreeMap` for deterministic ordering). Serialized to NDJSON by `EventSerializer`.

---

## Intelligence Loading

At startup, before the first packet is processed, SNF-Core loads:

```
datasets/ja3/ja3_fingerprints.csv    →  Ja3Database  (labels + threat actors)
datasets/ja4/ja4_fingerprints.csv    →  Ja4Database  (labels + threat actors)
datasets/ioc/ip_blocklist.csv        →  IocMatcher   (IP HashMap)
datasets/ioc/domain_blocklist.csv    →  IocMatcher   (domain HashMap)
datasets/ports/                      →  port→service map
```

All intelligence is immutable after load. Shared across workers via `Arc` — zero-copy, zero locking during capture. Missing files emit a warning and continue — SNF-Core never aborts startup due to missing optional datasets.

---

## Output Structure

```
output/
  snf_events_<timestamp>.ndjson      — Full event stream (NDJSON)
  snf_report_<timestamp>.json        — Session report (JSON)
  snf_report_<timestamp>.txt         — Session report (human-readable)
```

The NDJSON file begins with a `SessionHeader` record on line 1, followed by one `SnfEvent` per line. This structure enables streaming analysis with standard UNIX tools:

```bash
grep '"event_type":"TlsClientHello"' output/snf_events_*.ndjson | jq .
grep '"event_type":"intel.ioc_match"' output/snf_events_*.ndjson | jq .attributes
```

---

## Source Layout

```
src/
  capture/          Capture engine, PCAP replay, live capture backends
  config/           EngineConfig and all sub-configs (protocol, filter, intelligence...)
  core/             PacketContext, EventBus, EventType, SnfEvent, AnalyzerManager
  dataset/          JA3/JA4 database loaders, port-to-service mapping
  evidence/         EvidenceBundle, ReportBuilder, ReportWriter
  flow/             FlowTable, Flow struct, FlowKey, LRU eviction
  intelligence/     Protocol analyzers: JA3, JA4, IOC matcher, TLS, reverse DNS, ASN/GeoIP
  pipeline/         PacketPipeline, TCP reassembly, userspace filters
  behavior/         Beacon detection, DGA scoring, ICMP flood, SMB lateral movement
  anomaly/          Anomaly detection engine
  output/           EventSerializer, NDJSON writer, sanitization
  threading/        WorkerPool, PacketQueue, ThreadStats, EvidenceBundle merge
  storage/          FlowStore, SessionStore (historical analysis)
  graph/            Graph engine (commercial edition)
  timeline/         Timeline engine (commercial edition)
  stealth/          Stealth detection engine (commercial edition)
```

---

## Further Reading

- [Determinism Contract](02_determinism.md)
- [Protocol Support Reference](03_protocol_support.md)
- [Event Model Specification](04_event_model.md)
- [Deployment Guide](05_deployment.md)
- [Extending SNF-Core](06_extending.md)
