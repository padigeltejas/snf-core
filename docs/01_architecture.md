# Architecture Overview

SNF-Core is a deterministic, offline-first network packet analysis engine.

## Two-Binary Design

- `snf-core` — capture engine. Reads packets from PCAP files or live interfaces. Emits structured NDJSON.
- All post-session analysis is done by reading the NDJSON output.

## Packet Processing Pipeline

Every packet flows through this exact sequence:

1. **Capture** — pcap file or live interface (AF_PACKET / AF_XDP)
2. **PacketContextBuilder** — extract src/dst IP, ports, protocol from raw bytes via etherparse
3. **PacketPipeline** — Ethernet/IP/TCP/UDP parsing, TCP reassembly
4. **AnalyzerManager** — dispatches to all 14 protocol analyzers in fixed deterministic order
5. **Protocol Analyzers** — DNS, TLS, HTTP, QUIC, DHCP, ICMP, SMB, mDNS, DoH, DoT, Enterprise, Discovery
6. **EventBus** — serializes SnfEvent structs to NDJSON lines, writes to output file
7. **Worker Shard Merge** — multi-threaded shards merged into single output file at session end

## Operation Modes

| Mode | Use Case | Threads | Output |
|------|----------|---------|--------|
| `--forensic` | Post-incident analysis | Auto-scaled | Full NDJSON |
| `--monitor` | 24/7 live monitoring | Auto-scaled | Full NDJSON |
| `--stealth` | Covert sensor | 1 | Silent NDJSON |
| `--replay` | Deterministic replay | 1 (enforced) | Deterministic NDJSON |

## Multi-Threading

In multi-threaded mode (Forensic/Monitor with worker_threads > 1):

- Each worker has its own independent FlowTable, AnalyzerManager, and EventBus
- Workers write to `.worker_N` shard files during capture
- After shutdown, shards are merged into one final NDJSON file
- Worker_0 shard goes first — it holds the canonical session header on line 1

## Hardware Auto-Scaling

| CPU Cores | Workers |
|-----------|---------|
| 1–2 | 1 |
| 3–8 | cores - 1 |
| 9–16 | cores - 2 |
| 17+ | cores - 4 |

Use `--no-auto-scale` for conservative single-worker mode.

## Data Structures

- **FlowTable** — HashMap with FNV-1a hashing, LRU eviction, pre-allocated at 125% of max_flows
- **EventBus** — BufWriter-backed NDJSON emitter, one per worker
- **PacketContext** — stack-allocated per-packet workspace, ~150 fields
- **SnfEvent** — universal output record with 7 mandatory fields

## Determinism

See [02_determinism.md](02_determinism.md) for the full determinism contract.
