# Contributing to SNF-Core

Thank you for your interest in contributing. SNF-Core is a precision tool — every contribution must maintain the correctness, determinism, and performance guarantees the engine is built on.

---

## Non-Negotiable Rules

These apply to every pull request, no exceptions:

| Rule | Why |
|---|---|
| `cargo build` — 0 errors, 0 warnings | Warnings are bugs waiting to happen |
| `cargo test` — all tests pass | Regressions are unacceptable |
| `cargo clippy -- -D warnings` — clean | Idiomatic Rust only |
| No `.unwrap()` or `.expect()` in production paths | Panics crash live capture sessions |
| No `unsafe` without `// SAFETY:` comment | Unsafe must be auditable |
| Determinism preserved | Same PCAP must always produce SHA-256 identical output |
| All buffer reads bounds-checked | Malformed packets must never panic |
| New `PacketContext` fields added to both `new()` AND `PacketContextBuilder` | Compiler won't catch missing builder fields |
| New `EventType` variants added to both `enum` AND `as_str()` | Incomplete match arms cause silent drops |

---

## Setup

```bash
git clone https://github.com/padigeltejas/snf-core
cd snf-core

# Linux
sudo apt-get install libpcap-dev    # Debian/Ubuntu
sudo dnf install libpcap-devel      # RHEL/Fedora

# Windows — install Npcap from https://npcap.com

cargo build
cargo test
```

---

## What We Welcome

**High value contributions:**
- Additional IOC feeds and JA3/JA4 fingerprint databases
- New protocol analyzers (see [docs/06_extending.md](docs/06_extending.md))
- Platform-specific capture backend improvements
- Performance improvements with benchmarks
- Bug fixes with regression tests
- Documentation improvements and usage examples

**Please open an issue first for:**
- New protocol analyzers (to align on field naming conventions)
- Changes to the event schema (breaking changes require discussion)
- Changes to determinism-critical paths

---

## Project Structure

```
src/
  capture/        — Capture engine, PCAP replay, live capture
  config/         — EngineConfig, IntelligenceConfig, all config structs
  core/           — PacketContext, EventBus, EventType, AnalyzerManager
  dataset/        — JA3/JA4 database loaders, port mappings
  evidence/       — EvidenceBundle, ReportBuilder, ReportWriter
  flow/           — Flow table, flow struct, LRU eviction
  intelligence/   — JA3, JA4, IOC matcher, reverse DNS, ASN/GeoIP
  pipeline/       — Packet processing pipeline, TCP reassembly
  threading/      — WorkerPool, per-worker stats, EvidenceBundle merge
datasets/
  ja3/            — JA3 fingerprint CSV
  ja4/            — JA4 fingerprint CSV
  ioc/            — IP and domain blocklists
docs/             — Architecture, determinism, protocol, event model
```

---

## Adding a Protocol Analyzer

See [docs/06_extending.md](docs/06_extending.md) for the full step-by-step guide. The short version:

1. Add fields to `PacketContext` (`src/core/packet_context.rs`) — in both `new()` and `PacketContextBuilder`
2. Write the analyzer in `src/intelligence/` or `src/pipeline/`
3. Wire it into `AnalyzerManager` or `PacketPipeline`
4. Add new `EventType` variants if needed — in both `enum` and `as_str()`
5. Emit events in `emit_protocol_events()` in `packet_pipeline.rs`
6. Write unit tests covering normal, malformed, and edge-case packets
7. Verify `cargo build` — 0 warnings, `cargo test` — all pass

---

## Adding IOC Data

To contribute IOC feeds or fingerprint databases:

**IP blocklist** (`datasets/ioc/ip_blocklist.csv`):
```
ip,label,confidence,threat_actor
1.2.3.4,MalwareC2,85,ThreatActorName
```

**Domain blocklist** (`datasets/ioc/domain_blocklist.csv`):
```
domain,label,confidence,threat_actor
evil.com,MalwareC2,85,ThreatActorName
```

**JA3 database** (`datasets/ja3/ja3_fingerprints.csv`):
```
hash,label,threat_actor
aabbcc...32hexchars,MalwareClient,ThreatActorName
```

Confidence is 1–100. Only include entries from verifiable public threat intel sources (Feodo Tracker, Abuse.ch, MalwareBazaar, etc). Include the source in your PR description.

---

## Code Style

- Rust edition 2021
- `rustfmt` defaults — run `cargo fmt` before committing
- Prefer explicit error handling over `?` chains in hot paths
- Use `saturating_add` / `saturating_sub` for all counters — never let counters overflow
- Use `BTreeMap` for deterministic attribute ordering in events
- `AttrValue::Int` and `AttrValue::Float` do not exist — use `attr_u64()` and `attr_str()`
- Keep functions under ~100 lines — extract helpers freely
- Every public function gets a doc comment

---

## Submitting Changes

1. Fork the repository
2. Create a branch: `git checkout -b feat/your-feature`
3. Make changes following all rules above
4. Run the full check:
   ```bash
   cargo build
   cargo test
   cargo clippy -- -D warnings
   cargo fmt --check
   ```
5. Open a pull request with:
   - What the change does
   - Why it's needed
   - How you tested it
   - Any determinism implications

---

## Questions

Open an issue or reach out at [snflabs.io@gmail.com](mailto:snflabs.io@gmail.com).
