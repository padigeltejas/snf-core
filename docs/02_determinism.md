# Determinism Contract

SNF-Core makes a strong guarantee:

```
F(dataset, config, version) → identical NDJSON output
```

Given the same PCAP file, the same configuration, and the same binary version, SNF-Core produces **SHA-256 identical output on every run** — on any OS, any hardware, any number of CPU cores.

This property is not incidental. It is a first-class design constraint that shapes every component in the engine.

---

## Why Determinism Matters

**Forensic investigations** require reproducibility. An analyst must be able to re-run analysis on evidence months later and get byte-identical results. Non-deterministic output means findings cannot be independently verified.

**Regression testing** becomes trivial. A golden PCAP + golden output file catches any behavioral change — intended or accidental.

**Air-gapped deployments** benefit from predictable, auditable behavior. There are no hidden sources of variance like network lookups or timestamp-seeded RNGs.

---

## The Rules

Every rule below is enforced by design, not convention.

### 1. Packet order follows file order, never timestamp order

Packets are processed in the order they appear in the PCAP file. PCAP timestamps are used only as event metadata — never to sort, schedule, or sequence processing.

**Why:** Timestamp-based reordering introduces variance when packets have identical or near-identical timestamps. File order is canonical and unambiguous.

### 2. No wall-clock time in any analysis path

`std::time::SystemTime` and `std::time::Instant` are forbidden in all packet processing paths. All timestamps come from PCAP packet headers:

```rust
// Correct — deterministic
let timestamp_us = (header.ts.tv_sec as u64) * 1_000_000
                 + (header.ts.tv_usec as u64);

// Forbidden — breaks determinism
let timestamp_us = SystemTime::now()...;
```

Wall-clock time is used only for logging and performance measurement — never for output timestamps or event ordering.

### 3. No global mutable state

All analyzer state is session-scoped and worker-local. There are no global counters, global caches, or global accumulators that persist between sessions or are shared between workers.

Each worker initializes its own `FlowTable`, `AnalyzerManager`, `DnsCache`, `BehaviorEngine`, and `EvidenceBundle` at startup. State from one session cannot bleed into another.

### 4. Replay mode is always single-threaded

Multi-threaded mode distributes packets across workers by hash — the same packet always goes to the same worker, but the interleaving of events from different flows can vary slightly between runs due to OS thread scheduling.

Replay mode (`--replay`) enforces exactly 1 worker. This makes output byte-identical across all runs, on all hardware.

```bash
# Forensic mode: fast, consistent threat detection, slight event-order variance
./snf-core --forensic --pcap-file evidence.pcap

# Replay mode: byte-identical output, guaranteed
./snf-core --replay --pcap-file evidence.pcap
```

### 5. HashMap attributes are sorted via BTreeMap at serialization

`SnfEvent` attributes are stored in a `BTreeMap` — a sorted tree map. This guarantees that attribute keys always appear in the same alphabetical order in the NDJSON output, regardless of insertion order.

```json
// Always sorted alphabetically — never random
{"alpn":"h2","cert_cn":"example.com","ja3":"abc...","sni":"example.com","tls_version":"TLS1.2"}
```

### 6. Protocol analyzers run in fixed order

`AnalyzerManager` dispatches to all 18 analyzers in a fixed, hardcoded sequence. Analyzer N always runs before Analyzer N+1, on every packet. This ensures that analyzer interactions (e.g., DNS resolving a domain before TLS sees the SNI) are deterministic.

### 7. No randomness

No UUID generation, no random sampling, no probabilistic data structures (no Bloom filters, no HyperLogLog). Every count is exact. Every decision is deterministic.

### 8. All intelligence loaded at startup, never at runtime

JA3/JA4 databases and IOC blocklists are loaded once at startup and held immutably in memory for the duration of the session. No lazy loading, no background refresh, no network-fetched updates during capture.

---

## Verifying Determinism

SNF-Core ships with a built-in determinism checker:

```bash
./target/release/snf-core --determinism-check --pcap-file evidence.pcap
```

This runs the PCAP twice internally, computes SHA-256 of both output streams, and compares them. Exit codes:

| Exit Code | Meaning |
|---|---|
| 0 | PASS — outputs are SHA-256 identical |
| 1 | FAIL — outputs differ (bug, report it) |
| 2 | ERROR — could not complete check |

Example output:
```
[SNF] Determinism check: run 1...
[SNF] Determinism check: run 2...
[SNF] SHA-256 run 1: a1b2c3d4e5f6...
[SNF] SHA-256 run 2: a1b2c3d4e5f6...
[SNF] PASS — output is deterministic
```

---

## Cross-Platform Determinism

SNF-Core produces identical output on Linux and Windows from the same PCAP. This is verified in CI by:

1. Building release binaries on both platforms
2. Running the same PCAP on both
3. Comparing SHA-256 of the output NDJSON files

Floating point arithmetic is avoided in all output paths. All numeric output is integer-based. String formatting uses Rust's deterministic `Display` implementations.

---

## What Is NOT Guaranteed Deterministic

| Aspect | Why |
|---|---|
| Performance metrics (PPS, worker balance) | Wall-clock dependent |
| Log messages and stderr output | Not part of the output contract |
| Worker N event interleaving in multi-thread mode | Use `--replay` for byte-identical output |
| Session report timestamps | Generated at report-build time |

---

## Determinism in Practice

**Forensic workflow:**
```bash
# Analyst A runs analysis
./snf-core --replay --pcap-file evidence.pcap -o evidence_run1.ndjson

# Analyst B independently verifies — months later, different machine
./snf-core --replay --pcap-file evidence.pcap -o evidence_run2.ndjson

# SHA-256 identical
sha256sum evidence_run1.ndjson evidence_run2.ndjson
```

**Regression testing:**
```bash
# Capture golden output
./snf-core --replay --pcap-file test_malware.pcap -o golden.ndjson

# After code changes, verify nothing broke
./snf-core --replay --pcap-file test_malware.pcap -o new.ndjson
diff golden.ndjson new.ndjson  # expect: no output
```

---

## Contributing: Preserving Determinism

Any contribution that touches the analysis path must preserve the determinism guarantee. Specifically:

- **Do not** use `SystemTime::now()`, `Instant::now()`, or any wall-clock source in output paths
- **Do not** use `HashMap` for ordered output — use `BTreeMap`
- **Do not** introduce global mutable state
- **Do not** add randomness of any kind (UUIDs, sampling, probabilistic structures)
- **Do** run `./snf-core --determinism-check` on your test PCAPs before submitting a PR
- **Do** add a determinism test if your change touches event emission or serialization

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the full contribution checklist.
