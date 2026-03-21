# Determinism Contract

F(dataset, config, version) → identical NDJSON output

Same PCAP + same config + same binary = SHA-256 identical output. Every time. On any OS.

## Rules
- Packets processed in file order, never timestamp order
- No system clock in analysis path — all timestamps from PCAP headers
- No global mutable state — all analyzer state is session-scoped
- Replay mode always single-threaded
- HashMap attributes sorted via BTreeMap at serialization time only

## Verify
```bash
./target/release/snf-core --determinism-check --pcap-file evidence.pcap
# PASS SHA-256: abc123... (exit 0)
```
