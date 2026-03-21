# Contributing to SNF-Core

## Non-Negotiable Rules

- `cargo build` — 0 errors, 0 warnings
- `cargo test` — all tests pass
- `cargo clippy -- -D warnings` — clean
- No `.unwrap()` or `.expect()` in production paths
- No `unsafe` without `// SAFETY:` comment
- Determinism preserved — same PCAP always produces identical output
- All buffer reads bounds-checked
- New `PacketContext` fields added to both `new()` AND `PacketContextBuilder`

## Setup
```bash
git clone https://github.com/padigeltejas/snf-core
cd snf-core
sudo apt-get install libpcap-dev  # Linux
cargo build
```

## Adding a Protocol Analyzer

See [docs/06_extending.md](docs/06_extending.md) for step-by-step instructions.

## Submitting Changes

1. Fork the repository
2. Create a branch: `git checkout -b feat/your-feature`
3. Make changes following the rules above
4. Open a pull request with a clear description
