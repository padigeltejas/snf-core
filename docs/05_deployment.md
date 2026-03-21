# Deployment Guide

## Requirements
- Rust 1.75+
- Linux: `sudo apt-get install libpcap-dev`
- Windows: Npcap + Npcap SDK

## Build
```bash
cargo build --release
```

## Run
```bash
# PCAP analysis
./target/release/snf-core --forensic --pcap-file capture.pcap

# Live capture (requires root/Administrator)
sudo ./target/release/snf-core --monitor --interface 0

# Silent sensor
sudo ./target/release/snf-core --stealth --interface 0

# Determinism verification
./target/release/snf-core --determinism-check --pcap-file capture.pcap
```

## Configuration
```bash
cp snf.toml.example snf.toml
# Edit output_dir and max_memory_mb as needed
```

## CLI Flags
```
--forensic / --monitor / --stealth / --replay
--pcap-file <path>
--interface <n>
-o / --output <path>
--threads <n>
--no-auto-scale
--max-memory <MB>
--packet-limit <n>
--dry-run
--determinism-check
--help / --version
```

## Live Capture Privileges (Linux)
```bash
# Grant CAP_NET_RAW (recommended over running as root)
sudo setcap cap_net_raw+ep ./target/release/snf-core
```
