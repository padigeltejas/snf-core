# Deployment Guide

## Minimum System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 1 core (x86_64) | 4+ cores |
| RAM | 256 MB | 2+ GB |
| Disk | 50 MB | 1+ GB (for NDJSON output) |
| OS (Linux) | RHEL 8 / Ubuntu 20.04 / Debian 11 | RHEL 9 / Ubuntu 22.04+ |
| OS (Windows) | Windows 10 x64 | Windows 11 x64 |
| Rust | 1.75+ | latest stable |

## Dependencies

### Linux
```bash
# Debian / Ubuntu
sudo apt-get install libpcap-dev

# RHEL / CentOS / Fedora
sudo dnf install libpcap-devel

# Arch
sudo pacman -S libpcap
```

### Windows
1. Download and install **Npcap** from https://npcap.com/#download
   - During install, check **"Install Npcap in WinPcap API-compatible mode"**
2. Download the **Npcap SDK** from the same page
3. Set environment variable: `NPCAP_SDK=C:\npcap-sdk` (or wherever you extracted the SDK)

### Rust
```bash
# Install rustup (Linux/macOS)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Windows: download rustup-init.exe from https://rustup.rs
```

## Build
```bash
git clone https://github.com/padigeltejas/snf-core.git
cd snf-core
cargo build --release
```

## Run

### PCAP Analysis
```bash
./target/release/snf-core --forensic --pcap-file capture.pcap -o output/results.ndjson
```

### Live Capture (Linux)
```bash
# Requires root or CAP_NET_RAW capability
sudo ./target/release/snf-core --monitor --interface 1 -o output/live.ndjson

# Find your interface index
./target/release/snf-core --help | grep interface

# Grant capability instead of running as root (recommended)
sudo setcap cap_net_raw+ep ./target/release/snf-core
./target/release/snf-core --monitor --interface 1 -o output/live.ndjson
```

### Live Capture (Windows)
```powershell
# Run as Administrator
.\target\release\snf-core.exe --monitor --interface 1 -o output\live.ndjson
```

### Verify Determinism
```bash
./target/release/snf-core --determinism-check --pcap-file capture.pcap
# PASS = exit 0, FAIL = exit 1, ERROR = exit 2
```

## Configuration

Copy the example config and adjust:
```bash
cp snf.toml.example snf.toml
```

Key settings in `snf.toml`:
```toml
# Output directory (auto-created if missing)
output_dir = "output"

# Memory cap in MB (0 = unlimited)
# max_memory_mb = 512
```

## Optional: MaxMind GeoIP / ASN Databases

ASN and GeoIP enrichment is disabled by default. To enable:

1. Register free at https://www.maxmind.com/en/geolite2/signup
2. Download `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb`
3. Place them in the `datasets/` directory
4. Place them in the `datasets/` directory — SNF-Core will detect them automatically on next run

## Performance Tuning
```bash
# Auto-scales to available CPUs by default
./target/release/snf-core --forensic --pcap-file capture.pcap

# Pin to specific thread count
./target/release/snf-core --forensic --pcap-file capture.pcap --threads 4

# Memory-constrained environments
./target/release/snf-core --forensic --pcap-file capture.pcap --no-auto-scale --max-memory 256
```

## Silent Sensor Deployment
```bash
# Zero console output, minimal footprint
sudo ./target/release/snf-core --stealth --interface 1 -o /var/log/snf/events.ndjson
```
