# Deployment Guide

This guide covers everything needed to deploy SNF-Core in production — from system requirements through live capture, performance tuning, and silent sensor deployment.

---

## System Requirements

### Minimum

| Component | Minimum |
|---|---|
| Architecture | x86_64 |
| CPU | 1 core |
| RAM | 256 MB |
| Disk | 50 MB (binary) + space for NDJSON output |
| OS (Linux) | RHEL 8 / Ubuntu 20.04 / Debian 11 |
| OS (Windows) | Windows 10 x64 |
| Rust | 1.75+ |

### Recommended (Production)

| Component | Recommended |
|---|---|
| CPU | 4+ cores |
| RAM | 4+ GB (for large PCAPs or sustained live capture) |
| Disk | SSD, 50+ GB for output retention |
| OS (Linux) | RHEL 9 / Ubuntu 22.04+ |
| NIC | Intel i210/i350/X550 or Mellanox for high-throughput live capture |

### Throughput Reference

| Workers | Typical Throughput |
|---|---|
| 1 | ~500 Mbps |
| 4 | ~2 Gbps |
| 8 | ~4 Gbps |
| 10 | ~5 Gbps |

Throughput depends heavily on protocol mix, CPU speed, and storage write speed.

---

## Dependencies

### Linux

```bash
# Debian / Ubuntu
sudo apt-get update && sudo apt-get install -y libpcap-dev

# RHEL / CentOS / Rocky / Alma
sudo dnf install -y libpcap-devel

# Arch Linux
sudo pacman -S libpcap

# Verify
dpkg -l libpcap-dev  # Debian/Ubuntu
rpm -q libpcap-devel  # RHEL
```

### Windows

1. Download **Npcap** from [https://npcap.com/#download](https://npcap.com/#download)
2. During installation, check **"Install Npcap in WinPcap API-compatible mode"**
3. Download the **Npcap SDK** from the same page
4. Extract the SDK and set the environment variable:
   ```powershell
   [Environment]::SetEnvironmentVariable("NPCAP_SDK", "C:\npcap-sdk", "Machine")
   ```
5. Restart your terminal or IDE

### Rust Toolchain

```bash
# Linux / macOS
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# Windows — download and run rustup-init.exe from https://rustup.rs

# Verify
rustc --version  # must be 1.75+
cargo --version
```

---

## Building

```bash
git clone https://github.com/padigeltejas/snf-core.git
cd snf-core

# Development build (faster compilation, slower execution)
cargo build

# Production build (optimized — use this for deployment)
cargo build --release

# Verify
./target/release/snf-core --help
```

The release binary is self-contained. No runtime dependencies beyond libpcap/Npcap.

---

## Configuration

Copy the example config and customize:

```bash
cp snf.toml.example snf.toml
```

### Essential Settings

```toml
[output]
# Directory for NDJSON output and session reports (auto-created)
output_dir = "output"

# Verbosity: 0 = silent, 1 = summary, 2 = verbose
verbosity = 1

[protocol]
# Enable/disable individual analyzers
enable_dns   = true
enable_tls   = true
enable_http  = true
enable_quic  = true
enable_dhcp  = true
enable_icmp  = true
enable_smb   = true
enable_mdns  = true
enable_ics   = true     # Modbus, DNP3, S7comm, EtherNet/IP, PROFINET
enable_lan   = true     # LLDP, CDP

# TLS fingerprinting
ja3_enabled  = true
ja4_enabled  = true

[intelligence]
# Offline IOC matching
ioc_matching_enabled      = true
ioc_ip_blocklist_path     = "datasets/ioc/ip_blocklist.csv"
ioc_domain_blocklist_path = "datasets/ioc/domain_blocklist.csv"

# GeoIP / ASN enrichment (disabled by default — requires MaxMind databases)
enable_asn_mapping   = false
enable_geoip_mapping = false

[performance]
# Worker threads (0 = auto-scale to hardware)
worker_threads = 0

# Packet batch size per worker wakeup
packet_batch_size = 64

# Maximum flows in FlowTable per worker
max_flows = 100000
```

Full configuration reference: all options are documented in `snf.toml.example`.

---

## PCAP Analysis

```bash
# Basic forensic analysis
./target/release/snf-core --forensic --pcap-file capture.pcap

# Specify output location
./target/release/snf-core --forensic --pcap-file capture.pcap -o /data/output/results.ndjson

# Use custom config
./target/release/snf-core --forensic --pcap-file capture.pcap --config /etc/snf/snf.toml

# Single-threaded deterministic replay (guaranteed byte-identical output)
./target/release/snf-core --replay --pcap-file evidence.pcap -o evidence_analysis.ndjson

# Limit packets processed (useful for testing)
./target/release/snf-core --forensic --pcap-file capture.pcap --packet-limit 10000
```

---

## Live Capture

### Linux

```bash
# Requires root or CAP_NET_RAW capability

# Find available interfaces
./target/release/snf-core --list-interfaces

# Capture on interface 1 (e.g., eth0)
sudo ./target/release/snf-core --monitor --interface 1 -o /var/log/snf/live.ndjson

# Recommended: grant capability instead of running as root
sudo setcap cap_net_raw+ep ./target/release/snf-core
./target/release/snf-core --monitor --interface 1 -o /var/log/snf/live.ndjson

# Apply BPF filter
sudo ./target/release/snf-core --monitor --interface 1 --bpf "not port 22"
```

### Windows

```powershell
# Run PowerShell as Administrator

# Find available interfaces
.\target\release\snf-core.exe --list-interfaces

# Capture on interface 1
.\target\release\snf-core.exe --monitor --interface 1 -o output\live.ndjson
```

---

## Verifying Determinism

```bash
./target/release/snf-core --determinism-check --pcap-file evidence.pcap
```

Exit codes:
- `0` — PASS, output is SHA-256 identical across runs
- `1` — FAIL, output differs (report as a bug)
- `2` — ERROR, check could not complete

---

## Optional: GeoIP and ASN Enrichment

ASN and GeoIP enrichment is disabled by default. To enable:

1. Register for a free MaxMind account at [https://www.maxmind.com/en/geolite2/signup](https://www.maxmind.com/en/geolite2/signup)
2. Download `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb`
3. Place them in the `datasets/` directory
4. Enable in `snf.toml`:
   ```toml
   [intelligence]
   enable_asn_mapping   = true
   enable_geoip_mapping = true
   geo_db_path = "datasets/GeoLite2-City.mmdb"
   asn_db_path = "datasets/GeoLite2-ASN.mmdb"
   ```

---

## IOC Feed Management

SNF-Core loads IOC blocklists from CSV files at startup. To update feeds:

```bash
# Replace the blocklist files
cp new_ip_blocklist.csv datasets/ioc/ip_blocklist.csv
cp new_domain_blocklist.csv datasets/ioc/domain_blocklist.csv

# Restart SNF-Core — changes take effect on next startup
```

**CSV format:**
```
# IP blocklist: datasets/ioc/ip_blocklist.csv
ip,label,confidence,threat_actor
185.220.101.1,Tor_exit_node,90,Tor Network
203.170.84.119,Emotet_C2_epoch3,95,Emotet

# Domain blocklist: datasets/ioc/domain_blocklist.csv
domain,label,confidence,threat_actor
evil-c2.example.com,MalwareC2,85,ThreatActor
```

Confidence is 1–100. Lines starting with `#` are comments. UTF-8 encoding required (BOM is handled automatically).

---

## Performance Tuning

### CPU

```bash
# Auto-scale to available hardware (default)
./snf-core --forensic --pcap-file capture.pcap

# Pin to specific thread count
./snf-core --forensic --pcap-file capture.pcap --threads 8

# Force single-threaded (for constrained environments or determinism)
./snf-core --forensic --pcap-file capture.pcap --no-auto-scale
```

### Memory

The primary memory consumers are:
- `FlowTable` — pre-allocated at startup. Default 100,000 flows × N workers
- `EvidenceBundle` — grows with session length
- NDJSON write buffer — one per worker, 64KB default

For memory-constrained environments:
```toml
[performance]
worker_threads    = 2
max_flows         = 25000
packet_batch_size = 32
```

### Disk I/O

NDJSON output is the main disk bottleneck at high packet rates. Use an SSD for the output directory. For extremely high throughput, use a ramdisk:

```bash
# Linux — write to tmpfs
mkdir /tmp/snf-output
./snf-core --monitor --interface 1 -o /tmp/snf-output/live.ndjson
# Periodically rotate/move files to persistent storage
```

---

## Silent Sensor Deployment

For covert monitoring with minimal footprint:

```bash
# Stealth mode — zero console output, minimal resource usage
sudo ./target/release/snf-core --stealth \
  --interface 1 \
  --config /etc/snf/sensor.toml \
  -o /var/log/snf/events.ndjson
```

Recommended `sensor.toml` for silent sensors:

```toml
[output]
verbosity = 0         # Complete silence
output_dir = "/var/log/snf"

[performance]
worker_threads = 2    # Minimal CPU usage
```

### systemd Service

```ini
# /etc/systemd/system/snf-sensor.service
[Unit]
Description=SNF-Core Network Sensor
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/snf-core --stealth --interface 1 -o /var/log/snf/events.ndjson
Restart=on-failure
RestartSec=5
User=root
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now snf-sensor
sudo systemctl status snf-sensor
```

---

## Output Rotation

SNF-Core does not rotate output files internally. Use logrotate or a cron job:

```bash
# /etc/logrotate.d/snf
/var/log/snf/*.ndjson {
    daily
    rotate 30
    compress
    missingok
    notifempty
    postrotate
        systemctl restart snf-sensor
    endscript
}
```

---

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| `Permission denied` on live capture | Missing CAP_NET_RAW | `sudo setcap cap_net_raw+ep ./snf-core` |
| `Cannot open device` on Windows | Npcap not installed | Install Npcap with WinPcap-compatible mode |
| `IOC matching disabled` at startup | Blocklist file not found | Check `ioc_ip_blocklist_path` in config |
| High memory usage | Too many flows | Reduce `max_flows` in config |
| Low throughput | Too few workers | Increase `worker_threads` or use `--no-auto-scale` |
| Output file not created | `output_dir` not writable | Check directory permissions |
| `malformed lines skipped` warning | CSV file encoding | Ensure CSV files are UTF-8 (BOM handled automatically) |
