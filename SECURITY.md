# Security Policy

## Reporting a Vulnerability

Do NOT open a public GitHub issue for security vulnerabilities.
Email: padigeltejas@gmail.com

Include: description, reproduction steps, potential impact.
You will receive acknowledgement within 72 hours.

## Security Model

SNF-Core treats every PCAP as a potentially adversarial file.

All parsers enforce:
- Bounds-checked buffer reads before every array access
- `saturating_add()` / `saturating_sub()` for all counter arithmetic
- `MAX_*` constants capping all loops on untrusted data
- UTF-8 validation on all string fields from packets
- No unbounded heap allocation from packet data

Crafted packet data causing a panic or out-of-bounds access is a P0 security bug.

## Supported Versions

| Version | Supported |
|---|---|
| 1.x | Yes |
