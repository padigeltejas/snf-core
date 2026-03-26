# Security Policy

## Reporting a Vulnerability

Do NOT open a public GitHub issue for security vulnerabilities.
Email: snflabs.io@gmail.com

Include: description, reproduction steps, potential impact.

### Triaging & SLA
- **Triaged by:** Tejas Padigel (SNF Labs Founder/Maintainer).
- **Acknowledgement SLA:** Within 72 hours.
- **Fix Delivery SLA:** Patched releases are issued within 7 days for DoS bugs and 48 hours for arbitrary code execution or out-of-bounds vectors.
- **Disclosure:** We will explicitly credit the researcher in our advisories upon release.

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
