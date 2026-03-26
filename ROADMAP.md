# SNF-Core Roadmap

This Roadmap highlights the short-term and medium-term milestones for the SNF-Core open-source edition.

## Near Term (v1.1.X)

- [ ] **Fuzzing Infrastructure:** Integrate `cargo-fuzz` to aggressively test packet parsers for DNS, TLS, QUIC, and HTTP/2 against malformed inputs to harden security and prevent panics.
- [ ] **Protocol Conformance Suite:** Implement known bad PCAPs showcasing deliberate RFC deviations and add assertions confirming protocol analyzers flag them correctly.
- [ ] **Cross-Platform Delivery:** Establish seamless CI artifact generation for macOS (x86_64, aarch64), Linux (Ubuntu, RHEL), and Windows (MSVC/GNU).

## Medium Term (v1.2.X)

- [ ] **Expanded Threat Feeds:** Publish an open-source stream of daily-updated JA3/JA4 IOC blocks tailored to evolving botnets and ransomware actors.
- [ ] **Community Extensibility API:** Document and finalize traits allowing third parties to inject custom custom rules and stateless packet dissection plugins natively without touching core parsing loops.
- [ ] **Enhanced Determinism Audits:** Auto-generate cryptographic signing manifests (PKCS#7 equivalent via OpenSSL/Ring) mapping PCAP hashes to the final NDJSON session output.

## Long Term (v2.0)

- [ ] **Zero-Copy AF_XDP Tuning Guides:** Port over detailed eBPF tutorials on squeezing sub-microsecond throughput latency for standard network adapters currently in the enterprise offering.

### Contribution Notes
Interested in tackling any bullet points? Grab an unassigned one, drop an issue indicating you're working on it, and label it `enhancement` or `good first issue`!
