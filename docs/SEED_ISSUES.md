# Seed Issues for SNF-Core

To foster community contribution and avoid the "dead repository" look, we recommend creating the following GitHub issues immediately. Label them with `good first issue` and `enhancement`.

---

## Issue 1: Add Unit Tests for HTTP/2 HPACK Decoder Edge Cases
**Title:** Add unit tests for HTTP/2 HPACK decoder edge cases
**Description:**
Currently, our `HTTP/2` analyzer processes standard HPACK pseudo-headers (`:method`, `:path`), but we are lacking test coverage for maliciously crafted sizes (e.g., Integer Overflow vulnerabilities in the variable-length integer representation).
We need a contributor to:
1. Review `src/analyzers/http/http2_analyzer.rs`.
2. Write unit tests passing byte arrays with Max-Size HPACK boundaries.
3. Ensure no panics occur on illegal index values.

**Labels:** `good first issue`, `security`, `testing`

---

## Issue 2: Implement PCAP-NG Block Parser for Interface Metadata
**Title:** Implement PCAP-NG block parser for interface metadata
**Description:**
We natively read `.pcap` files successfully, and our underlying `pcap` crate handles standard flows. However, for deterministic outputs on `.pcapng` files, extracting the Interface Description Block (IDB) ensures we log correct interface drop counts natively. 
To pick this up:
1. Intercept PCAP-NG block IDs in the main offline capture loop.
2. Store MAC/Link-Type in the `EvidenceBundle`.

**Labels:** `good first issue`, `core`, `enhancement`

---

## Issue 3: Extend ICMP Parser to Support Specific IPv6 NDP Types
**Title:** Extend ICMP parser to support specific IPv6 NDP Types
**Description:**
The core ICMP parser supports ICMPv4 correctly (echo requests, unreachable). We need support for capturing IPv6 Neighbor Discovery Protocol (NDP) router advertisements (Types 133, 134, 135, 136).
This is heavily requested for edge anomaly tracking.

**Labels:** `good first issue`, `protocols`, `help wanted`