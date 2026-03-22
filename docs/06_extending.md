# Extending SNF-Core

This guide explains how to add new protocol analyzers, new event types, new IOC feeds, and new behavioral detectors to SNF-Core.

All contributions must follow the [Non-Negotiable Rules](../CONTRIBUTING.md#non-negotiable-rules). Read CONTRIBUTING.md before starting.

---

## Adding a Protocol Analyzer

Adding a protocol to SNF-Core involves 8 steps. Each step is required — skipping any will result in a compile error or missing output.

---

### Step 1 — Add fields to PacketContext

All per-packet data lives in `PacketContext` (`src/core/packet_context.rs`). Add your protocol's fields to:

1. The **struct definition**
2. The **`new()` constructor**
3. The **`PacketContextBuilder::build()`** in `src/core/packet_context_builder.rs`

All three must always be in sync. A field missing from `new()` or `PacketContextBuilder` will cause a compile error — this is intentional.

```rust
// src/core/packet_context.rs — struct definition
pub struct PacketContext {
    // ... existing fields ...

    // ---------------- YOUR PROTOCOL ----------------
    /// Brief description of what this field contains.
    pub your_field:        Option<String>,
    /// Another field.
    pub your_other_field:  Option<u16>,
    pub your_flag:         bool,
}

// In new() constructor — initialize to safe defaults
Self {
    // ... existing initializations ...
    your_field:        None,
    your_other_field:  None,
    your_flag:         false,
}
```

```rust
// src/core/packet_context_builder.rs — PacketContextBuilder::build()
PacketContext {
    // ... existing initializations ...
    your_field:        None,
    your_other_field:  None,
    your_flag:         false,
}
```

**Rules for PacketContext fields:**
- Use `Option<T>` for fields that may not be present in every packet
- Use `bool` with a `false` default for flags
- Use `Vec<T>` with `Vec::new()` for list fields
- Never use `unwrap()` or `expect()` when reading these fields downstream

---

### Step 2 — Write the analyzer

Create `src/intelligence/your_protocol.rs` (or `src/analyzers/your_protocol.rs`):

```rust
// src/intelligence/your_protocol.rs
//
// YourProtocol analyzer.
//
// Detects YourProtocol on port XXXX and extracts [describe what].
//
// Design constraints:
//   - All loops bounded by MAX_* constants
//   - All buffer reads bounds-checked before access
//   - No unwrap/expect in any path
//   - UTF-8 validation on all string fields extracted from packets

use crate::core::packet_context::PacketContext;
use crate::config::engine_config::EngineConfig;

/// Maximum items to extract from a single packet (prevents O(n) explosion
/// on crafted packets with unreasonably large field counts).
const MAX_YOUR_ITEMS: usize = 64;

/// Minimum payload length required for a valid YourProtocol packet.
const MIN_PAYLOAD_LEN: usize = 8;

pub struct YourProtocolAnalyzer;

impl YourProtocolAnalyzer {
    pub fn analyze(
        ctx: &mut PacketContext,
        payload: &[u8],
        config: &EngineConfig,
    ) {
        // Config gate — check before any work
        if !config.protocol.enable_your_protocol {
            return;
        }

        // Port check
        if ctx.dst_port != 9999 && ctx.src_port != 9999 {
            return;
        }

        // Minimum length guard — always check before indexing
        if payload.len() < MIN_PAYLOAD_LEN {
            return;
        }

        // Parse header — bounds-checked
        let version = payload[0];
        let msg_type = payload[1];

        // Validate — reject malformed packets silently
        if version != 1 {
            return;
        }

        // Extract a length-prefixed field safely
        let name_len = payload[2] as usize;
        if 3 + name_len > payload.len() {
            return;  // truncated packet — exit cleanly
        }

        let name_bytes = &payload[3..3 + name_len];

        // UTF-8 validate all string fields from packets
        let name = match std::str::from_utf8(name_bytes) {
            Ok(s) => s.trim(),
            Err(_) => return,  // malformed encoding — discard silently
        };

        // Sanity-check extracted values before storing
        if name.is_empty() || name.len() > 256 {
            return;
        }

        // Set fields on PacketContext
        ctx.your_field       = Some(name.to_string());
        ctx.your_other_field = Some(msg_type as u16);
        ctx.your_flag        = true;
    }
}
```

**Mandatory analyzer rules:**
- Every buffer access must be bounds-checked before indexing
- Every loop must be bounded by a `MAX_*` constant
- Every string field from a packet must be UTF-8 validated
- Never `panic!`, `unwrap()`, or `expect()` — malformed packets must be handled gracefully
- Early-return on any validation failure — do not emit partial data

---

### Step 3 — Register the module

Add to `src/intelligence/mod.rs`:

```rust
pub mod your_protocol;
```

---

### Step 4 — Add a config gate

Add to `src/config/protocol_config.rs`:

```rust
pub struct ProtocolConfig {
    // ... existing fields ...

    /// Enable YourProtocol analysis.
    pub enable_your_protocol: bool,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            // ... existing defaults ...
            enable_your_protocol: true,
        }
    }
}
```

---

### Step 5 — Wire into AnalyzerManager

Add to `src/core/analyzer_manager.rs` in the `analyze()` method, at the appropriate position in the fixed analyzer order:

```rust
// In AnalyzerManager::analyze()
if config.protocol.enable_your_protocol {
    YourProtocolAnalyzer::analyze(ctx, payload, config);
}
```

Import the analyzer at the top of the file:

```rust
use crate::intelligence::your_protocol::YourProtocolAnalyzer;
```

---

### Step 6 — Add EventType variants

Add to `src/core/event.rs` in **two places**:

```rust
// 1. The EventType enum
pub enum EventType {
    // ... existing variants ...
    YourProtocolEvent,
}

// 2. The as_str() implementation — compiler enforces exhaustiveness
impl EventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            // ... existing arms ...
            EventType::YourProtocolEvent => "your_protocol.event",
        }
    }
}
```

The compiler will error if `as_str()` is missing an arm — this is intentional and prevents silent event type drops.

---

### Step 7 — Emit events in the pipeline

Add event emission to `src/pipeline/packet_pipeline.rs` in the `emit_protocol_events()` function:

```rust
// In emit_protocol_events()
if config.protocol.enable_your_protocol {
    if let Some(ref field) = ctx.your_field {
        let mut e = SnfEvent::new(
            0, pid, ts,
            EventType::YourProtocolEvent,
            "YOURPROTO",
            flow_id,
        );
        // Add attributes — note: use attr_u64() for integers, attr_str() for strings
        // AttrValue::Int and AttrValue::Float do NOT exist
        e.attr_str("your_field", field.clone());
        if let Some(other) = ctx.your_other_field {
            e.attr_u16("your_other_field", other);
        }
        e.attr_bool("your_flag", ctx.your_flag);
        bus.emit(e);

        if config.output.show_packet_logs {
            println!("[YOURPROTO] field={} flag={}", field, ctx.your_flag);
        }
    }
}
```

---

### Step 8 — Write tests

Add a `#[cfg(test)]` module to your analyzer file:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::packet_context::PacketContext;
    use crate::config::engine_config::EngineConfig;
    use std::net::IpAddr;

    fn make_ctx(src_port: u16, dst_port: u16) -> PacketContext {
        PacketContext::new(
            "192.168.1.1".parse().unwrap(),
            "192.168.1.2".parse().unwrap(),
            src_port,
            dst_port,
            "TCP",
            100,
            1700000000000000,
        )
    }

    #[test]
    fn test_valid_packet_extracted() {
        let payload = vec![
            0x01,       // version = 1
            0x02,       // msg_type = 2
            0x05,       // name_len = 5
            b'h', b'e', b'l', b'l', b'o',  // name = "hello"
        ];
        let config = EngineConfig::default();
        let mut ctx = make_ctx(12345, 9999);
        YourProtocolAnalyzer::analyze(&mut ctx, &payload, &config);
        assert_eq!(ctx.your_field, Some("hello".to_string()));
        assert_eq!(ctx.your_other_field, Some(2));
        assert!(ctx.your_flag);
    }

    #[test]
    fn test_wrong_port_ignored() {
        let payload = vec![0x01, 0x02, 0x00];
        let config = EngineConfig::default();
        let mut ctx = make_ctx(12345, 80);  // wrong port
        YourProtocolAnalyzer::analyze(&mut ctx, &payload, &config);
        assert!(ctx.your_field.is_none());
    }

    #[test]
    fn test_too_short_ignored() {
        let payload = vec![0x01];  // too short
        let config = EngineConfig::default();
        let mut ctx = make_ctx(12345, 9999);
        YourProtocolAnalyzer::analyze(&mut ctx, &payload, &config);
        assert!(ctx.your_field.is_none());
    }

    #[test]
    fn test_truncated_name_ignored() {
        let payload = vec![
            0x01, 0x02,
            0x0a,  // name_len = 10, but only 3 bytes follow
            b'a', b'b', b'c',
        ];
        let config = EngineConfig::default();
        let mut ctx = make_ctx(12345, 9999);
        YourProtocolAnalyzer::analyze(&mut ctx, &payload, &config);
        assert!(ctx.your_field.is_none());
    }

    #[test]
    fn test_invalid_utf8_ignored() {
        let payload = vec![
            0x01, 0x02,
            0x02,       // name_len = 2
            0xff, 0xfe, // invalid UTF-8
        ];
        let config = EngineConfig::default();
        let mut ctx = make_ctx(12345, 9999);
        YourProtocolAnalyzer::analyze(&mut ctx, &payload, &config);
        assert!(ctx.your_field.is_none());
    }

    #[test]
    fn test_config_gate_disables_analyzer() {
        let payload = vec![0x01, 0x02, 0x00];
        let mut config = EngineConfig::default();
        config.protocol.enable_your_protocol = false;
        let mut ctx = make_ctx(12345, 9999);
        YourProtocolAnalyzer::analyze(&mut ctx, &payload, &config);
        assert!(ctx.your_field.is_none());
    }
}
```

**Test coverage requirements:**
- Happy path — valid packet, all fields extracted correctly
- Wrong port — analyzer must not activate
- Too short — minimum length guard
- Truncated fields — length prefix points past end of buffer
- Invalid UTF-8 — must not panic, must return cleanly
- Config gate disabled — analyzer must do nothing

---

### Final Checklist

Before opening a PR:

```bash
cargo build           # 0 errors, 0 warnings
cargo test            # all tests pass
cargo clippy -- -D warnings   # clean
cargo fmt --check     # formatted
```

Verify your new event appears in output:
```bash
./target/release/snf-core --forensic --pcap-file your_test.pcap | grep your_protocol
```

---

## Adding IOC Feeds

To add entries to the offline IOC blocklists:

```bash
# Append to IP blocklist
echo "1.2.3.4,MalwareC2,85,ThreatActorName" >> datasets/ioc/ip_blocklist.csv

# Append to domain blocklist
echo "evil.example.com,MalwareC2,85,ThreatActorName" >> datasets/ioc/domain_blocklist.csv
```

**CSV format:**
```
ip,label,confidence,threat_actor
1.2.3.4,label_no_spaces,85,Threat Actor Name
```

Rules for IOC contributions:
- Confidence is 1–100. Use 90+ only for verified C2 infrastructure
- Label must not contain commas
- Threat actor name should match established naming conventions (Emotet, Cobalt Strike, APT28, etc.)
- Only include entries from verifiable public sources (Feodo Tracker, Abuse.ch, MalwareBazaar, URLhaus)
- Include the source URL in your PR description

---

## Adding JA3/JA4 Fingerprints

```bash
# JA3: 32-character hex hash
echo "aabbccddeeff00112233445566778899,MalwareClient_v2,ThreatActorName" >> datasets/ja3/ja3_fingerprints.csv

# JA4: fingerprint string
echo "t13d191000_9dc949149365,CobaltStrike_HTTPS,Cobalt Strike" >> datasets/ja4/ja4_fingerprints.csv
```

**CSV format:**
```
hash,label,threat_actor
<32-hex-chars>,label_no_spaces,Threat Actor Name
```

The `threat_actor` column is optional — omit or leave empty for benign tool fingerprints (browsers, libraries).

---

## Adding Behavioral Detectors

Behavioral detectors live in `src/behavior/`. They consume a `PacketContext` and a `Flow` and emit `BehaviorAlert` events.

```rust
// src/behavior/your_detector.rs

use crate::core::packet_context::PacketContext;
use crate::flow::flow_struct::Flow;
use crate::config::engine_config::EngineConfig;
use crate::core::event_bus::EventBus;

pub struct YourDetector {
    // per-session state
}

impl YourDetector {
    pub fn new(config: &EngineConfig) -> Self {
        Self { /* init */ }
    }

    pub fn process(
        &mut self,
        ctx: &PacketContext,
        flow: &Flow,
        flow_id: &str,
        config: &EngineConfig,
        event_bus: &mut Option<EventBus>,
    ) {
        // Detection logic
        // Emit events via event_bus if threshold crossed
    }
}
```

Wire into `BehaviorEngine` in `src/behavior/mod.rs`.

---

## Architecture Notes for Contributors

- **PacketContext is stack-allocated per packet** — keep field types small, avoid heap allocation where possible
- **AnalyzerManager runs in fixed order** — analyzers earlier in the order can set fields that later analyzers read
- **EventBus is per-worker** — never share an EventBus between workers or threads
- **EvidenceBundle is per-worker** — merged at session end via `merge_from()`
- **All intelligence is loaded at startup and immutable** — no runtime updates to JA3/JA4/IOC data
- **Determinism is sacred** — see [02_determinism.md](02_determinism.md) before touching any analysis path
