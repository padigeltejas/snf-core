# Extending SNF-Core

## Adding a Protocol Analyzer — 8 Steps

### 1. Create src/analyzers/your_protocol.rs
```rust
use crate::core::packet_context::PacketContext;
use crate::config::engine_config::EngineConfig;
use crate::core::parse_error::{ParseResult, SnfParseError};

pub fn analyze(ctx: &mut PacketContext, payload: &[u8], config: &EngineConfig) -> ParseResult {
    if ctx.src_port != 9999 && ctx.dst_port != 9999 { return Ok(()); }
    if payload.len() < 8 {
        return Err(SnfParseError::new("YourProtocol", "too short".into(), 0));
    }
    ctx.your_field = Some("value".to_string());
    Ok(())
}
```

### 2. Add fields to src/core/packet_context.rs
Add to struct AND to new() constructor.

### 3. Add same fields to src/core/packet_context_builder.rs
Both initializers must always be in sync.

### 4. Add to src/analyzers/mod.rs
`pub mod your_protocol;`

### 5. Add config gate to src/config/protocol_config.rs
`pub enable_your_protocol: bool,` with default `true`.

### 6. Wire into src/core/analyzer_manager/mod.rs
```rust
if config.protocol.enable_your_protocol {
    if let Err(e) = your_protocol::analyze(ctx, payload, config) { errors.push(e); }
}
```

### 7. Add EventType variant to src/core/event.rs
Add variant AND as_str() mapping — compiler enforces exhaustiveness.

### 8. Add emission to src/pipeline/packet_pipeline.rs
```rust
if config.protocol.enable_your_protocol {
    if let Some(ref val) = ctx.your_field {
        let mut e = SnfEvent::new(0, pid, ts, EventType::YourEvent, "PROTO", flow_id);
        e.attr_str("your_field", val.clone());
        bus.emit(e);
    }
}
```

## Rules
- 0 errors, 0 warnings
- No .unwrap() or .expect()
- All buffer reads bounds-checked
- All loops capped with MAX_* constant
- UTF-8 validation on all string fields from packets
- AttrValue::Int and AttrValue::Float do not exist — use attr_u64() and attr_str()
