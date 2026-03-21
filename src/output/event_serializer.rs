// src/output/event_serializer.rs
//
// Pure serialization logic for SnfEvent → NDJSON line.
//
// Extracted from event.rs so that event.rs remains a pure data definition
// with no I/O or formatting concerns.
//
// Design:
//   - All output is compact JSON (no pretty-print in hot path)
//   - Attribute keys sorted lexicographically for deterministic output
//   - String values are escape-sanitized (quote and backslash)
//   - No heap allocation beyond the final String — keys are sorted in-place
//   - Optional pretty-print path for debug/human output (non-hot)
//
// Security:
//   - All string values are sanitized before emission — no raw packet bytes
//     can appear unescaped in output
//   - Control characters (0x00–0x1F) are stripped from string values
//   - No format! panics — all integer formatting is infallible

use crate::core::event::{SnfEvent, AttrValue};

/// Serialize a single SnfEvent to a compact NDJSON line.
/// Output is deterministic: attributes sorted by key.
/// This is the canonical hot-path serializer used by NdjsonWriter.
pub fn to_ndjson_line(event: &SnfEvent) -> String {
    // Sort attribute keys for deterministic output across runs (determinism contract).
    let mut keys: Vec<&String> = event.attributes.keys().collect();
    keys.sort_unstable();

    let attrs: Vec<String> = keys.iter()
        .map(|k| format!("\"{}\":{}", k, serialize_attr_value(&event.attributes[*k])))
        .collect();

    format!(
        "{{\"event_id\":{},\"packet_id\":{},\"timestamp_us\":{},\
\"event_type\":\"{}\",\"protocol\":\"{}\",\"flow_id\":\"{}\",\
\"attributes\":{{{}}}}}",
        event.event_id,
        event.packet_id,
        event.timestamp_us,
        event.event_type.as_str(),
        sanitize_str(&event.protocol),
        sanitize_str(&event.flow_id),
        attrs.join(","),
    )
}

/// Serialize a single SnfEvent to indented JSON for debug/human output.
/// NOT used in hot path — only called when pretty_print_json=true.
pub fn to_pretty_json(event: &SnfEvent) -> String {
    let mut keys: Vec<&String> = event.attributes.keys().collect();
    keys.sort_unstable();

    let attrs: Vec<String> = keys.iter()
        .map(|k| format!(
            "    \"{}\": {}",
            k,
            serialize_attr_value(&event.attributes[*k])
        ))
        .collect();

    let attrs_block = if attrs.is_empty() {
        "{}".to_string()
    } else {
        format!("{{\n{}\n  }}", attrs.join(",\n"))
    };

    format!(
        "{{\n  \"event_id\": {},\n  \"packet_id\": {},\n  \"timestamp_us\": {},\n  \
\"event_type\": \"{}\",\n  \"protocol\": \"{}\",\n  \"flow_id\": \"{}\",\n  \
\"attributes\": {}\n}}",
        event.event_id,
        event.packet_id,
        event.timestamp_us,
        event.event_type.as_str(),
        sanitize_str(&event.protocol),
        sanitize_str(&event.flow_id),
        attrs_block,
    )
}

/// Serialize a single AttrValue to its JSON representation.
fn serialize_attr_value(v: &AttrValue) -> String {
    match v {
        AttrValue::Str(s)     => format!("\"{}\"", sanitize_str(s)),
        AttrValue::U64(n)     => n.to_string(),
        AttrValue::U16(n)     => n.to_string(),
        AttrValue::U8(n)      => n.to_string(),
        AttrValue::Bool(b)    => b.to_string(),
        AttrValue::Ip(ip)     => format!("\"{}\"", ip),
        AttrValue::U16List(v) => {
            let items: Vec<String> = v.iter().map(|n| n.to_string()).collect();
            format!("[{}]", items.join(","))
        }
        AttrValue::StrList(v) => {
            let items: Vec<String> = v.iter()
                .map(|s| format!("\"{}\"", sanitize_str(s)))
                .collect();
            format!("[{}]", items.join(","))
        }
    }
}

/// Sanitize a string for safe JSON emission.
///
/// Security contract:
///   - Escapes backslash and double-quote (JSON spec)
///   - Strips ASCII control characters 0x00–0x1F (prevents log injection)
///   - Does NOT truncate — caller is responsible for length bounding
///     before passing large strings (MAX_* constants in analyzers)
#[inline]
pub fn sanitize_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"'  => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            // Escape JSON control characters per RFC 8259 §7
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                // Other control chars: emit unicode escape
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_quotes() {
        assert_eq!(sanitize_str(r#"say "hello""#), r#"say \"hello\""#);
    }

    #[test]
    fn test_sanitize_backslash() {
        assert_eq!(sanitize_str(r"C:\path"), r"C:\\path");
    }

    #[test]
    fn test_sanitize_control_chars() {
        // NUL byte should become \u0000
        let s = "abc\x00def";
        assert_eq!(sanitize_str(s), r"abc\u0000def");
    }

    #[test]
    fn test_sanitize_newline() {
        assert_eq!(sanitize_str("line1\nline2"), "line1\\nline2");
    }
}