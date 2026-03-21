// src/analyzers/http/http2_analyzer.rs
//
// HTTP/2 protocol analyzer — basic header extraction.
//
// HTTP/2 uses binary framing (RFC 7540). Each frame:
//   length(3) + type(1) + flags(1) + stream_id(4) + payload
//
// This analyzer extracts pseudo-headers (:method, :path, :authority, :status)
// and selected regular headers (user-agent, content-type, content-length)
// from HEADERS frames using HPACK static table decoding.
//
// Scope (basic pass):
//   - Identifies HTTP/2 connection preface (PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n)
//   - Parses HEADERS frames (type 0x01)
//   - Decodes HPACK static table indexed headers only (index 1–61)
//   - Extracts :method, :path, :authority, :status, user-agent,
//     content-type, content-length
//   - Does NOT implement HPACK dynamic table (requires per-stream state)
//   - Does NOT implement HPACK Huffman decoding (literal headers only)
//
// Security:
//   - All frame lengths bounds-checked before slice
//   - Max frames per call capped at MAX_FRAMES_PER_CALL
//   - Header string values capped at MAX_HEADER_VALUE_LEN
//   - No unbounded allocation from untrusted length fields

use crate::core::packet_context::PacketContext;
use crate::config::engine_config::EngineConfig;
use crate::core::parse_error::{ParseResult, SnfParseError};

// ----------------------------------------------------------------
// CONSTANTS
// ----------------------------------------------------------------

/// HTTP/2 client connection preface (24 bytes).
pub const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// HTTP/2 frame header size in bytes.
const H2_FRAME_HEADER_LEN: usize = 9;

/// HTTP/2 HEADERS frame type.
const H2_FRAME_TYPE_HEADERS: u8 = 0x01;

/// HTTP/2 DATA frame type — skip but account for length.
const H2_FRAME_TYPE_DATA: u8 = 0x00;

/// SETTINGS frame — skip.
const H2_FRAME_TYPE_SETTINGS: u8 = 0x04;

/// Maximum frames to process per call (prevents CPU exhaustion on huge payloads).
const MAX_FRAMES_PER_CALL: usize = 32;

/// Maximum header value length to store.
const MAX_HEADER_VALUE_LEN: usize = 4096;

/// Maximum payload bytes per HEADERS frame to decode.
const MAX_HEADERS_PAYLOAD: usize = 16_384;

// ----------------------------------------------------------------
// HPACK STATIC TABLE (RFC 7541 Appendix A)
// Indices 1–61. Entry: (name, value).
// Only entries relevant to SNF extraction are included.
// Full table used for index→name lookup.
// ----------------------------------------------------------------

/// Returns the static header name for a given HPACK static table index (1-based).
/// Returns None for indices outside 1–61.
fn hpack_static_name(idx: u8) -> Option<&'static str> {
    match idx {
        1  => Some(":authority"),
        2  => Some(":method"),     // GET
        3  => Some(":method"),     // POST
        4  => Some(":path"),       // /
        5  => Some(":path"),       // /index.html
        6  => Some(":scheme"),     // http
        7  => Some(":scheme"),     // https
        8  => Some(":status"),     // 200
        9  => Some(":status"),     // 204
        10 => Some(":status"),     // 206
        11 => Some(":status"),     // 304
        12 => Some(":status"),     // 400
        13 => Some(":status"),     // 404
        14 => Some(":status"),     // 500
        15 => Some("accept-charset"),
        16 => Some("accept-encoding"),
        17 => Some("accept-language"),
        18 => Some("accept-ranges"),
        19 => Some("accept"),
        20 => Some("access-control-allow-origin"),
        21 => Some("age"),
        22 => Some("allow"),
        23 => Some("authorization"),
        24 => Some("cache-control"),
        25 => Some("content-disposition"),
        26 => Some("content-encoding"),
        27 => Some("content-language"),
        28 => Some("content-length"),
        29 => Some("content-location"),
        30 => Some("content-range"),
        31 => Some("content-type"),
        32 => Some("cookie"),
        33 => Some("date"),
        34 => Some("etag"),
        35 => Some("expect"),
        36 => Some("expires"),
        37 => Some("from"),
        38 => Some("host"),
        39 => Some("if-match"),
        40 => Some("if-modified-since"),
        41 => Some("if-none-match"),
        42 => Some("if-range"),
        43 => Some("if-unmodified-since"),
        44 => Some("last-modified"),
        45 => Some("link"),
        46 => Some("location"),
        47 => Some("max-forwards"),
        48 => Some("proxy-authenticate"),
        49 => Some("proxy-authorization"),
        50 => Some("range"),
        51 => Some("referer"),
        52 => Some("refresh"),
        53 => Some("retry-after"),
        54 => Some("server"),
        55 => Some("set-cookie"),
        56 => Some("strict-transport-security"),
        57 => Some("transfer-encoding"),
        58 => Some("user-agent"),
        59 => Some("vary"),
        60 => Some("via"),
        61 => Some("www-authenticate"),
        _  => None,
    }
}

/// Returns the pre-defined value for fully-indexed static table entries.
fn hpack_static_value(idx: u8) -> Option<&'static str> {
    match idx {
        2  => Some("GET"),
        3  => Some("POST"),
        4  => Some("/"),
        5  => Some("/index.html"),
        6  => Some("http"),
        7  => Some("https"),
        8  => Some("200"),
        9  => Some("204"),
        10 => Some("206"),
        11 => Some("304"),
        12 => Some("400"),
        13 => Some("404"),
        14 => Some("500"),
        _  => None,
    }
}

// ----------------------------------------------------------------
// PUBLIC ENTRY POINT
// ----------------------------------------------------------------

/// Attempt to parse HTTP/2 from `payload` into `ctx`.
///
/// Returns Ok(()) if the payload was parsed (or definitively is not HTTP/2).
/// Returns Err(SnfParseError) only for structural violations in a confirmed HTTP/2 stream.
pub fn analyze(
    ctx: &mut PacketContext,
    payload: &[u8],
    config: &EngineConfig,
) -> ParseResult {
    if payload.len() < H2_FRAME_HEADER_LEN {
        return Ok(());
    }

    // Detect HTTP/2 connection preface (client magic).
    // If present, skip it and process the frames that follow.
    let frame_start = if payload.starts_with(H2_PREFACE) {
        H2_PREFACE.len()
    } else {
        // Not starting with preface — could still be mid-stream HTTP/2.
        // Validate that the first 3 bytes look like a plausible frame length
        // before committing to parsing as HTTP/2.
        let first_frame_len = u24_be(payload, 0);
        if first_frame_len > MAX_HEADERS_PAYLOAD {
            return Ok(()); // Not HTTP/2 or payload too large — skip
        }
        0
    };

    parse_h2_frames(ctx, payload, frame_start, config)
}

// ----------------------------------------------------------------
// FRAME PARSER
// ----------------------------------------------------------------

fn parse_h2_frames(
    ctx: &mut PacketContext,
    payload: &[u8],
    start: usize,
    config: &EngineConfig,
) -> ParseResult {
    let mut pos = start;
    let mut frames_processed = 0;

    while pos + H2_FRAME_HEADER_LEN <= payload.len() {
        if frames_processed >= MAX_FRAMES_PER_CALL {
            break; // Cap — don't process unbounded frames
        }
        frames_processed += 1;

        // Frame header: length(3) + type(1) + flags(1) + stream_id(4, MSB reserved)
        let frame_length = u24_be(payload, pos);
        let frame_type   = payload[pos + 3];
        let _flags       = payload[pos + 4];
        // Stream ID: mask off reserved bit
        let _stream_id   = u32::from_be_bytes([
            payload[pos + 5] & 0x7F,
            payload[pos + 6],
            payload[pos + 7],
            payload[pos + 8],
        ]);

        let payload_start = pos + H2_FRAME_HEADER_LEN;
        let payload_end   = payload_start + frame_length;

        // Bounds check: entire frame must be within payload
        if payload_end > payload.len() {
            // Partial frame — normal for reassembly window, not an error
            break;
        }

        let frame_payload = &payload[payload_start..payload_end];

        match frame_type {
            H2_FRAME_TYPE_HEADERS => {
                parse_headers_frame(ctx, frame_payload, config)?;
            }
            H2_FRAME_TYPE_DATA | H2_FRAME_TYPE_SETTINGS => {
                // Skip — no actionable data for SNF
            }
            _ => {
                // Unknown frame type — skip payload, continue
            }
        }

        pos = payload_end;
    }

    Ok(())
}

// ----------------------------------------------------------------
// HEADERS FRAME PARSER
// ----------------------------------------------------------------

fn parse_headers_frame(
    ctx: &mut PacketContext,
    payload: &[u8],
    config: &EngineConfig,
) -> ParseResult {
    if payload.len() > MAX_HEADERS_PAYLOAD {
        return Err(SnfParseError::new(
            "HTTP2",
            format!("HEADERS frame payload {} > max {}", payload.len(), MAX_HEADERS_PAYLOAD),
            0,
        ));
    }

    // The HEADERS frame payload is the HPACK-encoded header block.
    // We implement static table decoding only (no dynamic table).
    decode_hpack(ctx, payload, config);
    Ok(())
}

// ----------------------------------------------------------------
// HPACK STATIC DECODER
// ----------------------------------------------------------------
// Decodes HPACK header block fragments.
// Handles:
//   - Indexed Header Field (first bit = 1): static table lookup
//   - Literal Header Field with Incremental Indexing (first 2 bits = 01):
//     name index + literal value
//   - Literal Header Field without Indexing (first 4 bits = 0000):
//     name index + literal value
//
// Does NOT handle:
//   - Dynamic table references (indices > 61)
//   - Huffman-encoded strings
//   - Dynamic table size updates
fn decode_hpack(
    ctx: &mut PacketContext,
    block: &[u8],
    config: &EngineConfig,
) {
    let mut pos = 0;

    while pos < block.len() {
        let byte = block[pos];

        // ---- Indexed Header Field (bit 7 = 1) ----
        // Representation: 1xxxxxxx
        // The entire entry (name + value) comes from the static table.
        if byte & 0x80 != 0 {
            let idx = byte & 0x7F;
            if idx >= 1 && idx <= 61 {
                if let (Some(name), Some(value)) = (hpack_static_name(idx), hpack_static_value(idx)) {
                    apply_header(ctx, name, value, config);
                }
            }
            pos += 1;
            continue;
        }

        // ---- Literal Header Field with Incremental Indexing (bits 7-6 = 01) ----
        // Representation: 01xxxxxx
        if byte & 0xC0 == 0x40 {
            let idx = byte & 0x3F;
            pos += 1;
            if idx == 0 {
                // New name (literal) + literal value — skip (no dynamic table)
                pos = skip_hpack_string(block, pos);
                pos = skip_hpack_string(block, pos);
            } else if idx <= 61 {
                // Static table name + literal value
                if let Some(name) = hpack_static_name(idx) {
                    if let Some((value, new_pos)) = read_hpack_string(block, pos) {
                        apply_header(ctx, name, &value, config);
                        pos = new_pos;
                    } else {
                        break; // Truncated
                    }
                } else {
                    pos = skip_hpack_string(block, pos);
                }
            } else {
                // Dynamic table reference — skip value
                pos = skip_hpack_string(block, pos);
            }
            continue;
        }

        // ---- Literal Header Field without Indexing (bits 7-4 = 0000) ----
        // Representation: 0000xxxx
        if byte & 0xF0 == 0x00 {
            let idx = byte & 0x0F;
            pos += 1;
            if idx == 0 {
                // Literal name + literal value — skip both
                pos = skip_hpack_string(block, pos);
                pos = skip_hpack_string(block, pos);
            } else if idx <= 61 {
                if let Some(name) = hpack_static_name(idx) {
                    if let Some((value, new_pos)) = read_hpack_string(block, pos) {
                        apply_header(ctx, name, &value, config);
                        pos = new_pos;
                    } else {
                        break;
                    }
                } else {
                    pos = skip_hpack_string(block, pos);
                }
            } else {
                pos = skip_hpack_string(block, pos);
            }
            continue;
        }

        // ---- Dynamic Table Size Update (bits 7-5 = 001) ----
        // Representation: 001xxxxx — skip
        if byte & 0xE0 == 0x20 {
            pos += 1; // Simple 5-bit integer — just advance
            continue;
        }

        // Unknown — advance one byte to avoid infinite loop
        pos += 1;
    }
}

// ----------------------------------------------------------------
// HEADER APPLICATION
// ----------------------------------------------------------------
// Maps decoded header name → PacketContext field.
// Only stores headers relevant to SNF analysis.

fn apply_header(
    ctx: &mut PacketContext,
    name: &str,
    value: &str,
    config: &EngineConfig,
) {
    // Cap value length — never store unbounded user-controlled strings
    let value = if value.len() > MAX_HEADER_VALUE_LEN {
        &value[..MAX_HEADER_VALUE_LEN]
    } else {
        value
    };

    match name {
        ":method" => {
            if ctx.http_method.is_none() {
                ctx.http_method  = Some(value.to_string());
                ctx.http_version = Some("HTTP/2".to_string());
            }
        }
        ":path" => {
            if ctx.http_uri.is_none() {
                ctx.http_uri = Some(value.to_string());
            }
        }
        ":authority" | "host" => {
            if ctx.http_host.is_none() {
                ctx.http_host = Some(value.to_string());
            }
        }
        ":status" => {
            if ctx.http_status_code.is_none() {
                if let Ok(code) = value.parse::<u16>() {
                    ctx.http_status_code = Some(code);
                    ctx.http_version = Some("HTTP/2".to_string());
                }
            }
        }
        "user-agent" => {
            if ctx.http_user_agent.is_none() {
                ctx.http_user_agent = Some(value.to_string());
            }
        }
        "content-type" => {
            if ctx.http_content_type.is_none() {
                ctx.http_content_type = Some(value.to_string());
            }
        }
        "content-length" => {
            if ctx.http_content_length.is_none() {
                if let Ok(len) = value.parse::<u64>() {
                    ctx.http_content_length = Some(len);
                }
            }
        }
        _ => {}
    }

    if config.output.show_http_logs && (name.starts_with(':') || name == "user-agent") {
        println!("[HTTP/2] {}: {}", name, value);
    }
}

// ----------------------------------------------------------------
// HPACK STRING HELPERS
// ----------------------------------------------------------------

/// Read an HPACK string literal from `block` starting at `pos`.
/// Returns (string_value, new_pos) or None if truncated or Huffman-encoded.
/// Huffman strings are skipped (not decoded) — returns None.
fn read_hpack_string(block: &[u8], pos: usize) -> Option<(String, usize)> {
    if pos >= block.len() {
        return None;
    }

    let byte = block[pos];
    let huffman = byte & 0x80 != 0;
    let str_len = (byte & 0x7F) as usize;
    let data_start = pos + 1;
    let data_end   = data_start + str_len;

    if data_end > block.len() {
        return None; // Truncated
    }

    if huffman {
        // Huffman decoding not implemented — skip and return None
        // so the caller skips this header rather than misinterpreting it.
        return None;
    }

    match std::str::from_utf8(&block[data_start..data_end]) {
        Ok(s) => Some((s.to_string(), data_end)),
        Err(_) => None,
    }
}

/// Skip an HPACK string literal starting at `pos`. Returns new pos.
/// If truncated, returns block.len() (safe sentinel).
fn skip_hpack_string(block: &[u8], pos: usize) -> usize {
    if pos >= block.len() {
        return block.len();
    }
    let str_len = (block[pos] & 0x7F) as usize;
    let new_pos = pos + 1 + str_len;
    new_pos.min(block.len())
}

// ----------------------------------------------------------------
// UTILITIES
// ----------------------------------------------------------------

/// Read 3 bytes big-endian as usize from `data` at `offset`.
/// Returns 0 if out of bounds.
#[inline]
fn u24_be(data: &[u8], offset: usize) -> usize {
    if offset + 3 > data.len() {
        return 0;
    }
    ((data[offset] as usize) << 16)
        | ((data[offset + 1] as usize) << 8)
        | (data[offset + 2] as usize)
}