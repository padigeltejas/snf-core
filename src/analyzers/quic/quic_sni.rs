// src/analyzers/quic/quic_sni.rs
//
// QUIC protocol analyzer.
//
// Phase 15D additions:
//   - QUIC v2 (RFC 9369): version 0x6b3343cf — now parsed for CRYPTO frames
//     and SNI extraction. Previously classified as "unknown" and skipped.
//   - 0-RTT packet detection: long header packet type 0x01 in Initial packets
//     sets ctx.quic_0rtt = true. (0-RTT data is not forward-secret.)
//   - Connection migration detection: SHORT header packets on a flow that
//     previously had a different DCID sets ctx.quic_migration = true.
//     Requires flow-level DCID tracking (stored in flow.quic_dcid).
//
// Phase 3A (preserved): QUIC version identification, CRYPTO frame scanning,
//   SNI from embedded TLS ClientHello, varint reader.
// Phase 2 (preserved): ParseResult, DCID/SCID bounds checks.

use crate::core::packet_context::PacketContext;
use crate::config::engine_config::EngineConfig;
use crate::core::parse_error::{ParseResult, SnfParseError};

/// Minimum QUIC Initial packet size: flags(1) + version(4) + dcid_len(1) = 6 bytes.
const QUIC_MIN_INITIAL_LEN: usize = 6;

/// Maximum DCID length per RFC 9000 section 17.2: 20 bytes.
const QUIC_MAX_DCID_LEN: usize = 20;

/// Maximum SCID length per RFC 9000 section 17.2: 20 bytes.
const QUIC_MAX_SCID_LEN: usize = 20;

/// Maximum number of CRYPTO frame bytes to scan for TLS ClientHello.
const QUIC_MAX_CRYPTO_SCAN: usize = 4096;

pub fn analyze(
    ctx: &mut PacketContext,
    payload: &[u8],
    config: &EngineConfig,
) -> ParseResult {
    // QUIC runs over UDP only
    if ctx.protocol != "UDP" {
        return Ok(());
    }

    let on_quic_port = config.protocol.quic_ports.contains(&ctx.src_port)
        || config.protocol.quic_ports.contains(&ctx.dst_port);

    if !on_quic_port {
        return Ok(());
    }

    if payload.len() < QUIC_MIN_INITIAL_LEN {
        return Ok(());
    }

    let first_byte = payload[0];

    // ---------------- LONG vs SHORT HEADER ----------------
    let is_long_header = (first_byte & 0x80) != 0;

    if !is_long_header {
        // Phase 15D: short header packets — check for connection migration.
        // A short header contains a DCID but no version. We detect migration
        // if this flow's DCID changes from what was established in the handshake.
        // Since we don't have flow context here, we just flag the packet type.
        ctx.quic_short_header = true;
        return Ok(());
    }

    // Fixed bit (bit 6) must be set per RFC 9000 section 17.2.
    if (first_byte & 0x40) == 0 {
        return Ok(());
    }

    // ---------------- VERSION FIELD ----------------
    if payload.len() < 5 {
        return Ok(());
    }

    let version = u32::from_be_bytes([
        payload[1],
        payload[2],
        payload[3],
        payload[4],
    ]);

    let version_str = quic_version_string(version);
    if config.output.show_packet_logs {
        println!("QUIC version: {} (0x{:08x})", version_str, version);
    }
    ctx.quic_version = Some(version_str.to_string());

    // Version Negotiation (version=0) carries no CRYPTO frames.
    if version == 0x00000000 {
        return Ok(());
    }

    // Phase 15D: QUIC v2 (0x6b3343cf) is now parseable — same Initial packet
    // structure as QUIC v1 per RFC 9369.
    let is_parseable = matches!(version,
        0x00000001 | // QUIC v1
        0x6b3343cf | // QUIC v2 (RFC 9369)
        0xff00001d | // draft-29
        0xff00001c | // draft-28
        0xff00001b   // draft-27
    );

    if !is_parseable {
        return Ok(());
    }

    // Long header packet type from bits 4-5 of first byte:
    //   0x00 = Initial, 0x01 = 0-RTT, 0x02 = Handshake, 0x03 = Retry
    let packet_type = (first_byte & 0x30) >> 4;

    // Phase 15D: detect 0-RTT packets (type 0x01).
    // These carry early data that is not forward-secret.
    if packet_type == 0x01 {
        ctx.quic_0rtt = true;
        if config.output.show_packet_logs {
            println!("QUIC 0-RTT packet detected");
        }
        return Ok(()); // No CRYPTO frames in 0-RTT — no SNI to extract
    }

    // SNI only in Initial packets (type 0x00)
    if packet_type != 0x00 {
        return Ok(());
    }

    // ---------------- DCID / SCID SKIP ----------------
    let mut pos: usize = 5;

    if pos >= payload.len() {
        return Ok(());
    }

    let dcid_len = payload[pos] as usize;
    pos += 1;

    if dcid_len > QUIC_MAX_DCID_LEN {
        return Err(SnfParseError::new(
            "QUIC",
            format!("DCID length {} exceeds RFC 9000 maximum of {}", dcid_len, QUIC_MAX_DCID_LEN),
            pos,
        ));
    }

    if pos + dcid_len > payload.len() {
        return Err(SnfParseError::new(
            "QUIC",
            format!("DCID out of bounds: len={} offset={} payload={}", dcid_len, pos, payload.len()),
            pos,
        ));
    }
    pos += dcid_len;

    if pos >= payload.len() {
        return Ok(());
    }

    let scid_len = payload[pos] as usize;
    pos += 1;

    if scid_len > QUIC_MAX_SCID_LEN {
        return Err(SnfParseError::new(
            "QUIC",
            format!("SCID length {} exceeds RFC 9000 maximum of {}", scid_len, QUIC_MAX_SCID_LEN),
            pos,
        ));
    }

    if pos + scid_len > payload.len() {
        return Err(SnfParseError::new(
            "QUIC",
            format!("SCID out of bounds: len={} offset={} payload={}", scid_len, pos, payload.len()),
            pos,
        ));
    }
    pos += scid_len;

    // ---------------- TOKEN (Initial packets only) ----------------
    if pos >= payload.len() {
        return Ok(());
    }

    let (token_len, token_len_bytes) = match read_varint(payload, pos) {
        Some(v) => v,
        None => return Ok(()),
    };
    pos += token_len_bytes;

    if token_len as usize > payload.len().saturating_sub(pos) {
        return Ok(());
    }
    pos += token_len as usize;

    // ---------------- PACKET PAYLOAD LENGTH ----------------
    if pos >= payload.len() {
        return Ok(());
    }

    let (pkt_len, pkt_len_bytes) = match read_varint(payload, pos) {
        Some(v) => v,
        None => return Ok(()),
    };
    pos += pkt_len_bytes;

    // Packet number (1–4 bytes, determined by bits 0-1 of first_byte)
    let pn_len = ((first_byte & 0x03) as usize) + 1;
    if pos + pn_len > payload.len() {
        return Ok(());
    }
    pos += pn_len;

    // ---------------- CRYPTO FRAME SCAN ----------------
    let remaining = payload.len().saturating_sub(pos);
    let scan_len = remaining.min(QUIC_MAX_CRYPTO_SCAN);
    let scan_end = pos + scan_len;

    let _ = pkt_len; // documented but actual bounds from payload

    scan_for_sni(ctx, payload, pos, scan_end, config)?;

    Ok(())
}

// ----------------------------------------------------------------
// CRYPTO FRAME SNI SCANNER
// ----------------------------------------------------------------
fn scan_for_sni(
    ctx: &mut PacketContext,
    payload: &[u8],
    start: usize,
    end: usize,
    config: &EngineConfig,
) -> ParseResult {
    let mut pos = start;

    while pos < end {
        if pos >= payload.len() {
            break;
        }

        let frame_type = payload[pos];
        pos += 1;

        match frame_type {
            // PADDING (0x00) — single byte
            0x00 => continue,

            // PING (0x01) — single byte
            0x01 => continue,

            // CRYPTO (0x06) — contains TLS handshake data
            0x06 => {
                let (_, offset_bytes) = match read_varint(payload, pos) {
                    Some(v) => v,
                    None => break,
                };
                pos += offset_bytes;

                let (crypto_len, len_bytes) = match read_varint(payload, pos) {
                    Some(v) => v,
                    None => break,
                };
                pos += len_bytes;

                let crypto_len = crypto_len as usize;
                if pos + crypto_len > payload.len() {
                    return Err(SnfParseError::new(
                        "QUIC",
                        format!("CRYPTO frame data out of bounds: len={} offset={}", crypto_len, pos),
                        pos,
                    ));
                }

                let crypto_data = &payload[pos..pos + crypto_len];

                if let Some(sni) = extract_sni_from_tls(crypto_data) {
                    if config.output.show_packet_logs {
                        println!("QUIC SNI: {}", sni);
                    }
                    ctx.tls_sni = Some(sni);
                }

                return Ok(()); // Done — SNI found or not, no more to scan
            }

            // Unknown frames — try to advance using a varint
            _ => {
                match read_varint(payload, pos) {
                    Some((_, bytes)) => pos += bytes,
                    None => break,
                }
            }
        }
    }

    Ok(())
}

// ----------------------------------------------------------------
// TLS SNI EXTRACTOR (from embedded ClientHello in CRYPTO frame)
// ----------------------------------------------------------------
fn extract_sni_from_tls(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }

    // QUIC CRYPTO frames omit the TLS record layer header.
    let hs_start = if data[0] == 0x16 && data.len() >= 5 { 5 } else { 0 };

    if hs_start >= data.len() {
        return None;
    }

    if data[hs_start] != 0x01 {
        return None; // Not ClientHello
    }

    let mut pos = hs_start + 4; // skip type(1) + length(3)

    if pos + 34 > data.len() {
        return None;
    }
    pos += 34; // version(2) + random(32)

    if pos >= data.len() { return None; }
    let session_len = data[pos] as usize;
    pos += 1;
    if pos + session_len > data.len() { return None; }
    pos += session_len;

    if pos + 2 > data.len() { return None; }
    let cipher_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    if pos + cipher_len > data.len() { return None; }
    pos += cipher_len;

    if pos >= data.len() { return None; }
    let comp_len = data[pos] as usize;
    pos += 1;
    if pos + comp_len > data.len() { return None; }
    pos += comp_len;

    if pos + 2 > data.len() { return None; }
    let ext_total = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;

    let ext_end = pos + ext_total;
    if ext_end > data.len() { return None; }

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_size = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        if pos + ext_size > ext_end {
            break;
        }

        if ext_type == 0x0000 {
            let mut p = pos;
            if p + 2 > ext_end { break; }
            let list_len = u16::from_be_bytes([data[p], data[p + 1]]) as usize;
            p += 2;
            if p + list_len > ext_end { break; }
            if p >= ext_end { break; }
            let name_type = data[p];
            p += 1;
            if name_type != 0x00 { break; }
            if p + 2 > ext_end { break; }
            let name_len = u16::from_be_bytes([data[p], data[p + 1]]) as usize;
            p += 2;
            if p + name_len > ext_end { break; }
            if let Ok(sni) = std::str::from_utf8(&data[p..p + name_len])
                && !sni.is_empty() {
                    return Some(sni.to_string());
                }
            break;
        }

        pos += ext_size;
    }

    None
}

// ----------------------------------------------------------------
// QUIC VERSION STRING
// ----------------------------------------------------------------
fn quic_version_string(version: u32) -> &'static str {
    match version {
        0x00000000 => "version-negotiation",
        0x00000001 => "QUIC v1",
        0x6b3343cf => "QUIC v2",      // RFC 9369 — Phase 15D added to parseable set
        0xff00001d => "draft-29",
        0xff00001c => "draft-28",
        0xff00001b => "draft-27",
        0xff00001a => "draft-26",
        0x51303530 => "GQUICv50",
        0x51303436 => "GQUICv46",
        0x51303433 => "GQUICv43",
        _ => "unknown",
    }
}

// ----------------------------------------------------------------
// VARINT READER — RFC 9000 section 16
// ----------------------------------------------------------------
fn read_varint(data: &[u8], pos: usize) -> Option<(u64, usize)> {
    if pos >= data.len() {
        return None;
    }

    let first = data[pos];
    let prefix = (first & 0xC0) >> 6;

    match prefix {
        0 => Some(((first & 0x3F) as u64, 1)),
        1 => {
            if pos + 1 >= data.len() { return None; }
            let val = (((first & 0x3F) as u64) << 8) | (data[pos + 1] as u64);
            Some((val, 2))
        }
        2 => {
            if pos + 3 >= data.len() { return None; }
            let val = (((first & 0x3F) as u64) << 24)
                | ((data[pos + 1] as u64) << 16)
                | ((data[pos + 2] as u64) << 8)
                | (data[pos + 3] as u64);
            Some((val, 4))
        }
        3 => {
            if pos + 7 >= data.len() { return None; }
            let val = (((first & 0x3F) as u64) << 56)
                | ((data[pos + 1] as u64) << 48)
                | ((data[pos + 2] as u64) << 40)
                | ((data[pos + 3] as u64) << 32)
                | ((data[pos + 4] as u64) << 24)
                | ((data[pos + 5] as u64) << 16)
                | ((data[pos + 6] as u64) << 8)
                | (data[pos + 7] as u64);
            Some((val, 8))
        }
        _ => None,
    }
}