// src/analyzers/tls.rs
//
// TLS protocol analyzer.
//
// Phase 15B additions:
//   - 0-RTT detection: Early Data extension (0x002a) in ClientHello sets
//     ctx.tls_early_data = true. This indicates a TLS 1.3 0-RTT attempt.
//   - Certificate chain extraction: now stores ALL certs in the chain
//     (not just the leaf). ctx.tls_cert_chain_len records total depth.
//   - OCSP Stapling detection: status_request extension (0x0012) in ClientHello
//     sets ctx.tls_ocsp_stapling = true.
//   - ECH (Encrypted Client Hello) detection: extension type 0xfe0d (draft) and
//     0x0039 (RFC) in ClientHello sets ctx.tls_ech_present = true.
//     ECH hides the true SNI inside an encrypted extension — the outer SNI
//     will show only the ECH provider domain (e.g. "cloudflare-ech.com").
//
// Phase 3A (preserved): ALPN, session ticket/PSK resumption, ServerHello parsing,
//   certificate CN/SAN/issuer/expiry, TLS version detection.
// Phase 2 (preserved): ParseResult, buffer cap, bounds-safe.

use crate::core::packet_context::PacketContext;
use crate::config::engine_config::EngineConfig;
use crate::discovery::dns_cache::DnsCache;
use crate::flow::flow_struct::Flow;
use crate::core::parse_error::{ParseResult, SnfParseError};
use x509_parser::prelude::*;

/// Maximum number of ALPN protocol strings to store per ClientHello.
const MAX_ALPN_PROTOCOLS: usize = 16;

/// Maximum length of a single ALPN protocol string per RFC 7301.
const MAX_ALPN_PROTO_LEN: usize = 255;

/// Maximum certificates to parse from a Certificate handshake message.
/// Prevents unbounded iteration on adversarial cert chains.
const MAX_CERT_CHAIN_DEPTH: usize = 8;

pub fn analyze(
    ctx: &mut PacketContext,
    payload: &[u8],
    flow: &mut Flow,
    _dns_cache: &mut DnsCache,
    config: &EngineConfig,
) -> ParseResult {
    // TLS only runs on TCP
    if ctx.protocol != "TCP" {
        return Ok(());
    }

    if payload.len() < 5 {
        return Ok(());
    }

    // ---------------- PORT + SIGNATURE CHECK ----------------
    let on_known_tls_port = config.protocol.tls_ports.contains(&ctx.src_port)
        || config.protocol.tls_ports.contains(&ctx.dst_port);

    let looks_like_tls = payload[0] == 0x16
        && payload[1] == 0x03
        && matches!(payload[2], 0x01 | 0x02 | 0x03 | 0x04);

    if !on_known_tls_port && !looks_like_tls {
        return Ok(());
    }

    // ---------------- TLS BUFFER OVERFLOW CHECK ----------------
    if flow.tls_buffer_overflow {
        return Err(SnfParseError::new(
            "TLS",
            "tls_buffer previously overflowed — stream state lost, skipping",
            0,
        ));
    }

    if !flow.check_tls_buffer_cap(payload.len()) {
        return Err(SnfParseError::new(
            "TLS",
            format!(
                "tls_buffer cap exceeded ({}B max) — stream state cleared",
                crate::flow::flow_struct::TLS_BUFFER_MAX_BYTES
            ),
            0,
        ));
    }

    // ---------------- TLS STREAM BUFFER ----------------
    flow.tls_buffer.extend_from_slice(payload);
    let records = extract_tls_records(&mut flow.tls_buffer);

    for record in &records {
        if record.len() < 5 {
            continue;
        }

        let content_type = record[0];

        // Extract TLS version from record header
        if record.len() >= 3 {
            let version_raw = u16::from_be_bytes([record[1], record[2]]);
            let version_string = match version_raw {
                0x0301 => "TLS1.0",
                0x0302 => "TLS1.1",
                0x0303 => "TLS1.2",
                0x0304 => "TLS1.3",
                _ => "UNKNOWN",
            };
            flow.tls_version = Some(version_string.to_string());
        }

        // Only process handshake records (content_type = 22 = 0x16)
        if content_type != 22 {
            continue;
        }

        flow.tls_detected = true;

        if record.len() < 9 {
            continue;
        }

        let handshake_type = record[5];

        if handshake_type == 2 {
            parse_server_hello(flow, record, config);
        }

        // Phase 15B: parse Certificate message for full chain depth
        if handshake_type == 11 {
            parse_tls_certificate(ctx, flow, record, config);
        }
    }

    // ---------------- CLIENT HELLO ----------------
    if payload[0] != 0x16 {
        return Ok(());
    }

    let mut pos: usize = 5;

    if payload.len() < pos + 4 {
        return Ok(());
    }

    let handshake_type = payload[pos];
    pos += 4;

    if handshake_type != 1 {
        return Ok(());
    }

    // ClientHello: version(2) + random(32) = 34 bytes
    if payload.len() < pos + 34 {
        return Err(SnfParseError::new(
            "TLS",
            format!("ClientHello truncated before version+random: offset {}", pos),
            pos,
        ));
    }
    pos += 34;

    // Session ID
    if pos >= payload.len() {
        return Err(SnfParseError::new("TLS", "ClientHello truncated before session_id_len", pos));
    }
    let session_len = payload[pos] as usize;
    pos += 1;
    if pos + session_len > payload.len() {
        return Err(SnfParseError::new(
            "TLS",
            format!("ClientHello session_id out of bounds: len={} offset={}", session_len, pos),
            pos,
        ));
    }
    pos += session_len;

    // Cipher suites
    if pos + 2 > payload.len() {
        return Err(SnfParseError::new("TLS", "ClientHello truncated before cipher_suites_len", pos));
    }
    let cipher_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2;
    if pos + cipher_len > payload.len() {
        return Err(SnfParseError::new(
            "TLS",
            format!("ClientHello cipher_suites out of bounds: len={} offset={}", cipher_len, pos),
            pos,
        ));
    }
    pos += cipher_len;

    // Compression methods
    if pos >= payload.len() {
        return Err(SnfParseError::new("TLS", "ClientHello truncated before comp_methods_len", pos));
    }
    let comp_len = payload[pos] as usize;
    pos += 1;
    if pos + comp_len > payload.len() {
        return Err(SnfParseError::new(
            "TLS",
            format!("ClientHello comp_methods out of bounds: len={} offset={}", comp_len, pos),
            pos,
        ));
    }
    pos += comp_len;

    // Extensions total length
    if pos + 2 > payload.len() {
        return Ok(()); // No extensions — valid for old TLS
    }
    let ext_total_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2;

    let ext_end = pos + ext_total_len;
    if ext_end > payload.len() {
        return Err(SnfParseError::new(
            "TLS",
            format!("ClientHello extensions length out of bounds: declared={} available={}", ext_total_len, payload.len() - pos),
            pos,
        ));
    }

    // ---------------- EXTENSION LOOP ----------------
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let ext_size = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;
        pos += 4;

        if pos + ext_size > ext_end {
            return Err(SnfParseError::new(
                "TLS",
                format!("extension type=0x{:04x} data out of bounds: size={} offset={}", ext_type, ext_size, pos),
                pos,
            ));
        }

        match ext_type {
            // SNI (0x0000)
            0x0000 => {
                if let Err(e) = extract_sni(ctx, payload, pos, ext_end, config) {
                    return Err(e);
                }
            }

            // ALPN (0x0010)
            0x0010 => {
                extract_alpn(ctx, payload, pos, pos + ext_size, config);
            }

            // Session Ticket (0x0023)
            0x0023 => {
                if ext_size > 0 {
                    ctx.tls_session_resumed = true;
                    flow.tls_session_resumed = true;
                }
            }

            // Pre-Shared Key (0x0029) — TLS 1.3 resumption
            0x0029 => {
                ctx.tls_session_resumed = true;
                flow.tls_session_resumed = true;
            }

            // Phase 15B: OCSP status_request (0x0012)
            // Client requesting certificate status stapling via OCSP.
            0x0012 => {
                ctx.tls_ocsp_stapling = true;
                if config.output.show_tls_logs {
                    println!("[TLS] OCSP stapling requested");
                }
            }

            // Phase 15B: Early Data (0x002a) — TLS 1.3 0-RTT
            // Presence in ClientHello indicates the client is sending 0-RTT data.
            // 0-RTT data is not forward-secret — replay attacks are possible.
            0x002a => {
                ctx.tls_early_data = true;
                if config.output.show_tls_logs {
                    println!("[TLS] 0-RTT Early Data extension detected");
                }
            }

            // Phase 15B: ECH draft (0xfe0d) and RFC (0x0039)
            // Encrypted Client Hello conceals the real SNI from passive observers.
            // The outer ClientHello SNI will be the ECH provider domain, not the real target.
            0xfe0d | 0x0039 => {
                ctx.tls_ech_present = true;
                if config.output.show_tls_logs {
                    println!("[TLS] ECH extension detected (type=0x{:04x})", ext_type);
                }
            }

            _ => {}
        }

        pos += ext_size;
    }

    Ok(())
}

// ----------------------------------------------------------------
// SNI EXTRACTOR
// ----------------------------------------------------------------
fn extract_sni(
    ctx: &mut PacketContext,
    payload: &[u8],
    pos: usize,
    ext_end: usize,
    config: &EngineConfig,
) -> ParseResult {
    let mut p = pos;

    if p + 2 > ext_end {
        return Err(SnfParseError::new("TLS", "SNI: truncated before list_len", p));
    }
    let list_len = u16::from_be_bytes([payload[p], payload[p + 1]]) as usize;
    p += 2;

    if p + list_len > ext_end {
        return Err(SnfParseError::new(
            "TLS",
            format!("SNI: list_len={} exceeds extension bounds", list_len),
            p,
        ));
    }

    if p >= ext_end {
        return Err(SnfParseError::new("TLS", "SNI: truncated before name_type", p));
    }
    let name_type = payload[p];
    p += 1;

    if name_type != 0x00 {
        return Ok(()); // Not host_name type
    }

    if p + 2 > ext_end {
        return Err(SnfParseError::new("TLS", "SNI: truncated before name_len", p));
    }
    let name_len = u16::from_be_bytes([payload[p], payload[p + 1]]) as usize;
    p += 2;

    if p + name_len > ext_end {
        return Err(SnfParseError::new(
            "TLS",
            format!("SNI: name_len={} exceeds extension bounds at offset={}", name_len, p),
            p,
        ));
    }

    match std::str::from_utf8(&payload[p..p + name_len]) {
        Ok(sni) if !sni.is_empty() => {
            if config.output.show_packet_logs {
                println!("TLS SNI: {}", sni);
            }
            ctx.tls_sni = Some(sni.to_string());
        }
        Ok(_) => {}
        Err(_) => {
            return Err(SnfParseError::new(
                "TLS",
                format!("SNI name contains non-UTF8 bytes at offset={}", p),
                p,
            ));
        }
    }

    Ok(())
}

// ----------------------------------------------------------------
// ALPN EXTRACTOR
// ----------------------------------------------------------------
fn extract_alpn(
    ctx: &mut PacketContext,
    payload: &[u8],
    start: usize,
    end: usize,
    _config: &EngineConfig,
) {
    let mut pos = start;

    if pos + 2 > end {
        return;
    }
    let list_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2;

    let list_end = pos + list_len;
    if list_end > end || list_end > payload.len() {
        return;
    }

    let mut count = 0usize;

    while pos < list_end && count < MAX_ALPN_PROTOCOLS {
        if pos >= payload.len() {
            break;
        }
        let proto_len = payload[pos] as usize;
        pos += 1;

        if proto_len == 0 || proto_len > MAX_ALPN_PROTO_LEN {
            break;
        }
        if pos + proto_len > list_end || pos + proto_len > payload.len() {
            break;
        }

        match std::str::from_utf8(&payload[pos..pos + proto_len]) {
            Ok(proto) if !proto.is_empty() => {
                ctx.tls_alpn_protocols.push(proto.to_string());
                if ctx.tls_alpn.is_none() {
                    ctx.tls_alpn = Some(proto.to_string());
                }
                count += 1;
            }
            _ => {}
        }

        pos += proto_len;
    }
}

// ----------------------------------------------------------------
// SERVER HELLO PARSER
// ----------------------------------------------------------------
fn parse_server_hello(flow: &mut Flow, record: &[u8], config: &EngineConfig) {
    let mut pos: usize = 9; // past record header + handshake header

    if record.len() < pos + 34 {
        return;
    }
    pos += 34; // version(2) + random(32)

    if pos >= record.len() {
        return;
    }
    let session_len = record[pos] as usize;
    pos += 1;

    if pos + session_len + 2 > record.len() {
        return;
    }
    pos += session_len;

    if pos + 2 > record.len() {
        return;
    }
    let cipher = u16::from_be_bytes([record[pos], record[pos + 1]]);
    flow.tls_cipher_suites = vec![cipher];
    pos += 2;

    if pos >= record.len() {
        return;
    }
    pos += 1; // compression method

    if pos + 2 > record.len() {
        return;
    }
    let ext_total_len = u16::from_be_bytes([record[pos], record[pos + 1]]) as usize;
    pos += 2;

    let ext_end = pos + ext_total_len;
    if ext_end > record.len() {
        return;
    }

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([record[pos], record[pos + 1]]);
        let ext_size = u16::from_be_bytes([record[pos + 2], record[pos + 3]]) as usize;
        pos += 4;

        if pos + ext_size > ext_end {
            break;
        }

        match ext_type {
            // supported_versions — TLS 1.3 true version
            0x002b => {
                if ext_size >= 2 {
                    let ver = u16::from_be_bytes([record[pos], record[pos + 1]]);
                    let ver_str = match ver {
                        0x0304 => "TLS1.3",
                        0x0303 => "TLS1.2",
                        0x0302 => "TLS1.1",
                        0x0301 => "TLS1.0",
                        _ => "UNKNOWN",
                    };
                    flow.tls_version = Some(ver_str.to_string());
                    if config.output.show_packet_logs {
                        println!("TLS ServerHello negotiated version: {}", ver_str);
                    }
                }
            }

            // ALPN (0x0010) — server-selected protocol
            0x0010 => {
                let mut ap = pos;
                if ap + 2 <= ext_end {
                    let list_len = u16::from_be_bytes([record[ap], record[ap + 1]]) as usize;
                    ap += 2;
                    if ap < ext_end && list_len > 0 {
                        let proto_len = record[ap] as usize;
                        ap += 1;
                        if ap + proto_len <= ext_end && proto_len > 0 && proto_len <= MAX_ALPN_PROTO_LEN {
                            if let Ok(proto) = std::str::from_utf8(&record[ap..ap + proto_len]) {
                                flow.alpn = Some(proto.to_string());
                            }
                        }
                    }
                }
            }

            _ => {}
        }

        pos += ext_size;
    }
}

// ----------------------------------------------------------------
// TLS RECORD EXTRACTOR
// ----------------------------------------------------------------
const TLS_MAX_RECORD_BODY: usize = 20_480;

fn extract_tls_records(buffer: &mut Vec<u8>) -> Vec<Vec<u8>> {
    let mut records = Vec::new();

    loop {
        if buffer.len() < 5 {
            break;
        }

        let length = u16::from_be_bytes([buffer[3], buffer[4]]) as usize;

        if length > TLS_MAX_RECORD_BODY {
            buffer.clear();
            break;
        }

        let record_len = 5 + length;

        if buffer.len() < record_len {
            break;
        }

        let record = buffer.drain(..record_len).collect::<Vec<u8>>();
        records.push(record);
    }

    records
}

// ----------------------------------------------------------------
// TLS CERTIFICATE PARSER
// ----------------------------------------------------------------
// Phase 15B: parses multiple certs in the chain, records chain depth.
// Leaf cert fields stored on ctx; chain depth in ctx.tls_cert_chain_len.
fn parse_tls_certificate(
    ctx: &mut PacketContext,
    _flow: &mut Flow,
    record: &[u8],
    config: &EngineConfig,
) {
    let mut pos: usize = 5;

    if record.len() < pos + 4 {
        return;
    }

    let handshake_type = record[pos];
    pos += 4;

    if handshake_type != 11 {
        return;
    }

    // Certificate list length (3 bytes big-endian)
    if record.len() < pos + 3 {
        return;
    }
    let cert_list_len = ((record[pos] as usize) << 16)
        | ((record[pos + 1] as usize) << 8)
        | (record[pos + 2] as usize);
    pos += 3;

    if pos + cert_list_len > record.len() {
        return;
    }

    let list_end = pos + cert_list_len;
    let mut cert_index = 0usize;

    // Phase 15B: iterate the full certificate chain, counting depth.
    while pos + 3 <= list_end && cert_index < MAX_CERT_CHAIN_DEPTH {
        // Each certificate is length-prefixed (3 bytes big-endian)
        let cert_len = ((record[pos] as usize) << 16)
            | ((record[pos + 1] as usize) << 8)
            | (record[pos + 2] as usize);
        pos += 3;

        if cert_len == 0 || pos + cert_len > list_end {
            break;
        }

        let cert_bytes = &record[pos..pos + cert_len];
        pos += cert_len;
        cert_index += 1;

        // Only extract detailed fields from the leaf (first) cert.
        // Intermediate and root certs are counted but not fully parsed.
        if cert_index == 1 {
            if let Ok((_, cert)) = parse_x509_certificate(cert_bytes) {
                // Risk scoring
                // Certificate risk scoring available in the commercial edition

                // Subject CN
                for attr in cert.subject().iter_common_name() {
                    if let Ok(cn) = attr.as_str() {
                        let sanitized = sanitize_cert_string(cn);
                        if !sanitized.is_empty() {
                            ctx.tls_cert_cn = Some(sanitized);
                        }
                    }
                }

                // Issuer CN
                for attr in cert.issuer().iter_common_name() {
                    if let Ok(cn) = attr.as_str() {
                        let sanitized = sanitize_cert_string(cn);
                        if !sanitized.is_empty() {
                            ctx.tls_cert_issuer = Some(sanitized);
                            break;
                        }
                    }
                }

                // Self-signed check: Subject DN == Issuer DN
                ctx.tls_cert_self_signed =
                    cert.subject().as_raw() == cert.issuer().as_raw();

                // Expiry check (uses pcap timestamp — deterministic)
                let not_after = cert.validity().not_after;
                ctx.tls_cert_not_after = Some(format!("{}", not_after));
                let packet_time_sec = ctx.timestamp_us / 1_000_000;
                let not_after_dt = not_after.to_datetime();
                ctx.tls_cert_expired = (not_after_dt.unix_timestamp() as u64) < packet_time_sec;

                // Subject Alternative Names (DNS SANs)
                if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
                    for name in san_ext.value.general_names.iter() {
                        if let x509_parser::extensions::GeneralName::DNSName(dns) = name {
                            let sanitized = sanitize_cert_string(dns);
                            if !sanitized.is_empty() {
                                ctx.tls_cert_sans.push(sanitized);
                            }
                        }
                    }
                }

                if let Some(ref cn) = ctx.tls_cert_cn {
                    if config.output.show_tls_logs {
                        println!(
                            "[TLS] CERT CN={} issuer={} self_signed={} expired={} chain_depth={}",
                            cn,
                            ctx.tls_cert_issuer.as_deref().unwrap_or("?"),
                            ctx.tls_cert_self_signed,
                            ctx.tls_cert_expired,
                            cert_index,
                        );
                    }
                }
            }
        }
    }

    // Phase 15B: record total chain depth observed
    ctx.tls_cert_chain_len = cert_index as u8;
}

// ----------------------------------------------------------------
// CERT STRING SANITIZER
// ----------------------------------------------------------------
// Strips control characters and replaces non-ASCII bytes with '?'.
fn sanitize_cert_string(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .map(|c| if c.is_ascii() { c } else { '?' })
        .take(256)
        .collect()
}
