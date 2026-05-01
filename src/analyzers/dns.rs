// src/analyzers/dns.rs
//
// DNS protocol analyzer.
//
// Phase 15A additions:
//   - TC (Truncation) bit detection: ctx.dns_truncated set true if TC bit set in flags.
//     A truncated DNS response means the client will retry over TCP.
//   - DNSSEC record types: RRSIG(46), DNSKEY(48), DS(43), NSEC(47), NSEC3(50)
//     Detected and stored in ctx.dns_dnssec_present = true.
//     RRSIG type-covered field extracted into ctx.dns_rrsig_type_covered.
//   - DoQ port detection: UDP port 853 treated as DNS-over-QUIC.
//     ctx.dns_transport set to "DoQ" when src/dst port = 853 over UDP.
//     Regular DNS over UDP 53 = "DNS", TCP 53 = "DNS-TCP".
//
// Phase 3A (preserved): MX/NS/PTR/TXT/SRV, TTL, CNAME chain, dns_record_type, dns_is_response.
// Phase 2 (preserved): ParseResult, bounds-safe, MAX_ANSWER_RECORDS cap.

use crate::config::engine_config::EngineConfig;
use crate::discovery::dns_cache::DnsCache;
use crate::core::packet_context::PacketContext;
use crate::core::parse_error::{ParseResult, SnfParseError};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Maximum number of answer records to process per response.
const MAX_ANSWER_RECORDS: u16 = 64;

/// Maximum length of a TXT record string value.
const MAX_TXT_VALUE_LEN: usize = 512;

/// Maximum number of TXT strings to store per packet.
const MAX_TXT_RECORDS: usize = 16;

/// Maximum number of MX/NS/SRV records to store per packet.
const MAX_MULTI_RECORDS: usize = 16;

/// DNS-over-QUIC port (RFC 9250).
const DOQ_PORT: u16 = 853;

/// DNS flags mask for TC (Truncation) bit — bit 9 of the flags word.
const DNS_FLAG_TC: u16 = 0x0200;

/// DNS flags mask for QR (Query/Response) bit — bit 15.
const DNS_FLAG_QR: u16 = 0x8000;

pub fn analyze(
    ctx: &mut PacketContext,
    payload: &[u8],
    dns_cache: &mut DnsCache,
    config: &EngineConfig,
) -> ParseResult {
    // Reset all DNS fields on entry — ensures no stale data from previous packets.
    ctx.dns_query_name = None;
    ctx.dns_resolved_ip = None;
    ctx.dns_domain = None;
    ctx.dns_record_type = None;
    ctx.dns_ttl = None;
    ctx.dns_cname_chain.clear();
    ctx.dns_mx_records.clear();
    ctx.dns_txt_records.clear();
    ctx.dns_ns_records.clear();
    ctx.dns_ptr_record = None;
    ctx.dns_srv_records.clear();
    ctx.dns_is_response = false;
    // Phase 15A fields
    ctx.dns_truncated = false;
    ctx.dns_dnssec_present = false;
    ctx.dns_rrsig_type_covered = None;
    ctx.dns_transport = None;

    // ---------------- PORT CHECK ----------------
    // Phase 15A: detect DNS-over-QUIC (DoQ) on port 853/UDP.
    let on_dns_port = ctx.src_port == config.protocol.dns_port
        || ctx.dst_port == config.protocol.dns_port;
    let on_doq_port = ctx.protocol == "UDP"
        && (ctx.src_port == DOQ_PORT || ctx.dst_port == DOQ_PORT);

    if !on_dns_port && !on_doq_port {
        return Ok(());
    }

    // Set transport label for event emission
    ctx.dns_transport = Some(if on_doq_port {
        "DoQ".to_string()
    } else if ctx.protocol == "TCP" {
        "DNS-TCP".to_string()
    } else {
        "DNS".to_string()
    });

    // ---------------- BASIC SIZE CHECK ----------------
    if payload.len() < 12 {
        return Err(SnfParseError::new(
            "DNS",
            format!("packet too short for DNS header: {} bytes", payload.len()),
            0,
        ));
    }

    // ---------------- TCP DNS LENGTH PREFIX ----------------
    // DNS over TCP prepends a 2-byte message length before the DNS payload.
    let payload: &[u8] = if ctx.protocol == "TCP" && payload.len() >= 14 {
        let declared_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
        if declared_len == payload.len() - 2 {
            &payload[2..]
        } else {
            payload
        }
    } else {
        payload
    };

    if payload.len() < 12 {
        return Err(SnfParseError::new(
            "DNS",
            "packet too short after TCP length prefix strip",
            0,
        ));
    }

    // ---------------- DNS FLAGS ----------------
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let is_response = (flags & DNS_FLAG_QR) != 0;
    ctx.dns_is_response = is_response;

    // Phase 15A: TC (Truncation) bit — response was truncated, client should retry TCP.
    ctx.dns_truncated = (flags & DNS_FLAG_TC) != 0;

    if config.output.show_dns_logs {
        println!(
            "DNS packet ({} bytes) is_response={} truncated={}",
            payload.len(), is_response, ctx.dns_truncated
        );
    }

    // ---------------- DNS HEADER ----------------
    let answer_count = u16::from_be_bytes([payload[6], payload[7]]);

    // ---------------- PARSE QUERY DOMAIN ----------------
    let mut pos = config.protocol.dns_header_length;
    let query_domain = match parse_dns_name(payload, &mut pos) {
        Some(d) => d,
        None => {
            return Err(SnfParseError::new(
                "DNS",
                format!("failed to parse query domain at offset {}", pos),
                pos,
            ));
        }
    };

    if !query_domain.is_empty() {
        ctx.dns_domain = Some(query_domain.clone());
    }

    // Skip QTYPE + QCLASS (4 bytes)
    if pos + 4 > payload.len() {
        return Err(SnfParseError::new(
            "DNS",
            format!("truncated before QTYPE/QCLASS: offset {} len {}", pos, payload.len()),
            pos,
        ));
    }
    pos += 4;

    // ---------------- PARSE ANSWERS (responses only) ----------------
    if !is_response || answer_count == 0 {
        return Ok(());
    }

    let records_to_parse = answer_count.min(MAX_ANSWER_RECORDS);

    let mut first_answer = true;

    for i in 0..records_to_parse {
        if pos + 2 > payload.len() {
            return Err(SnfParseError::new(
                "DNS",
                format!("answer {}: truncated before NAME field", i),
                pos,
            ));
        }

        let answer_name = parse_dns_name(payload, &mut pos).unwrap_or_default();

        // Need: type(2) + class(2) + ttl(4) + rdlength(2) = 10 bytes
        if pos + 10 > payload.len() {
            return Err(SnfParseError::new(
                "DNS",
                format!("answer {}: truncated before type/class/ttl/rdlen at offset {}", i, pos),
                pos,
            ));
        }

        let record_type = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        pos += 2; // type
        pos += 2; // class (skip)

        // TTL: 4 bytes big-endian
        let ttl = u32::from_be_bytes([
            payload[pos],
            payload[pos + 1],
            payload[pos + 2],
            payload[pos + 3],
        ]);
        pos += 4;

        if first_answer {
            ctx.dns_ttl = Some(ttl);
        }

        let rdlength = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
        pos += 2;

        if pos + rdlength > payload.len() {
            return Err(SnfParseError::new(
                "DNS",
                format!(
                    "answer {}: rdata out of bounds (offset={} rdlength={} payload_len={})",
                    i, pos, rdlength, payload.len()
                ),
                pos,
            ));
        }

        let resolved_name = if !answer_name.is_empty() {
            answer_name.clone()
        } else {
            query_domain.clone()
        };

        // Set dns_record_type from first answer
        if first_answer {
            ctx.dns_record_type = Some(record_type_to_str(record_type).to_string());
            first_answer = false;
        }

        match record_type {
            // ---------------- A RECORD (type 1) ----------------
            1 => {
                if rdlength == 4 {
                    let ip = Ipv4Addr::new(
                        payload[pos],
                        payload[pos + 1],
                        payload[pos + 2],
                        payload[pos + 3],
                    );
                    let resolved_ip = IpAddr::V4(ip);
                    if !resolved_name.is_empty() {
                        if config.output.show_dns_logs {
                            println!("DNS A: {} -> {}", resolved_name, resolved_ip);
                        }
                        dns_cache.insert(resolved_ip, resolved_name.clone());
                        ctx.dns_query_name = Some(resolved_name.clone());
                        ctx.dns_resolved_ip = Some(resolved_ip);
                    }
                } else {
                    return Err(SnfParseError::new(
                        "DNS",
                        format!("answer {}: A record rdlength={} (expected 4)", i, rdlength),
                        pos,
                    ));
                }
            }

            // ---------------- AAAA RECORD (type 28) ----------------
            28 => {
                if rdlength == 16 {
                    let mut bytes = [0u8; 16];
                    bytes.copy_from_slice(&payload[pos..pos + 16]);
                    let ip = Ipv6Addr::from(bytes);
                    let resolved_ip = IpAddr::V6(ip);
                    if !resolved_name.is_empty() {
                        if config.output.show_dns_logs {
                            println!("DNS AAAA: {} -> {}", resolved_name, resolved_ip);
                        }
                        dns_cache.insert(resolved_ip, resolved_name.clone());
                        if ctx.dns_resolved_ip.is_none() {
                            ctx.dns_query_name = Some(resolved_name.clone());
                            ctx.dns_resolved_ip = Some(resolved_ip);
                        }
                    }
                } else {
                    return Err(SnfParseError::new(
                        "DNS",
                        format!("answer {}: AAAA record rdlength={} (expected 16)", i, rdlength),
                        pos,
                    ));
                }
            }

            // ---------------- CNAME RECORD (type 5) ----------------
            5 => {
                let mut cname_pos = pos;
                if let Some(cname_target) = parse_dns_name(payload, &mut cname_pos)
                    && ctx.dns_cname_chain.len() < MAX_MULTI_RECORDS {
                        ctx.dns_cname_chain.push(cname_target);
                    }
            }

            // ---------------- MX RECORD (type 15) ----------------
            15 => {
                if rdlength < 3 {
                    return Err(SnfParseError::new(
                        "DNS",
                        format!("answer {}: MX record rdlength={} too short", i, rdlength),
                        pos,
                    ));
                }
                let mut mx_pos = pos + 2; // skip preference (2 bytes)
                if let Some(mx_exchange) = parse_dns_name(payload, &mut mx_pos)
                    && ctx.dns_mx_records.len() < MAX_MULTI_RECORDS {
                        ctx.dns_mx_records.push(mx_exchange);
                    }
            }

            // ---------------- NS RECORD (type 2) ----------------
            2 => {
                let mut ns_pos = pos;
                if let Some(ns_name) = parse_dns_name(payload, &mut ns_pos)
                    && ctx.dns_ns_records.len() < MAX_MULTI_RECORDS {
                        ctx.dns_ns_records.push(ns_name);
                    }
            }

            // ---------------- PTR RECORD (type 12) ----------------
            12 => {
                let mut ptr_pos = pos;
                if let Some(ptr_target) = parse_dns_name(payload, &mut ptr_pos)
                    && ctx.dns_ptr_record.is_none() {
                        ctx.dns_ptr_record = Some(ptr_target);
                    }
            }

            // ---------------- TXT RECORD (type 16) ----------------
            16 => {
                if ctx.dns_txt_records.len() < MAX_TXT_RECORDS
                    && let Some(txt_value) = parse_txt_rdata(payload, pos, pos + rdlength) {
                        ctx.dns_txt_records.push(txt_value);
                    }
            }

            // ---------------- SOA RECORD (type 6) — skip ----------------
            6 => {}

            // ---------------- SRV RECORD (type 33) ----------------
            33 => {
                if rdlength < 7 {
                    return Err(SnfParseError::new(
                        "DNS",
                        format!("answer {}: SRV record rdlength={} too short", i, rdlength),
                        pos,
                    ));
                }
                if pos + 6 > payload.len() {
                    return Err(SnfParseError::new(
                        "DNS",
                        format!("answer {}: SRV rdata out of bounds at offset {}", i, pos),
                        pos,
                    ));
                }
                let priority = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
                let weight   = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]);
                let port     = u16::from_be_bytes([payload[pos + 4], payload[pos + 5]]);
                let mut srv_pos = pos + 6;
                if let Some(target) = parse_dns_name(payload, &mut srv_pos) {
                    let srv_str = format!("{} {} {} {}", priority, weight, port, target);
                    if ctx.dns_srv_records.len() < MAX_MULTI_RECORDS {
                        ctx.dns_srv_records.push(srv_str);
                    }
                }
            }

            // ---------------- Phase 15A: DNSSEC record types ----------------

            // DS (43): Delegation Signer — indicates signed zone delegation.
            43 => {
                ctx.dns_dnssec_present = true;
                if config.output.show_dns_logs {
                    println!("DNS DNSSEC: DS record for {}", resolved_name);
                }
            }

            // RRSIG (46): Resource Record Signature.
            // RDATA layout: type_covered(2) + algorithm(1) + labels(1) + orig_ttl(4) +
            //   sig_expiration(4) + sig_inception(4) + key_tag(2) + signer_name + signature
            46 => {
                ctx.dns_dnssec_present = true;
                // Extract type_covered field — first 2 bytes of RDATA
                if rdlength >= 2 {
                    let type_covered = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
                    // Only store the first RRSIG's type_covered
                    if ctx.dns_rrsig_type_covered.is_none() {
                        ctx.dns_rrsig_type_covered = Some(
                            record_type_to_str(type_covered).to_string()
                        );
                    }
                }
                if config.output.show_dns_logs {
                    println!("DNS DNSSEC: RRSIG for {}", resolved_name);
                }
            }

            // NSEC (47): Next Secure — used to prove non-existence of records.
            47 => {
                ctx.dns_dnssec_present = true;
                if config.output.show_dns_logs {
                    println!("DNS DNSSEC: NSEC for {}", resolved_name);
                }
            }

            // DNSKEY (48): Public key used to verify RRSIG signatures.
            48 => {
                ctx.dns_dnssec_present = true;
                if config.output.show_dns_logs {
                    println!("DNS DNSSEC: DNSKEY for {}", resolved_name);
                }
            }

            // NSEC3 (50): Hashed Next Secure — DNSSEC denial of existence with hashing.
            50 => {
                ctx.dns_dnssec_present = true;
                if config.output.show_dns_logs {
                    println!("DNS DNSSEC: NSEC3 for {}", resolved_name);
                }
            }

            _ => {} // Unknown/unsupported record type — skip rdata
        }

        // Advance past rdata — covers all record types.
        pos += rdlength;
    }

    Ok(())
}

// ----------------------------------------------------------------
// DNS NAME PARSER
// ----------------------------------------------------------------
// Handles inline labels and pointer compression (0xC0xx).
// Updates pos to point past the consumed name field.
// Returns None on: out-of-bounds, pointer loop (> 10 jumps), forward pointer.
fn parse_dns_name(payload: &[u8], pos: &mut usize) -> Option<String> {
    let mut name = String::new();
    let mut jumps: usize = 0;
    const MAX_JUMPS: usize = 10;
    let mut current = *pos;
    let mut jumped = false;

    loop {
        if current >= payload.len() {
            return None;
        }

        let byte = payload[current];

        if byte & 0xC0 == 0xC0 {
            // Pointer compression — jump to referenced offset
            if current + 1 >= payload.len() {
                return None;
            }
            if !jumped {
                *pos = current + 2;
                jumped = true;
            }
            let offset = (((byte & 0x3F) as usize) << 8) | (payload[current + 1] as usize);
            if offset >= current {
                return None; // Forward/self pointer — reject
            }
            current = offset;
            jumps += 1;
            if jumps > MAX_JUMPS {
                return None;
            }
        } else if byte == 0x00 {
            // End of name
            if !jumped {
                *pos = current + 1;
            }
            break;
        } else {
            let label_len = byte as usize;
            current += 1;
            if current + label_len > payload.len() {
                return None;
            }
            if !name.is_empty() {
                name.push('.');
            }
            // Lossy UTF-8 — invalid bytes replaced with U+FFFD
            let label = String::from_utf8_lossy(&payload[current..current + label_len]);
            name.push_str(&label);
            current += label_len;
            if !jumped {
                *pos = current;
            }
        }
    }

    Some(name)
}

// ----------------------------------------------------------------
// TXT RDATA PARSER
// ----------------------------------------------------------------
fn parse_txt_rdata(payload: &[u8], start: usize, end: usize) -> Option<String> {
    let mut pos = start;
    let mut parts: Vec<String> = Vec::new();

    while pos < end {
        if pos >= payload.len() {
            return None;
        }
        let str_len = payload[pos] as usize;
        pos += 1;
        if pos + str_len > end || pos + str_len > payload.len() {
            return None;
        }
        let raw = &payload[pos..pos + str_len];
        pos += str_len;
        let capped_len = raw.len().min(MAX_TXT_VALUE_LEN);
        let txt_str = String::from_utf8_lossy(&raw[..capped_len]).into_owned();
        parts.push(txt_str);
    }

    if parts.is_empty() { None } else { Some(parts.join(" ")) }
}

// ----------------------------------------------------------------
// RECORD TYPE NAME HELPER
// ----------------------------------------------------------------
// Returns canonical string name for a DNS record type.
// Unknown types formatted as "TYPE{n}" per RFC 3597.
fn record_type_to_str(rtype: u16) -> &'static str {
    match rtype {
        1  => "A",
        2  => "NS",
        5  => "CNAME",
        6  => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        43 => "DS",
        46 => "RRSIG",
        47 => "NSEC",
        48 => "DNSKEY",
        50 => "NSEC3",
        _  => "UNKNOWN",
    }
}