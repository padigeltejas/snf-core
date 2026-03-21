// src/analyzers/mdns.rs
//
// mDNS (Multicast DNS) protocol analyzer — RFC 6762.
//
// Phase 15H additions:
//   - Service type extraction: PTR records with names matching
//     _<service>._<proto>.local pattern extract the service type
//     (e.g. "_http._tcp", "_airplay._tcp") into ctx.mdns_service_type.
//   - PTR binding: PTR record rdata (the target name) is stored in
//     ctx.mdns_ptr_target. For service PTRs this is the instance name
//     (e.g. "My Printer._ipp._tcp.local").
//   - Instance name extraction: the first label of the PTR rdata before
//     the service type is extracted as ctx.mdns_instance_name.
//   - All service TXT records: SRV target hostname stored in
//     ctx.mdns_srv_target and port in ctx.mdns_srv_port.
//
// Phase 2 (preserved): all bounds checks, MAX_ANSWER_RECORDS cap.

use crate::core::packet_context::PacketContext;
use crate::config::engine_config::EngineConfig;
use crate::core::parse_error::{ParseResult, SnfParseError};

/// mDNS UDP port per RFC 6762.
const MDNS_PORT: u16 = 5353;

/// Minimum mDNS message size: same as DNS header = 12 bytes.
const MDNS_MIN_LEN: usize = 12;

/// Maximum answer records to process per response.
const MAX_ANSWER_RECORDS: u16 = 32;

/// Maximum length for extracted name fields.
const MAX_NAME_LEN: usize = 253;

pub fn analyze(
    ctx: &mut PacketContext,
    payload: &[u8],
    config: &EngineConfig,
) -> ParseResult {
    if ctx.protocol != "UDP" {
        return Ok(());
    }

    let on_mdns_port = ctx.src_port == MDNS_PORT || ctx.dst_port == MDNS_PORT;
    if !on_mdns_port {
        return Ok(());
    }

    // Reset mDNS fields on entry
    ctx.mdns_query_name   = None;
    ctx.mdns_record_type  = None;
    ctx.mdns_is_response  = false;
    ctx.mdns_service_type = None;
    ctx.mdns_ptr_target   = None;
    ctx.mdns_instance_name = None;
    ctx.mdns_srv_target   = None;
    ctx.mdns_srv_port     = None;

    if payload.len() < MDNS_MIN_LEN {
        return Err(SnfParseError::new(
            "mDNS",
            format!("packet too short: {} bytes (minimum {})", payload.len(), MDNS_MIN_LEN),
            0,
        ));
    }

    // ---------------- mDNS HEADER ----------------
    let flags      = u16::from_be_bytes([payload[2], payload[3]]);
    let qdcount    = u16::from_be_bytes([payload[4], payload[5]]);
    let ancount    = u16::from_be_bytes([payload[6], payload[7]]);
    let is_response = (flags & 0x8000) != 0;

    ctx.mdns_is_response = is_response;

    let mut pos = 12usize;

    // ---------------- QUESTION SECTION ----------------
    if qdcount > 0 {
        match parse_mdns_name(payload, &mut pos) {
            Some(name) if !name.is_empty() => {
                if config.output.show_packet_logs {
                    println!("mDNS query name: {} is_response={}", name, is_response);
                }
                ctx.mdns_query_name = Some(name);
            }
            Some(_) => {}
            None => {
                return Err(SnfParseError::new(
                    "mDNS",
                    format!("failed to parse question name at offset {}", pos),
                    pos,
                ));
            }
        }

        // Skip QTYPE(2) + QCLASS(2)
        if pos + 4 > payload.len() {
            return Ok(());
        }
        pos += 4;

        // Skip remaining questions
        for _ in 1..qdcount {
            if parse_mdns_name(payload, &mut pos).is_none() {
                break;
            }
            if pos + 4 > payload.len() {
                break;
            }
            pos += 4;
        }
    }

    // ---------------- ANSWER SECTION ----------------
    if !is_response || ancount == 0 {
        return Ok(());
    }

    let records_to_parse = ancount.min(MAX_ANSWER_RECORDS);

    for i in 0..records_to_parse {
        if pos + 2 > payload.len() {
            break;
        }

        // Parse answer owner name
        let answer_name = match parse_mdns_name(payload, &mut pos) {
            Some(n) => n,
            None    => break,
        };

        // Need type(2)+class(2)+ttl(4)+rdlength(2) = 10 bytes
        if pos + 10 > payload.len() {
            break;
        }

        let record_type = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        pos += 2; // type
        pos += 2; // class
        pos += 4; // ttl

        let rdlength = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
        pos += 2;

        if pos + rdlength > payload.len() {
            return Err(SnfParseError::new(
                "mDNS",
                format!(
                    "answer {}: rdata OOB (offset={} rdlength={} payload={})",
                    i, pos, rdlength, payload.len()
                ),
                pos,
            ));
        }

        let rdata_end = pos + rdlength;

        // Set record type from first answer
        if i == 0 {
            let type_str = mdns_record_type_str(record_type);
            if config.output.show_packet_logs {
                println!("mDNS answer[0] type={} name={}", type_str, answer_name);
            }
            ctx.mdns_record_type = Some(type_str.to_string());
        }

        match record_type {
            // PTR (12): service instance pointer
            // answer_name = "_http._tcp.local" → service type
            // rdata = instance name like "My Mac._http._tcp.local"
            12 => {
                let mut rdata_pos = pos;
                if let Some(ptr_target) = parse_mdns_name(payload, &mut rdata_pos) {
                    if !ptr_target.is_empty() && ptr_target.len() <= MAX_NAME_LEN {
                        // Phase 15H: extract service type from answer name
                        // Pattern: _<service>._<proto>.local
                        if let Some(svc_type) = extract_service_type(&answer_name) {
                            ctx.mdns_service_type = Some(svc_type);
                        }

                        // Store PTR target (the instance name)
                        ctx.mdns_ptr_target = Some(ptr_target.clone());

                        // Extract instance name: first label of the PTR rdata
                        if let Some(instance) = extract_instance_name(&ptr_target) {
                            ctx.mdns_instance_name = Some(instance);
                        }

                        if config.output.show_packet_logs {
                            println!(
                                "[mDNS] PTR: {} → {} (service={})",
                                answer_name,
                                ptr_target,
                                ctx.mdns_service_type.as_deref().unwrap_or("?"),
                            );
                        }
                    }
                }
            }

            // SRV (33): service location — port + target hostname
            33 => {
                // SRV rdata: priority(2)+weight(2)+port(2)+target(name)
                if pos + 6 <= payload.len() {
                    let srv_port = u16::from_be_bytes([payload[pos + 4], payload[pos + 5]]);
                    ctx.mdns_srv_port = Some(srv_port);

                    let mut srv_pos = pos + 6;
                    if let Some(srv_target) = parse_mdns_name(payload, &mut srv_pos) {
                        if !srv_target.is_empty() && srv_target.len() <= MAX_NAME_LEN {
                            if config.output.show_packet_logs {
                                println!("[mDNS] SRV: port={} target={}", srv_port, srv_target);
                            }
                            ctx.mdns_srv_target = Some(srv_target);
                        }
                    }

                    // Also extract service type from SRV owner name if not already set
                    if ctx.mdns_service_type.is_none() {
                        if let Some(svc_type) = extract_service_type(&answer_name) {
                            ctx.mdns_service_type = Some(svc_type);
                        }
                    }
                }
            }

            _ => {}
        }

        pos = rdata_end;
    }

    Ok(())
}

// ----------------------------------------------------------------
// Phase 15H: SERVICE TYPE EXTRACTOR
// ----------------------------------------------------------------
// Extracts "_service._proto" from mDNS names like:
//   "_http._tcp.local"   → "_http._tcp"
//   "_airplay._tcp.local" → "_airplay._tcp"
// Returns None if pattern doesn't match.
fn extract_service_type(name: &str) -> Option<String> {
    let labels: Vec<&str> = name.splitn(4, '.').collect();
    if labels.len() >= 2 {
        let svc   = labels[0];
        let proto = labels[1];
        // Both must start with underscore per DNS-SD RFC 6763
        if svc.starts_with('_') && proto.starts_with('_') {
            return Some(format!("{}.{}", svc, proto));
        }
    }
    None
}

// ----------------------------------------------------------------
// Phase 15H: INSTANCE NAME EXTRACTOR
// ----------------------------------------------------------------
// Extracts the first label (instance name) from a DNS-SD PTR target.
// "My Mac._http._tcp.local" → "My Mac"
fn extract_instance_name(ptr_target: &str) -> Option<String> {
    // Instance name is everything before the first '.' that precedes "_<svc>"
    // Simple approach: find the first segment ending before a '_' label.
    let parts: Vec<&str> = ptr_target.splitn(2, "._").collect();
    if parts.len() == 2 && !parts[0].is_empty() {
        Some(parts[0].to_string())
    } else {
        None
    }
}

// ----------------------------------------------------------------
// mDNS NAME PARSER — same algorithm as dns.rs
// ----------------------------------------------------------------
fn parse_mdns_name(payload: &[u8], pos: &mut usize) -> Option<String> {
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
            // Pointer compression
            if current + 1 >= payload.len() {
                return None;
            }
            if !jumped {
                *pos = current + 2;
                jumped = true;
            }
            let offset = (((byte & 0x3F) as usize) << 8) | (payload[current + 1] as usize);
            if offset >= current {
                return None; // Forward pointer — malformed
            }
            current = offset;
            jumps += 1;
            if jumps > MAX_JUMPS {
                return None;
            }
        } else if byte == 0x00 {
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
// mDNS RECORD TYPE STRING
// ----------------------------------------------------------------
fn mdns_record_type_str(rtype: u16) -> &'static str {
    match rtype {
        1   => "A",
        2   => "NS",
        5   => "CNAME",
        12  => "PTR",
        15  => "MX",
        16  => "TXT",
        28  => "AAAA",
        33  => "SRV",
        47  => "NSEC",
        255 => "ANY",
        _   => "UNKNOWN",
    }
}