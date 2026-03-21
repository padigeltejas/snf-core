// src/analyzers/icmp.rs
//
// ICMP protocol analyzer (ICMPv4 and ICMPv6).
//
// Phase 15G additions:
//   - ICMP tunneling detection: payload-carrying ICMP echo packets
//     (type 8/0 for v4, 128/129 for v6) with payload > threshold set
//     ctx.icmp_tunnel_suspected = true. Tunnel heuristic: echo payloads
//     beyond the standard 32/56-byte ping size carry data.
//   - ICMPv6 Neighbor Discovery (ND) extraction:
//     - NS (type 135): target address extracted into ctx.icmp_nd_target
//     - NA (type 136): target address + flags (Router/Solicited/Override)
//       stored in ctx.icmp_nd_target and ctx.icmp_nd_flags
//     - RS (type 133) / RA (type 134): flagged via ctx.icmp_nd_type
//     - Redirect (type 137): target + dest extracted
//
// Phase 2 (preserved): all bounds checks, type/code tables, minimum length check.

use crate::core::packet_context::PacketContext;
use crate::config::engine_config::EngineConfig;
use crate::core::parse_error::{ParseResult, SnfParseError};

/// Minimum ICMP message size: type(1) + code(1) + checksum(2) = 4 bytes.
const ICMP_MIN_LEN: usize = 4;

/// Typical ping payload sizes (Windows=32, Linux=56, macOS=56).
/// Echo payloads above this threshold suggest tunneling or covert channel.
const ICMP_TUNNEL_PAYLOAD_THRESHOLD: usize = 128;

/// ICMPv6 ND message minimum: type(1)+code(1)+checksum(2)+reserved(4)+target_addr(16) = 24 bytes.
const ICMPV6_ND_MIN_LEN: usize = 24;

/// ICMPv6 echo header size: type(1)+code(1)+checksum(2)+id(2)+seq(2) = 8 bytes.
const ICMPV6_ECHO_HDR_LEN: usize = 8;

/// ICMPv4 echo header size: type(1)+code(1)+checksum(2)+id(2)+seq(2) = 8 bytes.
const ICMPV4_ECHO_HDR_LEN: usize = 8;

pub fn analyze(
    ctx: &mut PacketContext,
    payload: &[u8],
    config: &EngineConfig,
) -> ParseResult {
    let is_icmp   = ctx.protocol == "ICMP";
    let is_icmpv6 = ctx.protocol == "ICMPv6";

    if !is_icmp && !is_icmpv6 {
        return Ok(());
    }

    // Reset ICMP fields on entry
    ctx.icmp_type = None;
    ctx.icmp_code = None;
    ctx.icmp_description = None;
    ctx.icmp_tunnel_suspected = false;
    ctx.icmp_nd_type = None;
    ctx.icmp_nd_target = None;
    ctx.icmp_nd_flags = None;

    if payload.len() < ICMP_MIN_LEN {
        return Err(SnfParseError::new(
            "ICMP",
            format!("packet too short: {} bytes (minimum {})", payload.len(), ICMP_MIN_LEN),
            0,
        ));
    }

    let icmp_type = payload[0];
    let icmp_code = payload[1];

    ctx.icmp_type = Some(icmp_type);
    ctx.icmp_code = Some(icmp_code);

    let description = if is_icmp {
        icmpv4_description(icmp_type, icmp_code)
    } else {
        icmpv6_description(icmp_type, icmp_code)
    };

    ctx.icmp_description = Some(description.to_string());

    if config.output.show_packet_logs {
        println!(
            "{} type={} code={} ({})",
            ctx.protocol, icmp_type, icmp_code, description
        );
    }

    // ---------------- Phase 15G: ICMP TUNNEL DETECTION ----------------
    if is_icmp {
        detect_icmpv4_tunnel(ctx, payload, icmp_type, config);
    } else {
        // Phase 15G: ICMPv6 ND extraction + tunnel detection
        detect_icmpv6_features(ctx, payload, icmp_type, config);
    }

    Ok(())
}

// ----------------------------------------------------------------
// Phase 15G: ICMPv4 TUNNEL DETECTION
// ----------------------------------------------------------------
// Echo request (type 8) and echo reply (type 0) with large payloads
// are classic ICMP tunneling indicators (iodine, Hans, ptunnel).
fn detect_icmpv4_tunnel(
    ctx: &mut PacketContext,
    payload: &[u8],
    icmp_type: u8,
    config: &EngineConfig,
) {
    if icmp_type != 0 && icmp_type != 8 {
        return; // Only check echo request/reply
    }

    if payload.len() <= ICMPV4_ECHO_HDR_LEN {
        return;
    }

    let data_len = payload.len() - ICMPV4_ECHO_HDR_LEN;

    if data_len > ICMP_TUNNEL_PAYLOAD_THRESHOLD {
        ctx.icmp_tunnel_suspected = true;
        if config.output.show_packet_logs {
            println!(
                "[ICMP] Tunnel suspected: echo payload {} bytes (threshold {})",
                data_len, ICMP_TUNNEL_PAYLOAD_THRESHOLD
            );
        }
    }
}

// ----------------------------------------------------------------
// Phase 15G: ICMPv6 NEIGHBOR DISCOVERY + TUNNEL DETECTION
// ----------------------------------------------------------------
fn detect_icmpv6_features(
    ctx: &mut PacketContext,
    payload: &[u8],
    icmp_type: u8,
    config: &EngineConfig,
) {
    match icmp_type {
        // Echo request (128) and echo reply (129) — check for tunneling
        128 | 129 => {
            if payload.len() > ICMPV6_ECHO_HDR_LEN {
                let data_len = payload.len() - ICMPV6_ECHO_HDR_LEN;
                if data_len > ICMP_TUNNEL_PAYLOAD_THRESHOLD {
                    ctx.icmp_tunnel_suspected = true;
                    if config.output.show_packet_logs {
                        println!(
                            "[ICMPv6] Tunnel suspected: echo payload {} bytes",
                            data_len
                        );
                    }
                }
            }
        }

        // Router Solicitation (133) — node seeking router
        133 => {
            ctx.icmp_nd_type = Some("RS".to_string());
            if config.output.show_packet_logs {
                println!("[ICMPv6-ND] Router Solicitation");
            }
        }

        // Router Advertisement (134) — router announcing itself
        134 => {
            ctx.icmp_nd_type = Some("RA".to_string());
            if config.output.show_packet_logs {
                println!("[ICMPv6-ND] Router Advertisement");
            }
        }

        // Neighbor Solicitation (135): type(1)+code(1)+cksum(2)+reserved(4)+target(16)
        135 => {
            ctx.icmp_nd_type = Some("NS".to_string());
            if payload.len() >= ICMPV6_ND_MIN_LEN {
                let target = extract_ipv6_addr(payload, 8);
                if let Some(addr) = target {
                    if config.output.show_packet_logs {
                        println!("[ICMPv6-ND] Neighbor Solicitation target={}", addr);
                    }
                    ctx.icmp_nd_target = Some(addr);
                }
            }
        }

        // Neighbor Advertisement (136): type(1)+code(1)+cksum(2)+flags(4)+target(16)
        136 => {
            ctx.icmp_nd_type = Some("NA".to_string());
            if payload.len() >= ICMPV6_ND_MIN_LEN {
                // flags: byte 4, bits 31(R)/30(S)/29(O) of the reserved+flags u32
                let flags_u32 = u32::from_be_bytes([
                    payload[4], payload[5], payload[6], payload[7],
                ]);
                let r_flag = (flags_u32 & 0x80000000) != 0;
                let s_flag = (flags_u32 & 0x40000000) != 0;
                let o_flag = (flags_u32 & 0x20000000) != 0;

                let flags_str = format!(
                    "R={} S={} O={}",
                    if r_flag { 1 } else { 0 },
                    if s_flag { 1 } else { 0 },
                    if o_flag { 1 } else { 0 },
                );
                ctx.icmp_nd_flags = Some(flags_str.clone());

                let target = extract_ipv6_addr(payload, 8);
                if let Some(addr) = target {
                    if config.output.show_packet_logs {
                        println!("[ICMPv6-ND] Neighbor Advertisement target={} flags={}", addr, flags_str);
                    }
                    ctx.icmp_nd_target = Some(addr);
                }
            }
        }

        // Redirect (137): type+code+cksum(4)+reserved(4)+target(16)+dest(16)
        137 => {
            ctx.icmp_nd_type = Some("REDIRECT".to_string());
            if payload.len() >= 40 {
                let target = extract_ipv6_addr(payload, 8);
                if let Some(addr) = target {
                    if config.output.show_packet_logs {
                        println!("[ICMPv6-ND] Redirect target={}", addr);
                    }
                    ctx.icmp_nd_target = Some(addr);
                }
            }
        }

        _ => {}
    }
}

// ----------------------------------------------------------------
// IPv6 ADDRESS EXTRACTOR
// ----------------------------------------------------------------
// Reads 16 bytes at `offset` from payload and formats as IPv6 string.
fn extract_ipv6_addr(payload: &[u8], offset: usize) -> Option<String> {
    if offset + 16 > payload.len() {
        return None;
    }

    let mut groups = [0u16; 8];
    for i in 0..8 {
        groups[i] = u16::from_be_bytes([payload[offset + i * 2], payload[offset + i * 2 + 1]]);
    }

    // Format as compressed IPv6 (simple — no :: compression for clarity)
    let addr = format!(
        "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
        groups[0], groups[1], groups[2], groups[3],
        groups[4], groups[5], groups[6], groups[7],
    );

    Some(addr)
}

// ----------------------------------------------------------------
// ICMPv4 DESCRIPTION TABLE
// ----------------------------------------------------------------
fn icmpv4_description(icmp_type: u8, code: u8) -> &'static str {
    match icmp_type {
        0  => "echo-reply",
        3  => match code {
            0  => "net-unreachable",
            1  => "host-unreachable",
            2  => "protocol-unreachable",
            3  => "port-unreachable",
            4  => "fragmentation-needed",
            5  => "source-route-failed",
            6  => "dest-network-unknown",
            7  => "dest-host-unknown",
            9  => "dest-network-admin-prohibited",
            10 => "dest-host-admin-prohibited",
            11 => "network-unreachable-tos",
            12 => "host-unreachable-tos",
            13 => "communication-admin-prohibited",
            _  => "dest-unreachable",
        },
        4  => "source-quench",
        5  => match code {
            0 => "redirect-network",
            1 => "redirect-host",
            2 => "redirect-tos-network",
            3 => "redirect-tos-host",
            _ => "redirect",
        },
        8  => "echo-request",
        9  => "router-advertisement",
        10 => "router-solicitation",
        11 => match code {
            0 => "ttl-exceeded-in-transit",
            1 => "fragment-reassembly-exceeded",
            _ => "time-exceeded",
        },
        12 => match code {
            0 => "pointer-indicates-error",
            1 => "missing-required-option",
            2 => "bad-length",
            _ => "parameter-problem",
        },
        13 => "timestamp-request",
        14 => "timestamp-reply",
        17 => "address-mask-request",
        18 => "address-mask-reply",
        _  => "unknown",
    }
}

// ----------------------------------------------------------------
// ICMPv6 DESCRIPTION TABLE
// ----------------------------------------------------------------
fn icmpv6_description(icmp_type: u8, code: u8) -> &'static str {
    match icmp_type {
        1   => match code {
            0 => "no-route-to-dest",
            1 => "communication-admin-prohibited",
            2 => "beyond-scope-of-source",
            3 => "address-unreachable",
            4 => "port-unreachable",
            5 => "source-failed-ingress-egress",
            6 => "reject-route-to-dest",
            _ => "dest-unreachable",
        },
        2   => "packet-too-big",
        3   => match code {
            0 => "hop-limit-exceeded",
            1 => "fragment-reassembly-exceeded",
            _ => "time-exceeded",
        },
        4   => match code {
            0 => "erroneous-header-field",
            1 => "unrecognized-next-header",
            2 => "unrecognized-ipv6-option",
            _ => "parameter-problem",
        },
        128 => "echo-request",
        129 => "echo-reply",
        130 => "multicast-listener-query",
        131 => "multicast-listener-report",
        132 => "multicast-listener-done",
        133 => "router-solicitation",
        134 => "router-advertisement",
        135 => "neighbor-solicitation",
        136 => "neighbor-advertisement",
        137 => "redirect",
        143 => "multicast-listener-report-v2",
        _   => "unknown",
    }
}