// src/analyzers/dhcp.rs
//
// DHCP protocol analyzer.
//
// Phase 15E additions:
//   - DHCP Option 82 (Relay Agent Information): parsed from relay agent messages.
//     Sub-option 1 (Circuit ID) stored in ctx.dhcp_relay_circuit_id.
//     Sub-option 2 (Remote ID) stored in ctx.dhcp_relay_remote_id.
//     Presence of Option 82 sets ctx.dhcp_relay_present = true.
//   - DHCPv6 detection: UDP port 546/547 packets set ctx.dhcp_version = 6.
//     DHCPv6 message type extracted from the first byte.
//     Client DUID extracted from Client Identifier option (type 1).
//
// Phase 2 (preserved): ParseResult, all option parsing bounds-checked,
//   hlen validation, magic cookie check, MAX_* constants.

use crate::core::packet_context::PacketContext;
use crate::config::engine_config::EngineConfig;
use crate::core::parse_error::{ParseResult, SnfParseError};

/// DHCPv4 server/client ports.
const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;

/// DHCPv6 server/client ports (RFC 3315).
const DHCPV6_SERVER_PORT: u16 = 547;
const DHCPV6_CLIENT_PORT: u16 = 546;

/// Minimum DHCPv4 message size: fixed header is 236 bytes.
const DHCP_MIN_LEN: usize = 236;

/// DHCPv4 magic cookie offset and value.
const DHCP_MAGIC_COOKIE_OFFSET: usize = 236;
const DHCP_MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

/// Max lengths for stored string fields.
const MAX_HOSTNAME_LEN: usize = 253;
const MAX_VENDOR_CLASS_LEN: usize = 255;
/// Max length for Relay Agent sub-option values.
const MAX_RELAY_OPTION_LEN: usize = 128;
/// Max DUID length per RFC 3315: 128 bytes + 2 type bytes = 130.
const MAX_DUID_LEN: usize = 130;

/// DHCPv4 message type codes (Option 53).
const DHCP_DISCOVER: u8 = 1;
const DHCP_OFFER:    u8 = 2;
const DHCP_REQUEST:  u8 = 3;
const DHCP_DECLINE:  u8 = 4;
const DHCP_ACK:      u8 = 5;
const DHCP_NAK:      u8 = 6;
const DHCP_RELEASE:  u8 = 7;
const DHCP_INFORM:   u8 = 8;

pub fn analyze(
    ctx: &mut PacketContext,
    payload: &[u8],
    config: &EngineConfig,
) -> ParseResult {
    if ctx.protocol != "UDP" {
        return Ok(());
    }

    // Phase 15E: detect DHCPv6 on ports 546/547 before DHCPv4 check.
    let on_dhcpv6_port = ctx.src_port == DHCPV6_SERVER_PORT
        || ctx.src_port == DHCPV6_CLIENT_PORT
        || ctx.dst_port == DHCPV6_SERVER_PORT
        || ctx.dst_port == DHCPV6_CLIENT_PORT;

    if on_dhcpv6_port {
        return analyze_dhcpv6(ctx, payload, config);
    }

    let on_dhcp_port = ctx.src_port == DHCP_SERVER_PORT
        || ctx.src_port == DHCP_CLIENT_PORT
        || ctx.dst_port == DHCP_SERVER_PORT
        || ctx.dst_port == DHCP_CLIENT_PORT;

    if !on_dhcp_port {
        return Ok(());
    }

    // Reset all DHCP fields on entry
    ctx.dhcp_msg_type = None;
    ctx.dhcp_client_mac = None;
    ctx.dhcp_requested_ip = None;
    ctx.dhcp_assigned_ip = None;
    ctx.dhcp_hostname = None;
    ctx.dhcp_vendor_class = None;
    // Phase 15E relay fields
    ctx.dhcp_relay_present = false;
    ctx.dhcp_relay_circuit_id = None;
    ctx.dhcp_relay_remote_id = None;
    ctx.dhcp_version = 4;

    if payload.len() < DHCP_MIN_LEN {
        return Err(SnfParseError::new(
            "DHCP",
            format!("packet too short: {} bytes (minimum {})", payload.len(), DHCP_MIN_LEN),
            0,
        ));
    }

    // op, htype, hlen from fixed header
    let htype = payload[1];
    let hlen  = payload[2] as usize;

    // yiaddr: server-assigned IP (offset 16, 4 bytes)
    let yiaddr = &payload[16..20];
    if yiaddr != [0u8, 0, 0, 0] {
        ctx.dhcp_assigned_ip = Some(format!(
            "{}.{}.{}.{}",
            yiaddr[0], yiaddr[1], yiaddr[2], yiaddr[3]
        ));
    }

    // chaddr: client hardware address (offset 28)
    if htype == 1 && hlen == 6 {
        if 28 + 6 <= payload.len() {
            let mac = &payload[28..34];
            ctx.dhcp_client_mac = Some(format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
            ));
        }
    } else if hlen > 16 {
        return Err(SnfParseError::new(
            "DHCP",
            format!("invalid hlen={} (max 16)", hlen),
            2,
        ));
    }

    // Validate magic cookie before parsing options
    if payload.len() < DHCP_MAGIC_COOKIE_OFFSET + 4 {
        return Ok(());
    }

    let cookie = &payload[DHCP_MAGIC_COOKIE_OFFSET..DHCP_MAGIC_COOKIE_OFFSET + 4];
    if cookie != DHCP_MAGIC_COOKIE {
        return Err(SnfParseError::new(
            "DHCP",
            format!(
                "invalid magic cookie: {:02x}{:02x}{:02x}{:02x}",
                cookie[0], cookie[1], cookie[2], cookie[3]
            ),
            DHCP_MAGIC_COOKIE_OFFSET,
        ));
    }

    // ---------------- OPTION PARSING ----------------
    let mut pos = DHCP_MAGIC_COOKIE_OFFSET + 4;

    while pos < payload.len() {
        let option_code = payload[pos];
        pos += 1;

        match option_code {
            0   => continue, // PAD
            255 => break,    // END
            _ => {
                if pos >= payload.len() {
                    return Err(SnfParseError::new(
                        "DHCP",
                        format!("option {}: missing length byte at offset {}", option_code, pos),
                        pos,
                    ));
                }

                let opt_len = payload[pos] as usize;
                pos += 1;

                if pos + opt_len > payload.len() {
                    return Err(SnfParseError::new(
                        "DHCP",
                        format!(
                            "option {}: data out of bounds (len={} offset={} payload={})",
                            option_code, opt_len, pos, payload.len()
                        ),
                        pos,
                    ));
                }

                let opt_data = &payload[pos..pos + opt_len];

                match option_code {
                    // Option 53: DHCP Message Type (1 byte)
                    53 => {
                        if opt_len != 1 {
                            return Err(SnfParseError::new(
                                "DHCP",
                                format!("option 53: expected len=1 got {}", opt_len),
                                pos,
                            ));
                        }
                        let type_str = dhcp_msg_type_str(opt_data[0]);
                        ctx.dhcp_msg_type = Some(type_str.to_string());
                        if config.output.show_packet_logs {
                            println!("DHCP message type: {}", type_str);
                        }
                    }

                    // Option 12: Host Name
                    12 => {
                        let len = opt_len.min(MAX_HOSTNAME_LEN);
                        if let Ok(hostname) = std::str::from_utf8(&opt_data[..len])
                            && !hostname.is_empty() {
                                ctx.dhcp_hostname = Some(hostname.to_string());
                            }
                    }

                    // Option 50: Requested IP Address (4 bytes)
                    50 => {
                        if opt_len == 4 {
                            ctx.dhcp_requested_ip = Some(format!(
                                "{}.{}.{}.{}",
                                opt_data[0], opt_data[1], opt_data[2], opt_data[3]
                            ));
                        } else {
                            return Err(SnfParseError::new(
                                "DHCP",
                                format!("option 50: expected len=4 got {}", opt_len),
                                pos,
                            ));
                        }
                    }

                    // Option 60: Vendor Class Identifier
                    60 => {
                        let len = opt_len.min(MAX_VENDOR_CLASS_LEN);
                        if let Ok(vendor) = std::str::from_utf8(&opt_data[..len])
                            && !vendor.is_empty() {
                                ctx.dhcp_vendor_class = Some(vendor.to_string());
                            }
                    }

                    // Phase 15E: Option 82 — Relay Agent Information
                    // Contains sub-options identifying the relay agent and circuit.
                    // Layout: [sub_type(1) + sub_len(1) + sub_data(sub_len)]*
                    82 => {
                        ctx.dhcp_relay_present = true;
                        parse_relay_agent_option(ctx, opt_data, config);
                    }

                    _ => {}
                }

                pos += opt_len;
            }
        }
    }

    Ok(())
}

// ----------------------------------------------------------------
// Phase 15E: OPTION 82 — RELAY AGENT INFORMATION PARSER
// ----------------------------------------------------------------
// Sub-options of interest:
//   1 = Circuit ID (identifies the port/VLAN the client is connected to)
//   2 = Remote ID  (identifies the relay agent itself, e.g. MAC or FQDN)
fn parse_relay_agent_option(
    ctx: &mut PacketContext,
    data: &[u8],
    config: &EngineConfig,
) {
    let mut pos = 0;

    while pos + 2 <= data.len() {
        let sub_type = data[pos];
        let sub_len  = data[pos + 1] as usize;
        pos += 2;

        if pos + sub_len > data.len() {
            break; // Bounds check — malformed sub-option, stop parsing
        }

        let sub_data = &data[pos..pos + sub_len];
        let cap_len = sub_len.min(MAX_RELAY_OPTION_LEN);

        match sub_type {
            // Sub-option 1: Circuit ID — typically identifies ingress port/VLAN
            1 => {
                let value = String::from_utf8_lossy(&sub_data[..cap_len]).into_owned();
                if config.output.show_packet_logs {
                    println!("DHCP Option 82 Circuit-ID: {}", value);
                }
                ctx.dhcp_relay_circuit_id = Some(value);
            }

            // Sub-option 2: Remote ID — identifies the relay agent
            2 => {
                let value = String::from_utf8_lossy(&sub_data[..cap_len]).into_owned();
                if config.output.show_packet_logs {
                    println!("DHCP Option 82 Remote-ID: {}", value);
                }
                ctx.dhcp_relay_remote_id = Some(value);
            }

            _ => {} // Other sub-options ignored
        }

        pos += sub_len;
    }
}

// ----------------------------------------------------------------
// Phase 15E: DHCPv6 ANALYZER
// ----------------------------------------------------------------
// DHCPv6 message format (RFC 3315):
//   msg_type(1) + transaction_id(3) + [option_type(2) + option_len(2) + option_data]*
//
// Relay messages (msg_type 12=RELAY-FORW, 13=RELAY-REPL) have a different layout.
// We parse the simple client-server messages only.
fn analyze_dhcpv6(
    ctx: &mut PacketContext,
    payload: &[u8],
    config: &EngineConfig,
) -> ParseResult {
    // Reset DHCP fields for DHCPv6
    ctx.dhcp_msg_type = None;
    ctx.dhcp_client_mac = None;
    ctx.dhcp_requested_ip = None;
    ctx.dhcp_assigned_ip = None;
    ctx.dhcp_hostname = None;
    ctx.dhcp_vendor_class = None;
    ctx.dhcp_relay_present = false;
    ctx.dhcp_relay_circuit_id = None;
    ctx.dhcp_relay_remote_id = None;
    ctx.dhcp_version = 6;

    // Minimum DHCPv6 message: msg_type(1) + transaction_id(3) = 4 bytes
    if payload.len() < 4 {
        return Err(SnfParseError::new("DHCPv6", "packet too short (< 4 bytes)", 0));
    }

    let msg_type = payload[0];
    let msg_type_str = dhcpv6_msg_type_str(msg_type);
    ctx.dhcp_msg_type = Some(msg_type_str.to_string());

    if config.output.show_packet_logs {
        println!("DHCPv6 message type: {}", msg_type_str);
    }

    // Relay messages (12, 13) have a different header — skip option parsing for them
    if msg_type == 12 || msg_type == 13 {
        ctx.dhcp_relay_present = true;
        return Ok(());
    }

    // Options start at offset 4 (after msg_type + transaction_id)
    let mut pos = 4;

    while pos + 4 <= payload.len() {
        let opt_type = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let opt_len  = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;
        pos += 4;

        if pos + opt_len > payload.len() {
            return Err(SnfParseError::new(
                "DHCPv6",
                format!("option {} data out of bounds: len={} offset={}", opt_type, opt_len, pos),
                pos,
            ));
        }

        let opt_data = &payload[pos..pos + opt_len];

        match opt_type {
            // Option 1: Client Identifier — contains DUID
            1 => {
                // Store DUID as a hex string (capped at MAX_DUID_LEN bytes).
                // DUIDs are binary and may not be valid UTF-8.
                let cap = opt_len.min(MAX_DUID_LEN);
                let duid_hex = opt_data[..cap]
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(":");
                ctx.dhcp_client_mac = Some(duid_hex); // reuse field for DUID
                if config.output.show_packet_logs {
                    println!("DHCPv6 Client DUID: {} bytes", opt_len);
                }
            }

            // Option 3: Identity Association for Non-Temporary Address (IA_NA)
            // Contains the assigned IPv6 address in sub-options.
            3 => {
                // IA_NA: IAID(4) + T1(4) + T2(4) + [sub-options]
                if opt_len >= 12 {
                    let sub_start = pos + 12;
                    parse_dhcpv6_iaaddr(ctx, payload, sub_start, pos + opt_len, config);
                }
            }

            _ => {}
        }

        pos += opt_len;
    }

    Ok(())
}

// ----------------------------------------------------------------
// DHCPv6 IA_NA Sub-option Parser — extracts assigned IPv6 address
// ----------------------------------------------------------------
fn parse_dhcpv6_iaaddr(
    ctx: &mut PacketContext,
    payload: &[u8],
    start: usize,
    end: usize,
    _config: &EngineConfig,
) {
    let mut pos = start;

    while pos + 4 <= end && pos + 4 <= payload.len() {
        let sub_type = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let sub_len  = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;
        pos += 4;

        if pos + sub_len > end || pos + sub_len > payload.len() {
            break;
        }

        // Sub-option 5: IAADDR — contains the assigned IPv6 address (16 bytes)
        if sub_type == 5 && sub_len >= 16 {
            let mut addr_bytes = [0u8; 16];
            addr_bytes.copy_from_slice(&payload[pos..pos + 16]);
            let ipv6 = std::net::Ipv6Addr::from(addr_bytes);
            ctx.dhcp_assigned_ip = Some(ipv6.to_string());
        }

        pos += sub_len;
    }
}

// ----------------------------------------------------------------
// DHCPv4 MESSAGE TYPE STRING
// ----------------------------------------------------------------
fn dhcp_msg_type_str(msg_type: u8) -> &'static str {
    match msg_type {
        DHCP_DISCOVER => "DISCOVER",
        DHCP_OFFER    => "OFFER",
        DHCP_REQUEST  => "REQUEST",
        DHCP_DECLINE  => "DECLINE",
        DHCP_ACK      => "ACK",
        DHCP_NAK      => "NAK",
        DHCP_RELEASE  => "RELEASE",
        DHCP_INFORM   => "INFORM",
        _             => "UNKNOWN",
    }
}

// ----------------------------------------------------------------
// DHCPv6 MESSAGE TYPE STRING (RFC 3315 section 5.3)
// ----------------------------------------------------------------
fn dhcpv6_msg_type_str(msg_type: u8) -> &'static str {
    match msg_type {
        1  => "SOLICIT",
        2  => "ADVERTISE",
        3  => "REQUEST",
        4  => "CONFIRM",
        5  => "RENEW",
        6  => "REBIND",
        7  => "REPLY",
        8  => "RELEASE",
        9  => "DECLINE",
        10 => "RECONFIGURE",
        11 => "INFORMATION-REQUEST",
        12 => "RELAY-FORW",
        13 => "RELAY-REPL",
        _  => "UNKNOWN",
    }
}