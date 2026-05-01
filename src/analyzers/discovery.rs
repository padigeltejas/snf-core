// src/analyzers/discovery.rs
//
// Network discovery protocol analyzer — Phase 15K.
//
// Supports:
//   - SSDP (port 1900 UDP): M-SEARCH / NOTIFY detection, ST/NT field
//     extraction (service type), USN field (unique service name),
//     LOCATION header (URL for device description).
//   - UPnP detection: HTTP over SSDP — when LOCATION header contains
//     an HTTP URL pointing to a device description XML, set
//     ctx.upnp_location. Device type from NT/ST stored in ctx.upnp_device_type.
//   - FTP (port 21 TCP): command extraction (USER, PASS redacted,
//     CWD, LIST, RETR, STOR, PASV, PORT, QUIT), response code classification,
//     passive mode IP/port extraction.
//
// Security constraints:
//   - All header scanning uses bounded UTF-8 windows
//   - FTP PASS command value is NEVER stored — only presence flagged
//   - LOCATION URLs are capped at MAX_URL_LEN before storage
//   - FTP passive IP/port parsed from server response with bounds checks

use crate::core::packet_context::PacketContext;
use crate::config::engine_config::EngineConfig;
use crate::core::parse_error::{ParseResult, SnfParseError};

// ---- PORTS ----
const SSDP_PORT: u16 = 1900;
const FTP_PORT:  u16 = 21;

// ---- LIMITS ----
/// Maximum number of SSDP header lines to scan.
const SSDP_MAX_HEADERS: usize = 32;
/// Max length for SSDP field values.
const MAX_SSDP_FIELD_LEN: usize = 512;
/// Max LOCATION URL length.
const MAX_URL_LEN: usize = 512;
/// Max FTP command length.
const MAX_FTP_CMD_LEN: usize = 64;

pub fn analyze(
    ctx: &mut PacketContext,
    payload: &[u8],
    config: &EngineConfig,
) -> ParseResult {
    // Reset discovery fields on entry
    ctx.ssdp_method       = None;
    ctx.ssdp_st           = None;
    ctx.ssdp_usn          = None;
    ctx.upnp_location     = None;
    ctx.upnp_device_type  = None;
    ctx.ftp_command       = None;
    ctx.ftp_response_code = None;
    ctx.ftp_passive_addr  = None;
    ctx.ftp_auth_seen     = false;

    // ---------------- SSDP / UPnP ----------------
    let on_ssdp = ctx.src_port == SSDP_PORT || ctx.dst_port == SSDP_PORT;
    if on_ssdp && config.protocol.enable_ssdp {
        if let Err(e) = parse_ssdp(ctx, payload, config)
            && config.output.show_packet_logs {
                println!("[SSDP] parse error: {}", e);
            }
        return Ok(());
    }

    // ---------------- FTP ----------------
    let on_ftp = ctx.src_port == FTP_PORT || ctx.dst_port == FTP_PORT;
    if on_ftp && config.protocol.enable_ftp
        && let Err(e) = parse_ftp(ctx, payload, config)
            && config.output.show_packet_logs {
                println!("[FTP] parse error: {}", e);
            }

    Ok(())
}

// ================================================================
// SSDP / UPnP PARSER
// ================================================================
// SSDP messages are HTTP-like text over UDP multicast 239.255.255.250:1900.
// Client sends M-SEARCH; devices send NOTIFY.
fn parse_ssdp(
    ctx: &mut PacketContext,
    payload: &[u8],
    config: &EngineConfig,
) -> ParseResult {
    let text = match std::str::from_utf8(payload) {
        Ok(t)  => t,
        Err(_) => return Ok(()), // Non-UTF8 on SSDP port — skip
    };

    let mut header_count = 0usize;
    let mut first_line   = true;

    for line in text.lines() {
        if line.is_empty() {
            break; // End of headers
        }

        header_count += 1;
        if header_count > SSDP_MAX_HEADERS {
            return Err(SnfParseError::new(
                "SSDP",
                format!("header count exceeded {}", SSDP_MAX_HEADERS),
                0,
            ));
        }

        if first_line {
            first_line = false;
            // Request line: "M-SEARCH * HTTP/1.1" or "NOTIFY * HTTP/1.1"
            // Response: "HTTP/1.1 200 OK"
            let method = line.split_whitespace().next().unwrap_or("");
            if !method.is_empty() {
                ctx.ssdp_method = Some(method.to_string());
                if config.output.show_packet_logs {
                    println!("[SSDP] method={}", method);
                }
            }
            continue;
        }

        // Parse header: "Name: Value"
        if let Some(colon) = line.find(':') {
            let name  = line[..colon].trim().to_lowercase();
            let value = line[colon + 1..].trim();

            if value.is_empty() || value.len() > MAX_SSDP_FIELD_LEN {
                continue;
            }

            match name.as_str() {
                // ST (Search Target) from M-SEARCH, NT (Notification Type) from NOTIFY
                "st" | "nt" => {
                    ctx.ssdp_st = Some(value.to_string());
                    // Derive UPnP device type: "urn:schemas-upnp-org:device:MediaServer:1"
                    if value.contains(":device:") {
                        ctx.upnp_device_type = Some(value.to_string());
                    }
                    if config.output.show_packet_logs {
                        println!("[SSDP] ST/NT={}", value);
                    }
                }

                // USN: Unique Service Name — identifies device instance
                "usn" => {
                    ctx.ssdp_usn = Some(value.to_string());
                    if config.output.show_packet_logs {
                        println!("[SSDP] USN={}", value);
                    }
                }

                // LOCATION: URL to device description XML — UPnP device discovery
                "location" => {
                    let loc = if value.len() > MAX_URL_LEN {
                        &value[..MAX_URL_LEN]
                    } else {
                        value
                    };
                    ctx.upnp_location = Some(loc.to_string());
                    if config.output.show_packet_logs {
                        println!("[UPnP] LOCATION={}", loc);
                    }
                }

                _ => {}
            }
        }
    }

    Ok(())
}

// ================================================================
// FTP PARSER
// ================================================================
// FTP command channel uses ASCII text over TCP port 21.
// Client sends: "COMMAND [arg]\r\n"
// Server replies: "NNN Response text\r\n" (3-digit code)
fn parse_ftp(
    ctx: &mut PacketContext,
    payload: &[u8],
    config: &EngineConfig,
) -> ParseResult {
    let text = match std::str::from_utf8(payload) {
        Ok(t)  => t,
        Err(_) => return Ok(()),
    };

    // Take only the first line (FTP is line-oriented)
    let line = text.lines().next().unwrap_or("").trim();

    if line.is_empty() {
        return Ok(());
    }

    // ---------------- SERVER RESPONSE ----------------
    // Response format: "NNN [text]" where NNN is 3 ASCII digits
    let first3 = &line[..line.len().min(3)];
    if first3.len() == 3 && first3.chars().all(|c| c.is_ascii_digit()) {
        if let Ok(code) = first3.parse::<u16>() {
            ctx.ftp_response_code = Some(code);

            // Extract PASV response: "227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)"
            if code == 227 {
                extract_ftp_pasv_addr(ctx, line, config);
            }

            if config.output.show_packet_logs {
                println!("[FTP] Response code={}", code);
            }
        }
        return Ok(());
    }

    // ---------------- CLIENT COMMAND ----------------
    let parts: Vec<&str> = line.splitn(2, ' ').collect();
    let cmd = parts[0].to_uppercase();

    if cmd.is_empty() || cmd.len() > MAX_FTP_CMD_LEN {
        return Ok(());
    }

    // Validate: FTP commands are ASCII alpha only
    if !cmd.chars().all(|c| c.is_ascii_alphabetic()) {
        return Ok(());
    }

    let known_commands = [
        "USER", "PASS", "QUIT", "CWD", "PWD", "LIST", "NLST",
        "RETR", "STOR", "APPE", "DELE", "MKD", "RMD", "RNFR",
        "RNTO", "PASV", "PORT", "TYPE", "MODE", "STRU", "NOOP",
        "SYST", "FEAT", "OPTS", "AUTH", "PBSZ", "PROT", "MLSD",
        "MLST", "SIZE", "MDTM", "STAT", "ABOR", "HELP",
    ];

    if !known_commands.contains(&cmd.as_str()) {
        return Ok(()); // Not a known FTP command
    }

    // PASS command: flag auth seen but NEVER store the password
    if cmd == "PASS" {
        ctx.ftp_auth_seen = true;
        ctx.ftp_command = Some("PASS".to_string());
        if config.output.show_packet_logs {
            println!("[FTP] PASS command seen (value redacted)");
        }
        return Ok(());
    }

    // AUTH command: FTP-TLS upgrade
    if cmd == "AUTH" {
        ctx.ftp_auth_seen = true;
    }

    // Store command with argument (except PASS)
    let full_cmd = if parts.len() > 1 && !parts[1].is_empty() {
        format!("{} {}", cmd, parts[1].trim())
    } else {
        cmd.clone()
    };

    // Cap stored command length
    let stored = if full_cmd.len() > MAX_FTP_CMD_LEN * 2 {
        full_cmd[..MAX_FTP_CMD_LEN * 2].to_string()
    } else {
        full_cmd
    };

    if config.output.show_packet_logs {
        println!("[FTP] cmd={}", stored);
    }

    ctx.ftp_command = Some(stored);

    Ok(())
}

// ----------------------------------------------------------------
// FTP PASV Address Extractor
// ----------------------------------------------------------------
// PASV response: "227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)"
// IP = h1.h2.h3.h4, Port = p1*256 + p2
fn extract_ftp_pasv_addr(
    ctx: &mut PacketContext,
    line: &str,
    config: &EngineConfig,
) {
    // Find opening and closing parentheses
    let paren_start = match line.find('(') {
        Some(p) => p + 1,
        None    => return,
    };
    let paren_end = match line[paren_start..].find(')') {
        Some(p) => paren_start + p,
        None    => return,
    };

    let inner = &line[paren_start..paren_end];
    let parts: Vec<&str> = inner.splitn(6, ',').collect();

    if parts.len() != 6 {
        return;
    }

    let octets: Vec<u8> = parts[..4].iter()
        .filter_map(|s| s.trim().parse::<u8>().ok())
        .collect();

    if octets.len() != 4 {
        return;
    }

    let p1 = parts[4].trim().parse::<u16>().unwrap_or(0);
    let p2 = parts[5].trim().parse::<u16>().unwrap_or(0);
    let port = p1 * 256 + p2;

    let addr = format!("{}.{}.{}.{}:{}", octets[0], octets[1], octets[2], octets[3], port);

    if config.output.show_packet_logs {
        println!("[FTP] PASV addr={}", addr);
    }

    ctx.ftp_passive_addr = Some(addr);
}