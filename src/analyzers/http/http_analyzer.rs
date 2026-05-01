// src/analyzers/http/http_analyzer.rs
//
// HTTP/1.x and HTTP/2 protocol analyzer.
//
// Phase 15C additions:
//   - WebSocket upgrade detection: "Upgrade: websocket" header in HTTP/1.1
//     sets ctx.http_websocket = true and ctx.http_upgrade = Some("websocket").
//   - HTTP/3 detection: QUIC ALPN "h3" or "h3-29" already handled via QUIC+TLS
//     analyzers, but if http_version was set to "HTTP/2" via HPACK and the
//     underlying transport is UDP, we upgrade it to "HTTP/3" here.
//   - Response code classification: ctx.http_status_class set to
//     "1xx","2xx","3xx","4xx","5xx" based on status_code for fast event filtering.
//   - Referer header extraction: ctx.http_referer stored (bounded, sanitized).
//   - X-Forwarded-For extraction: ctx.http_xff stored — identifies real client
//     IP behind proxies/load-balancers. Bounded to MAX_XFF_LEN.
//
// Phase 3A (preserved): request line, response status, host, user-agent,
//   content-type, content-length, HTTP/2 frame parsing, :authority extraction.
// Phase 2 (preserved): ParseResult, port check, header count limit, host len limit.

use crate::core::packet_context::PacketContext;
use crate::config::engine_config::EngineConfig;
use crate::discovery::dns_cache::DnsCache;
use crate::core::parse_error::{ParseResult, SnfParseError};

/// Maximum number of HTTP/1.x header lines to scan.
const HTTP_MAX_HEADERS: usize = 100;

/// Maximum valid length for an HTTP Host header value (max FQDN per RFC 1035).
const HTTP_MAX_HOST_LEN: usize = 253;

/// Maximum length for HTTP method string.
const HTTP_MAX_METHOD_LEN: usize = 16;

/// Maximum length for HTTP URI.
const HTTP_MAX_URI_LEN: usize = 8192;

/// Maximum length for User-Agent header value.
const HTTP_MAX_UA_LEN: usize = 512;

/// Maximum length for Content-Type header value.
const HTTP_MAX_CONTENT_TYPE_LEN: usize = 256;

/// Maximum length for Referer header value (Phase 15C).
const HTTP_MAX_REFERER_LEN: usize = 1024;

/// Maximum length for X-Forwarded-For header value (Phase 15C).
/// XFF can contain multiple IPs separated by commas — cap generously.
const HTTP_MAX_XFF_LEN: usize = 512;

/// Maximum number of HTTP/2 frames to process per packet.
const HTTP2_MAX_FRAMES: usize = 256;

pub struct HttpAnalyzer;

impl HttpAnalyzer {
    pub fn analyze(
        ctx: &mut PacketContext,
        payload: &[u8],
        _dns_cache: &mut DnsCache,
        config: &EngineConfig,
    ) -> ParseResult {
        // Port check against configured http_ports
        let on_http_port = config.protocol.http_ports.contains(&ctx.src_port)
            || config.protocol.http_ports.contains(&ctx.dst_port);

        if !on_http_port {
            return Ok(());
        }

        // Phase 15C: if underlying transport is UDP (QUIC), mark as HTTP/3.
        // The QUIC+TLS analyzers extract SNI and ALPN; we just set the version label.
        if ctx.protocol == "UDP" {
            if ctx.tls_alpn.as_deref() == Some("h3")
                || ctx.tls_alpn.as_deref() == Some("h3-29")
            {
                ctx.http_version = Some("HTTP/3".to_string());
            }
            return Ok(());
        }

        // ---------------- HTTP/2 PREFACE DETECTION ----------------
        const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        if payload.starts_with(H2_PREFACE) {
            ctx.http_version = Some("HTTP/2".to_string());
        }

        // ---------------- HTTP/2 FRAME PARSER ----------------
        if let Err(e) = parse_http2_frames(ctx, payload, config)
            && config.output.show_packet_logs {
                println!("HTTP/2 parse note: {}", e);
            }

        // If HTTP/2 already found a host, skip HTTP/1.x scan
        if ctx.http_host.is_some() {
            // Still apply status classification if a code was found
            apply_status_class(ctx);
            return Ok(());
        }

        // ---------------- HTTP/1.x PARSER ----------------
        match std::str::from_utf8(payload) {
            Ok(data) => {
                parse_http1(ctx, data, config)?;
            }
            Err(_) => {
                // Non-UTF8 on HTTP port — could be TLS or binary, not an error
                return Ok(());
            }
        }

        // Phase 15C: classify status code after parsing
        apply_status_class(ctx);

        Ok(())
    }
}

// ----------------------------------------------------------------
// HTTP/1.x PARSER
// ----------------------------------------------------------------
fn parse_http1(
    ctx: &mut PacketContext,
    data: &str,
    config: &EngineConfig,
) -> ParseResult {
    let mut header_count = 0usize;
    let mut first_line = true;

    for line in data.lines() {
        if line.is_empty() {
            break; // End of headers
        }

        if first_line {
            first_line = false;
            parse_http1_first_line(ctx, line, config);
            continue;
        }

        header_count += 1;
        if header_count > HTTP_MAX_HEADERS {
            return Err(SnfParseError::new(
                "HTTP",
                format!("header count exceeded limit of {}", HTTP_MAX_HEADERS),
                0,
            ));
        }

        // Parse header — find the colon separator
        if let Some(colon_pos) = line.find(':') {
            let name  = line[..colon_pos].trim().to_lowercase();
            let value = line[colon_pos + 1..].trim();

            match name.as_str() {
                "host" => {
                    if value.len() <= HTTP_MAX_HOST_LEN && !value.is_empty() {
                        if config.output.show_packet_logs {
                            println!("HTTP Host: {}", value);
                        }
                        ctx.http_host = Some(value.to_string());
                    } else if value.len() > HTTP_MAX_HOST_LEN {
                        return Err(SnfParseError::new(
                            "HTTP",
                            format!("Host header value exceeds max length ({})", HTTP_MAX_HOST_LEN),
                            0,
                        ));
                    }
                }

                "user-agent" => {
                    if !value.is_empty() {
                        let truncated = if value.len() > HTTP_MAX_UA_LEN {
                            &value[..HTTP_MAX_UA_LEN]
                        } else {
                            value
                        };
                        ctx.http_user_agent = Some(truncated.to_string());
                    }
                }

                "content-type" => {
                    if !value.is_empty() {
                        let truncated = if value.len() > HTTP_MAX_CONTENT_TYPE_LEN {
                            &value[..HTTP_MAX_CONTENT_TYPE_LEN]
                        } else {
                            value
                        };
                        ctx.http_content_type = Some(truncated.to_string());
                    }
                }

                "content-length" => {
                    if let Ok(len) = value.trim().parse::<u64>() {
                        ctx.http_content_length = Some(len);
                    }
                }

                // Phase 15C: Upgrade header — detect WebSocket upgrade
                "upgrade" => {
                    let upgrade_val = value.to_lowercase();
                    if upgrade_val == "websocket" {
                        ctx.http_websocket = true;
                        ctx.http_upgrade = Some("websocket".to_string());
                        if config.output.show_http_logs {
                            println!("[HTTP] WebSocket upgrade detected");
                        }
                    } else if !value.is_empty() {
                        // Store other upgrade values (e.g. "h2c")
                        ctx.http_upgrade = Some(value.to_string());
                    }
                }

                // Phase 15C: Referer header — bounded storage
                "referer" => {
                    if !value.is_empty() {
                        let truncated = if value.len() > HTTP_MAX_REFERER_LEN {
                            &value[..HTTP_MAX_REFERER_LEN]
                        } else {
                            value
                        };
                        ctx.http_referer = Some(truncated.to_string());
                    }
                }

                // Phase 15C: X-Forwarded-For — identifies real client behind proxy
                "x-forwarded-for" => {
                    if !value.is_empty() {
                        let truncated = if value.len() > HTTP_MAX_XFF_LEN {
                            &value[..HTTP_MAX_XFF_LEN]
                        } else {
                            value
                        };
                        ctx.http_xff = Some(truncated.to_string());
                        if config.output.show_http_logs {
                            println!("[HTTP] X-Forwarded-For: {}", truncated);
                        }
                    }
                }

                _ => {}
            }
        }
    }

    Ok(())
}

// ----------------------------------------------------------------
// HTTP/1.x FIRST LINE PARSER
// ----------------------------------------------------------------
fn parse_http1_first_line(ctx: &mut PacketContext, line: &str, config: &EngineConfig) {
    let parts: Vec<&str> = line.splitn(3, ' ').collect();

    if parts.len() < 2 {
        return;
    }

    // Detect response: first token starts with "HTTP/"
    if parts[0].starts_with("HTTP/") {
        let version = parts[0];
        ctx.http_version = Some(version.to_string());

        if let Ok(code) = parts[1].parse::<u16>()
            && (100..=599).contains(&code) {
                ctx.http_status_code = Some(code);
                if config.output.show_packet_logs {
                    println!("HTTP Response: {} {}", version, code);
                }
            }
        return;
    }

    // Request line: METHOD URI HTTP/version
    let method = parts[0];

    let method_valid = !method.is_empty()
        && method.len() <= HTTP_MAX_METHOD_LEN
        && method.chars().all(|c| c.is_ascii_uppercase());

    if !method_valid {
        return;
    }

    // Only accept known HTTP methods — rejects garbage
    let known_methods = [
        "GET", "POST", "PUT", "DELETE", "HEAD",
        "OPTIONS", "PATCH", "CONNECT", "TRACE",
    ];
    if !known_methods.contains(&method) {
        return;
    }

    ctx.http_method = Some(method.to_string());

    if parts.len() >= 2 {
        let uri = parts[1];
        if !uri.is_empty() && uri.len() <= HTTP_MAX_URI_LEN {
            ctx.http_uri = Some(uri.to_string());
        }
    }

    if parts.len() >= 3 && parts[2].starts_with("HTTP/") {
        ctx.http_version = Some(parts[2].to_string());
    }

    if config.output.show_packet_logs {
        println!(
            "HTTP Request: {} {} {}",
            ctx.http_method.as_deref().unwrap_or(""),
            ctx.http_uri.as_deref().unwrap_or(""),
            ctx.http_version.as_deref().unwrap_or(""),
        );
    }
}

// ----------------------------------------------------------------
// Phase 15C: STATUS CODE CLASSIFIER
// ----------------------------------------------------------------
// Sets ctx.http_status_class from the numeric status code.
// Enables fast event filtering without string parsing downstream.
fn apply_status_class(ctx: &mut PacketContext) {
    if let Some(code) = ctx.http_status_code {
        ctx.http_status_class = Some(match code {
            100..=199 => "1xx",
            200..=299 => "2xx",
            300..=399 => "3xx",
            400..=499 => "4xx",
            500..=599 => "5xx",
            _         => "unknown",
        }.to_string());
    }
}

// ----------------------------------------------------------------
// HTTP/2 FRAME PARSER
// ----------------------------------------------------------------
fn parse_http2_frames(
    ctx: &mut PacketContext,
    payload: &[u8],
    config: &EngineConfig,
) -> ParseResult {
    let mut pos = 0usize;
    let mut frame_count = 0usize;

    while pos + 9 <= payload.len() {
        frame_count += 1;
        if frame_count > HTTP2_MAX_FRAMES {
            return Err(SnfParseError::new(
                "HTTP",
                format!("HTTP/2 frame count exceeded limit of {}", HTTP2_MAX_FRAMES),
                pos,
            ));
        }

        // HTTP/2 frame header: length(3) + type(1) + flags(1) + stream_id(4) = 9 bytes
        let length = ((payload[pos] as usize) << 16)
            | ((payload[pos + 1] as usize) << 8)
            | (payload[pos + 2] as usize);

        let frame_type = payload[pos + 3];
        let frame_end  = pos + 9 + length;

        if frame_end > payload.len() {
            break; // Partial frame — normal at reassembly boundaries
        }

        // HEADERS frame type = 0x01
        if frame_type == 0x01 {
            let headers_block = &payload[pos + 9..frame_end];
            extract_http2_authority(ctx, headers_block, config);
            if ctx.http_host.is_some() {
                return Ok(());
            }
        }

        pos = frame_end;
    }

    Ok(())
}

// ----------------------------------------------------------------
// HTTP/2 :authority EXTRACTOR
// ----------------------------------------------------------------
// Conservative passive scan for :authority pseudo-header in raw HPACK block.
fn extract_http2_authority(
    ctx: &mut PacketContext,
    headers: &[u8],
    config: &EngineConfig,
) {
    let needle = b":authority";
    let len = headers.len();

    if len < needle.len() + 3 {
        return;
    }

    let search_end = len - needle.len();
    let mut i = 0usize;

    while i <= search_end {
        if &headers[i..i + needle.len()] == needle {
            let after = i + needle.len();

            if after < len {
                let rest = &headers[after..];
                let value_start = rest
                    .iter()
                    .position(|&b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b':')
                    .unwrap_or(len);

                if value_start < rest.len() {
                    let value_end = rest[value_start..]
                        .iter()
                        .position(|&b| {
                            !b.is_ascii_alphanumeric() && b != b'.' && b != b'-' && b != b':'
                        })
                        .map(|e| value_start + e)
                        .unwrap_or(rest.len());

                    let domain_bytes = &rest[value_start..value_end];

                    if domain_bytes.len() > 3 && domain_bytes.len() <= HTTP_MAX_HOST_LEN
                        && let Ok(domain) = std::str::from_utf8(domain_bytes)
                            && domain.contains('.') {
                                if config.output.show_packet_logs {
                                    println!("HTTP/2 :authority = {}", domain);
                                }
                                ctx.http_host = Some(domain.to_string());
                                return;
                            }
                }
            }
        }
        i += 1;
    }
}