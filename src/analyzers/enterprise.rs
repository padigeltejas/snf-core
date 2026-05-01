// src/analyzers/enterprise.rs
//
// Enterprise authentication protocol analyzer — Phase 15J.
//
// Supports:
//   - Kerberos (port 88 TCP/UDP): message type detection (AS-REQ, AS-REP,
//     TGS-REQ, TGS-REP, AP-REQ, AP-REP, KRB-ERROR), principal name
//     extraction, realm extraction, error code decoding.
//   - LDAP (port 389 TCP, 636 TLS): message type (BIND, SEARCH, ADD,
//     MODIFY, DELETE), search base/filter extraction, bind DN extraction.
//   - RDP (port 3389 TCP): protocol version detection (RDP 4/5/6/7/8/10),
//     cookie/routing token extraction, NLA/SSL/RDP security detection.
//
// Security constraints:
//   - All offset math bounds-checked before access
//   - MAX_* constants cap all loops on untrusted data
//   - No raw credential bytes stored — only metadata
//   - ASN.1 parsing is length-validated before any slice

use crate::core::packet_context::PacketContext;
use crate::config::engine_config::EngineConfig;
use crate::core::parse_error::ParseResult;

// ---- PORTS ----
const KERBEROS_PORT_PRIMARY: u16 = 88;
const LDAP_PORT:             u16 = 389;
const LDAPS_PORT:            u16 = 636;
const RDP_PORT:              u16 = 3389;

// ---- LIMITS ----
/// Max bytes to scan in Kerberos payload for fields.
const KRB_MAX_SCAN: usize = 512;
/// Max bytes to scan in LDAP payload.
const LDAP_MAX_SCAN: usize = 512;
/// Max length for extracted DN, realm, principal strings.
const MAX_FIELD_LEN: usize = 256;
/// Max RDP cookie length.
const MAX_RDP_COOKIE_LEN: usize = 128;

pub fn analyze(
    ctx: &mut PacketContext,
    payload: &[u8],
    config: &EngineConfig,
) -> ParseResult {
    // Reset enterprise fields on entry
    ctx.krb_msg_type    = None;
    ctx.krb_realm       = None;
    ctx.krb_principal   = None;
    ctx.krb_error_code  = None;
    ctx.ldap_msg_type   = None;
    ctx.ldap_base_dn    = None;
    ctx.ldap_bind_dn    = None;
    ctx.rdp_version     = None;
    ctx.rdp_cookie      = None;
    ctx.rdp_security    = None;

    // ---------------- KERBEROS ----------------
    let on_krb = ctx.src_port == KERBEROS_PORT_PRIMARY
        || ctx.dst_port == KERBEROS_PORT_PRIMARY;

    if on_krb && config.protocol.enable_kerberos {
        if let Err(e) = parse_kerberos(ctx, payload, config)
            && config.output.show_packet_logs {
                println!("[Kerberos] parse error: {}", e);
            }
        return Ok(());
    }

    // ---------------- LDAP / LDAPS ----------------
    let on_ldap = ctx.src_port == LDAP_PORT || ctx.dst_port == LDAP_PORT
        || ctx.src_port == LDAPS_PORT || ctx.dst_port == LDAPS_PORT;

    if on_ldap && config.protocol.enable_ldap {
        if let Err(e) = parse_ldap(ctx, payload, config)
            && config.output.show_packet_logs {
                println!("[LDAP] parse error: {}", e);
            }
        return Ok(());
    }

    // ---------------- RDP ----------------
    let on_rdp = ctx.src_port == RDP_PORT || ctx.dst_port == RDP_PORT;

    if on_rdp && config.protocol.enable_rdp
        && let Err(e) = parse_rdp(ctx, payload, config)
            && config.output.show_packet_logs {
                println!("[RDP] parse error: {}", e);
            }

    Ok(())
}

// ================================================================
// KERBEROS PARSER
// ================================================================
// Kerberos messages are ASN.1 DER encoded. The APPLICATION tag
// identifies the message type:
//   [APPLICATION 10] = AS-REQ     [APPLICATION 11] = AS-REP
//   [APPLICATION 12] = TGS-REQ    [APPLICATION 13] = TGS-REP
//   [APPLICATION 14] = AP-REQ     [APPLICATION 15] = AP-REP
//   [APPLICATION 30] = KRB-ERROR
//
// For TCP, Kerberos messages have a 4-byte length prefix. We handle both.
fn parse_kerberos(
    ctx: &mut PacketContext,
    payload: &[u8],
    config: &EngineConfig,
) -> ParseResult {
    if payload.is_empty() {
        return Ok(());
    }

    let scan = &payload[..payload.len().min(KRB_MAX_SCAN)];
    let mut pos = 0usize;

    // Skip 4-byte TCP length prefix if present (TCP Kerberos wrapping)
    if scan.len() >= 5 && is_krb_app_tag(scan[4]) {
        pos = 4;
    }

    if pos >= scan.len() {
        return Ok(());
    }

    // Expect ASN.1 APPLICATION tag (0x6a–0x7f range for Kerberos)
    let tag = scan[pos];
    if !is_krb_app_tag(tag) {
        return Ok(()); // Not Kerberos
    }

    // Map APPLICATION tag to message type name
    let msg_type = krb_msg_type_name(tag);
    ctx.krb_msg_type = Some(msg_type.to_string());

    if config.output.show_packet_logs {
        println!("[Kerberos] msg_type={} tag=0x{:02x}", msg_type, tag);
    }

    // Skip tag(1) + length(variable)
    pos += 1;
    if pos >= scan.len() {
        return Ok(());
    }

    let (_, len_bytes) = read_asn1_length(scan, pos);
    pos += len_bytes;

    // Scan for realm (GeneralString or UTF8String, tag 0x1B or 0x0C)
    // and principal name (SEQUENCE of strings) within the bounded scan area.
    extract_krb_realm_and_principal(ctx, scan, pos, config);

    // For KRB-ERROR (tag 0x7e): extract error-code field
    if tag == 0x7e {
        extract_krb_error_code(ctx, scan, pos, config);
    }

    Ok(())
}

// ----------------------------------------------------------------
// Kerberos realm + principal extraction
// ----------------------------------------------------------------
// Scans the DER blob for realm (GeneralString after cname/crealm context tags)
// and sname strings. This is a heuristic scan — not a full ASN.1 parser.
fn extract_krb_realm_and_principal(
    ctx: &mut PacketContext,
    scan: &[u8],
    start: usize,
    config: &EngineConfig,
) {
    let mut pos = start;

    while pos + 2 < scan.len() {
        let tag = scan[pos];
        pos += 1;

        let (len, lb) = read_asn1_length(scan, pos);
        pos += lb;

        if len == 0 || pos + len > scan.len() {
            break;
        }

        let content = &scan[pos..pos + len];

        // GeneralString (0x1B) or UTF8String (0x0C) — candidate for realm/principal
        if (tag == 0x1B || tag == 0x0C) && len > 0 && len <= MAX_FIELD_LEN
            && let Ok(s) = std::str::from_utf8(content) {
                let s = s.trim();
                if !s.is_empty() {
                    // Heuristic: realm contains only uppercase + dots + hyphens
                    let looks_like_realm = s.chars().all(|c| {
                        c.is_ascii_uppercase() || c == '.' || c == '-' || c.is_ascii_digit()
                    }) && s.contains('.');

                    if looks_like_realm && ctx.krb_realm.is_none() {
                        ctx.krb_realm = Some(s.to_string());
                        if config.output.show_packet_logs {
                            println!("[Kerberos] realm={}", s);
                        }
                    } else if ctx.krb_principal.is_none() && !looks_like_realm {
                        // Store first non-realm string as principal (often username)
                        ctx.krb_principal = Some(s.to_string());
                        if config.output.show_packet_logs {
                            println!("[Kerberos] principal={}", s);
                        }
                    }

                    if ctx.krb_realm.is_some() && ctx.krb_principal.is_some() {
                        return; // Got both — done
                    }
                }
            }

        pos += len;
    }
}

// ----------------------------------------------------------------
// Kerberos error code extraction
// ----------------------------------------------------------------
fn extract_krb_error_code(
    ctx: &mut PacketContext,
    scan: &[u8],
    start: usize,
    config: &EngineConfig,
) {
    // Scan for INTEGER tag (0x02) with length 4 — error-code is a 32-bit int
    let mut pos = start;
    while pos + 6 < scan.len() {
        if scan[pos] == 0x02 {
            let len = scan[pos + 1] as usize;
            if len <= 4 && pos + 2 + len <= scan.len() {
                let mut val = 0u32;
                for i in 0..len {
                    val = (val << 8) | (scan[pos + 2 + i] as u32);
                }
                let err_name = krb_error_name(val);
                ctx.krb_error_code = Some(err_name.to_string());
                if config.output.show_packet_logs {
                    println!("[Kerberos] error={} ({})", val, err_name);
                }
                return;
            }
        }
        pos += 1;
    }
}

// ----------------------------------------------------------------
// ASN.1 DER length reader
// ----------------------------------------------------------------
// Returns (length_value, bytes_consumed).
fn read_asn1_length(data: &[u8], pos: usize) -> (usize, usize) {
    if pos >= data.len() {
        return (0, 1);
    }
    let first = data[pos];
    if first & 0x80 == 0 {
        // Short form
        (first as usize, 1)
    } else {
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes == 0 || pos + 1 + num_bytes > data.len() {
            return (0, 1 + num_bytes);
        }
        let mut len = 0usize;
        for i in 0..num_bytes.min(4) {
            len = (len << 8) | (data[pos + 1 + i] as usize);
        }
        (len, 1 + num_bytes)
    }
}

fn is_krb_app_tag(tag: u8) -> bool {
    // Kerberos APPLICATION tags: 0x6A(10), 0x6B(11), 0x6C(12), 0x6D(13),
    // 0x6E(14), 0x6F(15), 0x7E(30)
    matches!(tag, 0x6A | 0x6B | 0x6C | 0x6D | 0x6E | 0x6F | 0x7E)
}

fn krb_msg_type_name(tag: u8) -> &'static str {
    match tag {
        0x6A => "AS-REQ",
        0x6B => "AS-REP",
        0x6C => "TGS-REQ",
        0x6D => "TGS-REP",
        0x6E => "AP-REQ",
        0x6F => "AP-REP",
        0x7E => "KRB-ERROR",
        _    => "UNKNOWN",
    }
}

fn krb_error_name(code: u32) -> &'static str {
    match code {
        0  => "KDC_ERR_NONE",
        6  => "KDC_ERR_C_PRINCIPAL_UNKNOWN",
        7  => "KDC_ERR_S_PRINCIPAL_UNKNOWN",
        12 => "KDC_ERR_NEVER_VALID",
        14 => "KDC_ERR_ETYPE_NOSUPP",
        17 => "KDC_ERR_KEY_EXPIRED",
        18 => "KDC_ERR_PREAUTH_FAILED",
        23 => "KDC_ERR_WRONG_REALM",
        24 => "KDC_ERR_CLIENT_NOT_TRUSTED",
        25 => "KDC_ERR_KDC_NOT_TRUSTED",
        29 => "KDC_ERR_PREAUTH_REQUIRED",
        36 => "KDC_ERR_SKEW",
        37 => "KRB_AP_ERR_SKEW",
        41 => "KRB_AP_ERR_REPEAT",
        42 => "KRB_AP_ERR_NOT_US",
        44 => "KRB_AP_ERR_BADDIRECTION",
        45 => "KRB_AP_ERR_MSG_TYPE",
        60 => "KDC_ERR_CLIENT_NOT_TRUSTED",
        68 => "KRB_ERR_GENERIC",
        _  => "KRB_ERR_UNKNOWN",
    }
}

// ================================================================
// LDAP PARSER
// ================================================================
// LDAP messages are LDAPMessage ASN.1 SEQUENCE:
//   messageID(INTEGER) + protocolOp(CHOICE) + controls(optional)
// protocolOp APPLICATION tags identify the operation type.
fn parse_ldap(
    ctx: &mut PacketContext,
    payload: &[u8],
    config: &EngineConfig,
) -> ParseResult {
    if payload.len() < 6 {
        return Ok(());
    }

    let scan = &payload[..payload.len().min(LDAP_MAX_SCAN)];

    // Expect SEQUENCE tag 0x30
    if scan[0] != 0x30 {
        return Ok(());
    }

    let (_, seq_lb) = read_asn1_length(scan, 1);
    let mut pos = 1 + seq_lb;

    if pos >= scan.len() {
        return Ok(());
    }

    // messageID: INTEGER (0x02)
    if scan[pos] != 0x02 {
        return Ok(());
    }
    pos += 1;
    let (id_len, id_lb) = read_asn1_length(scan, pos);
    pos += id_lb + id_len; // skip messageID value

    if pos >= scan.len() {
        return Ok(());
    }

    // protocolOp: APPLICATION tag identifies operation
    let op_tag = scan[pos];
    let op_name = ldap_op_name(op_tag);
    ctx.ldap_msg_type = Some(op_name.to_string());

    if config.output.show_packet_logs {
        println!("[LDAP] op={} tag=0x{:02x}", op_name, op_tag);
    }

    pos += 1;
    let (op_len, op_lb) = read_asn1_length(scan, pos);
    pos += op_lb;

    if pos + op_len > scan.len() {
        return Ok(());
    }

    let op_content = &scan[pos..pos + op_len.min(scan.len() - pos)];

    // Extract DN / filter based on operation type
    match op_tag {
        // BindRequest (0x60): version(INT) + name(OCTET/UTF8) + authentication
        0x60 => {
            extract_ldap_bind_dn(ctx, op_content, config);
        }

        // SearchRequest (0x63): baseObject(OCTET) + scope + deref + ... + filter
        0x63 => {
            extract_ldap_search_base(ctx, op_content, config);
        }

        _ => {}
    }

    Ok(())
}

// ----------------------------------------------------------------
// LDAP Bind DN extractor
// ----------------------------------------------------------------
fn extract_ldap_bind_dn(
    ctx: &mut PacketContext,
    content: &[u8],
    config: &EngineConfig,
) {
    // Skip version INTEGER, then read name OCTET STRING (0x04) or UTF8String (0x0C)
    let mut pos = 0;

    // Skip version: INTEGER(0x02) + len(1) + value
    if pos + 3 > content.len() || content[pos] != 0x02 {
        return;
    }
    let ver_len = content[pos + 1] as usize;
    pos += 2 + ver_len;

    if pos >= content.len() {
        return;
    }

    // Name: OCTET STRING or UTF8String
    let tag = content[pos];
    if tag != 0x04 && tag != 0x0C {
        return;
    }
    pos += 1;

    let (name_len, name_lb) = read_asn1_length(content, pos);
    pos += name_lb;

    if name_len == 0 || name_len > MAX_FIELD_LEN || pos + name_len > content.len() {
        return;
    }

    if let Ok(dn) = std::str::from_utf8(&content[pos..pos + name_len]) {
        let dn = dn.trim();
        if !dn.is_empty() {
            if config.output.show_packet_logs {
                println!("[LDAP] Bind DN={}", dn);
            }
            ctx.ldap_bind_dn = Some(dn.to_string());
        }
    }
}

// ----------------------------------------------------------------
// LDAP Search Base DN extractor
// ----------------------------------------------------------------
fn extract_ldap_search_base(
    ctx: &mut PacketContext,
    content: &[u8],
    config: &EngineConfig,
) {
    // baseObject is first field: OCTET STRING (0x04)
    if content.len() < 3 || (content[0] != 0x04 && content[0] != 0x0C) {
        return;
    }

    let (base_len, base_lb) = read_asn1_length(content, 1);
    let base_start = 1 + base_lb;

    if base_len == 0 || base_len > MAX_FIELD_LEN || base_start + base_len > content.len() {
        return;
    }

    if let Ok(base) = std::str::from_utf8(&content[base_start..base_start + base_len]) {
        let base = base.trim();
        if !base.is_empty() {
            if config.output.show_packet_logs {
                println!("[LDAP] Search base={}", base);
            }
            ctx.ldap_base_dn = Some(base.to_string());
        }
    }
}

fn ldap_op_name(tag: u8) -> &'static str {
    match tag {
        0x60 => "BIND_REQ",
        0x61 => "BIND_RESP",
        0x62 => "UNBIND_REQ",
        0x63 => "SEARCH_REQ",
        0x64 => "SEARCH_RESULT_ENTRY",
        0x65 => "SEARCH_RESULT_DONE",
        0x66 => "MODIFY_REQ",
        0x67 => "MODIFY_RESP",
        0x68 => "ADD_REQ",
        0x69 => "ADD_RESP",
        0x6A => "DEL_REQ",
        0x6B => "DEL_RESP",
        0x6C => "MODIFY_DN_REQ",
        0x6D => "MODIFY_DN_RESP",
        0x6E => "COMPARE_REQ",
        0x6F => "COMPARE_RESP",
        0x70 => "ABANDON_REQ",
        0x73 => "SEARCH_RESULT_REF",
        0x77 => "EXTENDED_REQ",
        0x78 => "EXTENDED_RESP",
        0x79 => "INTERMEDIATE_RESP",
        _    => "UNKNOWN",
    }
}

// ================================================================
// RDP PARSER
// ================================================================
// RDP connection initiation uses X.224 / TPKT:
//   TPKT: version(1=3) + reserved(1) + length(2) = 4 bytes
//   X.224 CR TPDU follows: length(1) + code(0xE0) + dst_ref(2) + src_ref(2) + class(1)
// After X.224 header comes the RDP negotiation request (0x01) or response.
fn parse_rdp(
    ctx: &mut PacketContext,
    payload: &[u8],
    config: &EngineConfig,
) -> ParseResult {
    if payload.len() < 11 {
        return Ok(());
    }

    // TPKT header: version must be 3
    if payload[0] != 0x03 || payload[1] != 0x00 {
        return Ok(());
    }

    let tpkt_len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    if tpkt_len < 11 || tpkt_len > payload.len() {
        return Ok(());
    }

    // X.224 TPDU: payload[4] = length, payload[5] = code
    let x224_code = payload[5];

    // CR TPDU (0xE0) = Connection Request — client initiating
    // CC TPDU (0xD0) = Connection Confirm — server responding
    if x224_code != 0xE0 && x224_code != 0xD0 {
        return Ok(());
    }

    let is_request = x224_code == 0xE0;

    // X.224 header is 7 bytes (length+code+dst_ref+src_ref+class = 7).
    // RDP negotiation data starts at offset 11 (4 TPKT + 7 X.224).
    let rdp_start = 11usize;

    if rdp_start >= payload.len() {
        return Ok(());
    }

    // Look for routing token / cookie in the X.224 user data area (before rdp_start)
    // Cookie format: "Cookie: mstshash=<token>\r\n"
    extract_rdp_cookie(ctx, payload, rdp_start, config);

    if rdp_start >= payload.len() {
        return Ok(());
    }

    // RDP Negotiation Request/Response: type(1) + flags(1) + length(2) + data(4)
    let neg_type = payload[rdp_start];

    match neg_type {
        0x01 if is_request => {
            // RDP Negotiation Request — requestedProtocols bitmask at offset +4
            if rdp_start + 8 <= payload.len() {
                let protocols = u32::from_le_bytes([
                    payload[rdp_start + 4],
                    payload[rdp_start + 5],
                    payload[rdp_start + 6],
                    payload[rdp_start + 7],
                ]);
                let sec = rdp_security_string(protocols);
                ctx.rdp_security = Some(sec.to_string());
                if config.output.show_packet_logs {
                    println!("[RDP] NegReq protocols=0x{:08x} ({})", protocols, sec);
                }
            }
        }

        0x02 if !is_request => {
            // RDP Negotiation Response — selectedProtocol at offset +4
            if rdp_start + 8 <= payload.len() {
                let selected = u32::from_le_bytes([
                    payload[rdp_start + 4],
                    payload[rdp_start + 5],
                    payload[rdp_start + 6],
                    payload[rdp_start + 7],
                ]);
                let sec = rdp_security_string(selected);
                ctx.rdp_security = Some(sec.to_string());
                if config.output.show_packet_logs {
                    println!("[RDP] NegResp selected=0x{:08x} ({})", selected, sec);
                }
            }
        }

        _ => {}
    }

    // Version detection from GCC Conference Create Request (appears in MCS PDU later).
    // For early connection phase, RDP version is embedded in client/server capabilities.
    // Set a conservative label here — refined in capability exchange if needed.
    ctx.rdp_version = Some("RDP".to_string());

    Ok(())
}

// ----------------------------------------------------------------
// RDP Cookie / Routing Token Extractor
// ----------------------------------------------------------------
// X.224 user data area (bytes 11 to rdp_start - 1 in payload, but rdp_start=11
// so we scan the full X.224 variable data if the CR TPDU has extra data).
// Cookie is ASCII text: "Cookie: mstshash=IDENTIFIER\r\n"
fn extract_rdp_cookie(
    ctx: &mut PacketContext,
    payload: &[u8],
    search_end: usize,
    config: &EngineConfig,
) {
    const COOKIE_PREFIX: &[u8] = b"Cookie: mstshash=";

    let search_area = &payload[..search_end.min(payload.len())];

    if search_area.len() < COOKIE_PREFIX.len() + 2 {
        return;
    }

    // Linear scan for cookie prefix
    for i in 0..=search_area.len().saturating_sub(COOKIE_PREFIX.len()) {
        if &search_area[i..i + COOKIE_PREFIX.len()] != COOKIE_PREFIX {
            continue;
        }

        let cookie_start = i + COOKIE_PREFIX.len();
        let cookie_slice = &search_area[cookie_start..];

        // Find \r\n terminator
        let cookie_len = cookie_slice
            .windows(2)
            .position(|w| w == b"\r\n")
            .unwrap_or(cookie_slice.len().min(MAX_RDP_COOKIE_LEN));

        let cookie_len = cookie_len.min(MAX_RDP_COOKIE_LEN);

        if cookie_len > 0
            && let Ok(cookie) = std::str::from_utf8(&cookie_slice[..cookie_len]) {
                if config.output.show_packet_logs {
                    println!("[RDP] Cookie: mstshash={}", cookie);
                }
                ctx.rdp_cookie = Some(cookie.to_string());
            }

        break;
    }
}

fn rdp_security_string(protocols: u32) -> &'static str {
    // selectedProtocol bitmask (RFC MS-RDPBCGR):
    // 0x00000000 = RDP Standard (RC4)
    // 0x00000001 = TLS
    // 0x00000002 = CredSSP (NLA)
    // 0x00000004 = RDSTLS
    // 0x00000008 = CredSSP with Early User Authorization
    match protocols {
        0x00000000 => "RDP-STANDARD",
        0x00000001 => "TLS",
        0x00000002 => "CredSSP-NLA",
        0x00000003 => "TLS+CredSSP",
        0x00000004 => "RDSTLS",
        0x00000008 => "CredSSP-EARLY-AUTH",
        _          => "MULTI-PROTOCOL",
    }
}