// src/analyzers/smb.rs
//
// SMB protocol analyzer (SMB1, SMB2, SMB3).
//
// Phase 15F additions:
//   - SMB2/3 dialect detection from NEGOTIATE response:
//     DialectRevision field (offset 4 of response body) mapped to
//     ctx.smb_dialect ("SMB2.0","SMB2.1","SMB3.0","SMB3.0.2","SMB3.1.1").
//   - Share enumeration detection: TREE_CONNECT request path extracted
//     into ctx.smb_share_path (e.g. "\\\\server\\IPC$", "\\\\server\\C$").
//     Administrative share access ($) sets ctx.smb_admin_share = true.
//   - Pass-the-hash indicator: SESSION_SETUP with NTLMSSP_AUTH blob
//     containing NtChallengeResponse of exactly 24 bytes (LM/NTLMv1 hash)
//     OR presence of NTLMv2 blob sets ctx.smb_pth_indicator = true.
//     This is a heuristic — definitive confirmation requires full NTLM decode.
//   - SMB3 encryption detection: SMB2 flags bit 4 (ENCRYPTED) set in
//     any frame sets ctx.smb_encrypted = true.
//
// Phase 2 (preserved): ParseResult, all bounds checks, static command/status tables.

use crate::core::packet_context::PacketContext;
use crate::config::engine_config::EngineConfig;
use crate::core::parse_error::{ParseResult, SnfParseError};

/// SMB TCP ports: 445 direct, 139 NetBIOS Session Service.
const SMB_PORT_DIRECT:  u16 = 445;
const SMB_PORT_NETBIOS: u16 = 139;

/// SMB1 protocol identifier: "\xFFSMB"
const SMB1_MAGIC: [u8; 4] = [0xFF, 0x53, 0x4D, 0x42];

/// SMB2/3 protocol identifier: "\xFESMB"
const SMB2_MAGIC: [u8; 4] = [0xFE, 0x53, 0x4D, 0x42];

/// NetBIOS Session Service header size: type(1) + length(3) = 4 bytes.
const NETBIOS_HEADER_LEN: usize = 4;

/// SMB1 fixed header minimum size.
const SMB1_MIN_LEN: usize = 32;

/// SMB2 fixed header size: 64 bytes.
const SMB2_HEADER_LEN: usize = 64;

/// SMB2 FLAGS field bit 4 — ENCRYPTED (SMB3 transform header follows).
const SMB2_FLAGS_ENCRYPTED: u32 = 0x00000004;

/// NTLMSSP signature bytes (8 bytes).
const NTLMSSP_SIG: &[u8] = b"NTLMSSP\x00";

/// NTLMSSP AUTHENTICATE message type value (little-endian u32 = 3).
const NTLMSSP_AUTH_TYPE: u32 = 3;

/// Max bytes to scan in SESSION_SETUP body for NTLMSSP blob.
const MAX_NTLM_SCAN: usize = 512;

/// Max share path length to store.
const MAX_SHARE_PATH_LEN: usize = 256;

pub fn analyze(
    ctx: &mut PacketContext,
    payload: &[u8],
    config: &EngineConfig,
) -> ParseResult {
    if ctx.protocol != "TCP" {
        return Ok(());
    }

    let on_smb_port = ctx.src_port == SMB_PORT_DIRECT
        || ctx.dst_port == SMB_PORT_DIRECT
        || ctx.src_port == SMB_PORT_NETBIOS
        || ctx.dst_port == SMB_PORT_NETBIOS;

    if !on_smb_port {
        return Ok(());
    }

    // Reset SMB fields on entry
    ctx.smb_command = None;
    ctx.smb_version = None;
    ctx.smb_status  = None;
    ctx.smb_dialect = None;
    ctx.smb_share_path = None;
    ctx.smb_admin_share = false;
    ctx.smb_pth_indicator = false;
    ctx.smb_encrypted = false;

    if payload.len() < NETBIOS_HEADER_LEN + 4 {
        return Ok(());
    }

    // ---------------- NETBIOS SESSION SERVICE HEADER ----------------
    let nb_type = payload[0];
    if nb_type != 0x00 {
        return Ok(()); // Not a Session Message
    }

    let nb_len = ((payload[1] as usize) << 16)
        | ((payload[2] as usize) << 8)
        | (payload[3] as usize);

    if nb_len == 0 {
        return Ok(()); // Keepalive
    }

    let smb_start = NETBIOS_HEADER_LEN;

    if smb_start + 4 > payload.len() {
        return Err(SnfParseError::new(
            "SMB",
            format!("NetBIOS payload truncated: nb_len={} available={}", nb_len, payload.len() - smb_start),
            smb_start,
        ));
    }

    let magic = &payload[smb_start..smb_start + 4];

    if magic == SMB1_MAGIC {
        return parse_smb1(ctx, payload, smb_start, config);
    }

    if magic == SMB2_MAGIC {
        return parse_smb2(ctx, payload, smb_start, config);
    }

    Ok(())
}

// ----------------------------------------------------------------
// SMB1 PARSER
// ----------------------------------------------------------------
fn parse_smb1(
    ctx: &mut PacketContext,
    payload: &[u8],
    smb_start: usize,
    config: &EngineConfig,
) -> ParseResult {
    if smb_start + SMB1_MIN_LEN > payload.len() {
        return Err(SnfParseError::new(
            "SMB",
            format!("SMB1 header truncated at offset {}", smb_start),
            smb_start,
        ));
    }

    let command = payload[smb_start + 4];

    let status = u32::from_le_bytes([
        payload[smb_start + 5],
        payload[smb_start + 6],
        payload[smb_start + 7],
        payload[smb_start + 8],
    ]);

    let command_name = smb1_command_name(command);
    let status_name  = nt_status_name(status);

    if config.output.show_packet_logs {
        println!("SMB1 command={} (0x{:02x}) status={}", command_name, command, status_name);
    }

    ctx.smb_version = Some("SMB1".to_string());
    ctx.smb_command = Some(command_name.to_string());
    ctx.smb_status  = Some(status_name.to_string());

    Ok(())
}

// ----------------------------------------------------------------
// SMB2/3 PARSER
// ----------------------------------------------------------------
// SMB2 fixed header (64 bytes after NetBIOS):
//   magic(4) + structure_size(2) + credit_charge(2) + status(4) +
//   command(2) + credits(2) + flags(4) + next_command(4) +
//   message_id(8) + reserved(4) + tree_id(4) + session_id(8) +
//   signature(16)
fn parse_smb2(
    ctx: &mut PacketContext,
    payload: &[u8],
    smb_start: usize,
    config: &EngineConfig,
) -> ParseResult {
    if smb_start + SMB2_HEADER_LEN > payload.len() {
        return Err(SnfParseError::new(
            "SMB",
            format!("SMB2 header truncated at offset {}", smb_start),
            smb_start,
        ));
    }

    // NT status: bytes 8–11 (little-endian u32)
    let status = u32::from_le_bytes([
        payload[smb_start + 8],
        payload[smb_start + 9],
        payload[smb_start + 10],
        payload[smb_start + 11],
    ]);

    // Command: bytes 12–13 (little-endian u16)
    let command = u16::from_le_bytes([
        payload[smb_start + 12],
        payload[smb_start + 13],
    ]);

    // Flags: bytes 16–19 — bit 0 = response, bit 2 = encrypted (SMB3)
    let flags = u32::from_le_bytes([
        payload[smb_start + 16],
        payload[smb_start + 17],
        payload[smb_start + 18],
        payload[smb_start + 19],
    ]);
    let is_response = (flags & 0x00000001) != 0;

    // Phase 15F: detect SMB3 encryption
    if (flags & SMB2_FLAGS_ENCRYPTED) != 0 {
        ctx.smb_encrypted = true;
    }

    let command_name = smb2_command_name(command);
    let status_name  = nt_status_name(status);

    if config.output.show_packet_logs {
        println!(
            "SMB2 command={} (0x{:04x}) status={} is_response={} encrypted={}",
            command_name, command, status_name, is_response, ctx.smb_encrypted
        );
    }

    // SMB body starts at smb_start + 64
    let body_start = smb_start + SMB2_HEADER_LEN;

    // Phase 15F: per-command body parsing
    match command {
        // NEGOTIATE (0x0000) response — contains DialectRevision
        0x0000 if is_response => {
            parse_smb2_negotiate_response(ctx, payload, body_start, config);
            ctx.smb_version = Some("SMB2/3".to_string());
        }

        // SESSION_SETUP (0x0001) — detect pass-the-hash via NTLMSSP
        0x0001 if !is_response => {
            parse_smb2_session_setup(ctx, payload, body_start, config);
            ctx.smb_version = Some("SMB2".to_string());
        }

        // TREE_CONNECT (0x0003) request — extract share path
        0x0003 if !is_response => {
            parse_smb2_tree_connect(ctx, payload, body_start, config);
            ctx.smb_version = Some("SMB2".to_string());
        }

        _ => {
            ctx.smb_version = Some(if is_response && command == 0 {
                "SMB2/3".to_string()
            } else {
                "SMB2".to_string()
            });
        }
    }

    ctx.smb_command = Some(command_name.to_string());
    ctx.smb_status  = Some(status_name.to_string());

    Ok(())
}

// ----------------------------------------------------------------
// Phase 15F: NEGOTIATE RESPONSE — Dialect Detection
// ----------------------------------------------------------------
// NEGOTIATE response body layout (structure_size=65):
//   structure_size(2) + security_mode(2) + dialect_revision(2) + ...
fn parse_smb2_negotiate_response(
    ctx: &mut PacketContext,
    payload: &[u8],
    body_start: usize,
    config: &EngineConfig,
) {
    // Need at least structure_size(2) + security_mode(2) + dialect_revision(2) = 6 bytes
    if body_start + 6 > payload.len() {
        return;
    }

    let dialect = u16::from_le_bytes([payload[body_start + 4], payload[body_start + 5]]);

    let dialect_str = match dialect {
        0x0202 => "SMB2.0",
        0x0210 => "SMB2.1",
        0x0300 => "SMB3.0",
        0x0302 => "SMB3.0.2",
        0x0311 => "SMB3.1.1",
        0x02FF => "SMB2-wildcard", // Indicates multi-protocol negotiate
        _      => "SMB2-unknown",
    };

    ctx.smb_dialect = Some(dialect_str.to_string());

    if config.output.show_packet_logs {
        println!("[SMB] NEGOTIATE dialect: {} (0x{:04x})", dialect_str, dialect);
    }
}

// ----------------------------------------------------------------
// Phase 15F: SESSION_SETUP REQUEST — Pass-the-Hash Detection
// ----------------------------------------------------------------
// SESSION_SETUP request body layout:
//   structure_size(2) + flags(1) + security_mode(1) + capabilities(4) +
//   channel(4) + security_buffer_offset(2) + security_buffer_length(2) +
//   previous_session_id(8) + security_blob(variable)
//
// Pass-the-hash heuristic: NTLMSSP AUTHENTICATE message with
// NTChallengeResponseLen == 24 (NTLMv1) or NTChallengeResponseLen > 24
// and MessageType == 3 (AUTHENTICATE).
fn parse_smb2_session_setup(
    ctx: &mut PacketContext,
    payload: &[u8],
    body_start: usize,
    config: &EngineConfig,
) {
    // structure_size(2) + flags(1) + security_mode(1) + capabilities(4) +
    // channel(4) + sec_buf_offset(2) + sec_buf_len(2) + prev_session_id(8) = 24 bytes
    if body_start + 24 > payload.len() {
        return;
    }

    let sec_buf_offset = u16::from_le_bytes([
        payload[body_start + 12],
        payload[body_start + 13],
    ]) as usize;

    let sec_buf_len = u16::from_le_bytes([
        payload[body_start + 14],
        payload[body_start + 15],
    ]) as usize;

    // sec_buf_offset is relative to start of SMB2 header (smb_start),
    // but body_start = smb_start + 64. Adjust: absolute = smb_start + sec_buf_offset.
    // Simpler: the offset is from start of the SMB2 message (after NetBIOS).
    let smb_start = body_start.saturating_sub(SMB2_HEADER_LEN);
    let blob_start = smb_start + sec_buf_offset;

    if blob_start + sec_buf_len > payload.len() || sec_buf_len == 0 {
        return;
    }

    let scan_len = sec_buf_len.min(MAX_NTLM_SCAN);
    let blob = &payload[blob_start..blob_start + scan_len];

    // Search for NTLMSSP\x00 signature within the blob
    if blob.len() < NTLMSSP_SIG.len() + 8 {
        return;
    }

    for i in 0..=(blob.len().saturating_sub(NTLMSSP_SIG.len() + 8)) {
        if &blob[i..i + NTLMSSP_SIG.len()] != NTLMSSP_SIG {
            continue;
        }

        // Found NTLMSSP signature — read MessageType (4 bytes LE after signature)
        let type_start = i + NTLMSSP_SIG.len();
        if type_start + 4 > blob.len() {
            break;
        }

        let msg_type = u32::from_le_bytes([
            blob[type_start],
            blob[type_start + 1],
            blob[type_start + 2],
            blob[type_start + 3],
        ]);

        if msg_type != NTLMSSP_AUTH_TYPE {
            break; // Not AUTHENTICATE message
        }

        // AUTHENTICATE layout after MessageType(4):
        //   LmChallengeResponseLen(2) + LmChallengeResponseMaxLen(2) +
        //   LmChallengeResponseBufferOffset(4) +
        //   NtChallengeResponseLen(2) + NtChallengeResponseMaxLen(2) + ...
        let nt_len_offset = type_start + 4 + 8; // skip LM fields
        if nt_len_offset + 2 > blob.len() {
            break;
        }

        let nt_resp_len = u16::from_le_bytes([blob[nt_len_offset], blob[nt_len_offset + 1]]);

        // NTLMv1 hash = exactly 24 bytes. Pass-the-hash typically uses NTLMv1.
        // NTLMv2 responses are > 24 bytes but can also be used for PtH.
        // Flag both as a PtH indicator for analyst review.
        if nt_resp_len == 24 || nt_resp_len > 24 {
            ctx.smb_pth_indicator = true;
            if config.output.show_packet_logs {
                println!("[SMB] Pass-the-hash indicator: NTLMSSP AUTH NtRespLen={}", nt_resp_len);
            }
        }

        break;
    }
}

// ----------------------------------------------------------------
// Phase 15F: TREE_CONNECT REQUEST — Share Path Extraction
// ----------------------------------------------------------------
// TREE_CONNECT request body:
//   structure_size(2) + reserved(2) + path_offset(2) + path_length(2) +
//   path(variable, UTF-16LE)
fn parse_smb2_tree_connect(
    ctx: &mut PacketContext,
    payload: &[u8],
    body_start: usize,
    config: &EngineConfig,
) {
    if body_start + 8 > payload.len() {
        return;
    }

    let path_offset = u16::from_le_bytes([payload[body_start + 4], payload[body_start + 5]]) as usize;
    let path_length = u16::from_le_bytes([payload[body_start + 6], payload[body_start + 7]]) as usize;

    if path_length == 0 || path_length > MAX_SHARE_PATH_LEN * 2 {
        return; // path_length is in bytes; UTF-16LE = 2 bytes/char
    }

    // path_offset is from start of SMB2 message header
    let smb_start = body_start.saturating_sub(SMB2_HEADER_LEN);
    let path_start = smb_start + path_offset;

    if path_start + path_length > payload.len() {
        return;
    }

    // Decode UTF-16LE share path
    let utf16_bytes = &payload[path_start..path_start + path_length];
    let char_count = path_length / 2;
    let mut share_path = String::with_capacity(char_count.min(MAX_SHARE_PATH_LEN));

    for i in 0..char_count.min(MAX_SHARE_PATH_LEN) {
        let offset = i * 2;
        if offset + 2 > utf16_bytes.len() {
            break;
        }
        let codeunit = u16::from_le_bytes([utf16_bytes[offset], utf16_bytes[offset + 1]]);
        // Only store printable ASCII — reject surrogate pairs and non-ASCII
        if codeunit > 0 && codeunit < 0x80 {
            share_path.push(codeunit as u8 as char);
        } else if codeunit == 0 {
            break; // Null terminator
        } else {
            share_path.push('?'); // Non-ASCII in share path — sanitize
        }
    }

    if !share_path.is_empty() {
        // Detect administrative shares: path ends with $ (e.g. IPC$, C$, ADMIN$)
        if share_path.ends_with('$') {
            ctx.smb_admin_share = true;
        }

        if config.output.show_packet_logs {
            println!("[SMB] TREE_CONNECT path={} admin={}", share_path, ctx.smb_admin_share);
        }

        ctx.smb_share_path = Some(share_path);
    }
}

// ----------------------------------------------------------------
// SMB1 COMMAND TABLE
// ----------------------------------------------------------------
fn smb1_command_name(cmd: u8) -> &'static str {
    match cmd {
        0x00 => "CREATE_DIRECTORY",
        0x01 => "DELETE_DIRECTORY",
        0x02 => "OPEN",
        0x03 => "CREATE",
        0x04 => "CLOSE",
        0x05 => "FLUSH",
        0x06 => "DELETE",
        0x07 => "RENAME",
        0x08 => "QUERY_INFORMATION",
        0x09 => "SET_INFORMATION",
        0x0A => "READ",
        0x0B => "WRITE",
        0x0C => "LOCK_BYTE_RANGE",
        0x0D => "UNLOCK_BYTE_RANGE",
        0x0E => "CREATE_TEMPORARY",
        0x0F => "CREATE_NEW",
        0x10 => "CHECK_DIRECTORY",
        0x11 => "PROCESS_EXIT",
        0x12 => "SEEK",
        0x13 => "LOCK_AND_READ",
        0x14 => "WRITE_AND_UNLOCK",
        0x1A => "READ_RAW",
        0x1D => "WRITE_RAW",
        0x22 => "SET_INFORMATION2",
        0x23 => "QUERY_INFORMATION2",
        0x24 => "LOCKING_ANDX",
        0x25 => "TRANSACTION",
        0x27 => "IOCTL",
        0x2B => "ECHO",
        0x2D => "OPEN_ANDX",
        0x2E => "READ_ANDX",
        0x2F => "WRITE_ANDX",
        0x32 => "TRANSACTION2",
        0x34 => "FIND_CLOSE2",
        0x70 => "TREE_CONNECT",
        0x71 => "TREE_DISCONNECT",
        0x72 => "NEGOTIATE",
        0x73 => "SESSION_SETUP_ANDX",
        0x74 => "LOGOFF_ANDX",
        0x75 => "TREE_CONNECT_ANDX",
        0xA0 => "NT_TRANSACT",
        0xA2 => "NT_CREATE_ANDX",
        0xA4 => "NT_CANCEL",
        0xA5 => "NT_RENAME",
        0xFF => "NO_ANDX_COMMAND",
        _    => "UNKNOWN",
    }
}

// ----------------------------------------------------------------
// SMB2 COMMAND TABLE
// ----------------------------------------------------------------
fn smb2_command_name(cmd: u16) -> &'static str {
    match cmd {
        0x0000 => "NEGOTIATE",
        0x0001 => "SESSION_SETUP",
        0x0002 => "LOGOFF",
        0x0003 => "TREE_CONNECT",
        0x0004 => "TREE_DISCONNECT",
        0x0005 => "CREATE",
        0x0006 => "CLOSE",
        0x0007 => "FLUSH",
        0x0008 => "READ",
        0x0009 => "WRITE",
        0x000A => "LOCK",
        0x000B => "IOCTL",
        0x000C => "CANCEL",
        0x000D => "ECHO",
        0x000E => "QUERY_DIRECTORY",
        0x000F => "CHANGE_NOTIFY",
        0x0010 => "QUERY_INFO",
        0x0011 => "SET_INFO",
        0x0012 => "OPLOCK_BREAK",
        _      => "UNKNOWN",
    }
}

// ----------------------------------------------------------------
// NT STATUS CODE TABLE
// ----------------------------------------------------------------
fn nt_status_name(status: u32) -> &'static str {
    match status {
        0x00000000 => "STATUS_SUCCESS",
        0x00000103 => "STATUS_PENDING",
        0x80000005 => "STATUS_BUFFER_OVERFLOW",
        0x80000006 => "STATUS_NO_MORE_FILES",
        0xC0000001 => "STATUS_UNSUCCESSFUL",
        0xC0000002 => "STATUS_NOT_IMPLEMENTED",
        0xC0000005 => "STATUS_ACCESS_VIOLATION",
        0xC0000008 => "STATUS_INVALID_HANDLE",
        0xC000000D => "STATUS_INVALID_PARAMETER",
        0xC000000F => "STATUS_NO_SUCH_FILE",
        0xC0000011 => "STATUS_END_OF_FILE",
        0xC0000016 => "STATUS_MORE_PROCESSING_REQUIRED",
        0xC0000017 => "STATUS_NO_MEMORY",
        0xC0000022 => "STATUS_ACCESS_DENIED",
        0xC0000023 => "STATUS_BUFFER_TOO_SMALL",
        0xC0000034 => "STATUS_OBJECT_NAME_NOT_FOUND",
        0xC0000035 => "STATUS_OBJECT_NAME_COLLISION",
        0xC000006D => "STATUS_LOGON_FAILURE",
        0xC000006E => "STATUS_ACCOUNT_RESTRICTION",
        0xC000006F => "STATUS_INVALID_LOGON_HOURS",
        0xC0000070 => "STATUS_INVALID_WORKSTATION",
        0xC0000071 => "STATUS_PASSWORD_EXPIRED",
        0xC0000072 => "STATUS_ACCOUNT_DISABLED",
        0xC000009A => "STATUS_INSUFFICIENT_RESOURCES",
        0xC00000BB => "STATUS_NOT_SUPPORTED",
        0xC00000CC => "STATUS_BAD_NETWORK_NAME",
        0xC0000101 => "STATUS_DIRECTORY_NOT_EMPTY",
        0xC0000103 => "STATUS_NOT_A_DIRECTORY",
        0xC0000120 => "STATUS_CANCELLED",
        0xC0000121 => "STATUS_CANNOT_DELETE",
        0xC0000193 => "STATUS_ACCOUNT_EXPIRED",
        0xC0000224 => "STATUS_PASSWORD_MUST_CHANGE",
        0xC0000225 => "STATUS_NOT_FOUND",
        0xC0000234 => "STATUS_ACCOUNT_LOCKED_OUT",
        0xC000035C => "STATUS_NETWORK_SESSION_EXPIRED",
        _          => "STATUS_UNKNOWN",
    }
}