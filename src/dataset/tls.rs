// src/dataset/tls.rs
// TLS dataset utilities
// This module contains TLS metadata and lookup helpers.
// It MUST NOT perform packet parsing (that belongs in analyzers).

/// Returns human readable TLS version name
pub fn tls_version_name(version: u16) -> &'static str {
    match version {
        0x0300 => "SSL 3.0",
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        _ => "Unknown TLS Version",
    }
}

/// Returns a human readable TLS handshake type
pub fn tls_handshake_name(handshake_type: u8) -> &'static str {
    match handshake_type {
        0 => "HelloRequest",
        1 => "ClientHello",
        2 => "ServerHello",
        4 => "NewSessionTicket",
        8 => "EncryptedExtensions",
        11 => "Certificate",
        12 => "ServerKeyExchange",
        13 => "CertificateRequest",
        14 => "ServerHelloDone",
        15 => "CertificateVerify",
        16 => "ClientKeyExchange",
        20 => "Finished",
        _ => "Unknown Handshake",
    }
}

/// Returns a readable TLS content type
pub fn tls_record_type(record_type: u8) -> &'static str {
    match record_type {
        20 => "ChangeCipherSpec",
        21 => "Alert",
        22 => "Handshake",
        23 => "ApplicationData",
        24 => "Heartbeat",
        _ => "Unknown Record",
    }
}

/// Common TLS ports used in the wild
pub const TLS_PORTS: &[u16] = &[
    443,  // HTTPS
    8443, // Alternative HTTPS
    993,  // IMAPS
    995,  // POP3S
    465,  // SMTPS
];