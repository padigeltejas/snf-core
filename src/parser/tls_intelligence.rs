use crate::core::packet_context::PacketContext;
use crate::config::engine_config::EngineConfig;

pub struct TlsIntelligence;

impl TlsIntelligence {

    pub fn analyze(
        ctx: &mut PacketContext,
        payload: &[u8],
        config: &EngineConfig,
    ) {

        if !config.protocol.tls_intelligence_enabled {
            return;
        }

        if payload.len() < 5 {
            return;
        }

        // TLS record type
        let record_type = payload[0];

        // 22 = handshake
        if record_type != 22 {
            return;
        }

        let version = u16::from_be_bytes([payload[1], payload[2]]);
        ctx.tls_version = Some(Self::version_to_string(version));

        if config.output.show_packet_logs {
            println!("TLS version detected: {}", ctx.tls_version.as_ref().unwrap());
        }

        // Skip record header
        let mut pos = 5;

        if payload.len() < pos + 4 {
            return;
        }

        // handshake type
        let handshake_type = payload[pos];

        // 1 = ClientHello
        if handshake_type != 1 {
            return;
        }

        pos += 4;

        if payload.len() < pos + 34 {
            return;
        }

        // Skip client version + random
        pos += 34;

        if payload.len() < pos + 1 {
            return;
        }

        // session id
        let session_len = payload[pos] as usize;
        pos += 1 + session_len;

        if payload.len() < pos + 2 {
            return;
        }

        // cipher suites length
        let cipher_len =
            u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;

        pos += 2;

        if payload.len() < pos + cipher_len {
            return;
        }

        // extract cipher suites
        let mut ciphers = Vec::new();

        for i in (0..cipher_len).step_by(2) {
            if pos + i + 1 >= payload.len() {
                break;
            }

            let cipher = u16::from_be_bytes([
                payload[pos + i],
                payload[pos + i + 1],
            ]);

            ciphers.push(cipher);
        }

        ctx.tls_cipher_suites = ciphers.clone();

        if config.output.show_packet_logs {
            println!("TLS cipher suites detected: {:?}", ciphers);
        }

        pos += cipher_len;

        if payload.len() < pos + 1 {
            return;
        }

        // compression methods
        let comp_len = payload[pos] as usize;
        pos += 1 + comp_len;

        if payload.len() < pos + 2 {
            return;
        }

        // extensions length
        let ext_len =
            u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;

        pos += 2;

        let end = pos + ext_len;

        while pos + 4 <= end && pos + 4 <= payload.len() {

            let ext_type =
                u16::from_be_bytes([payload[pos], payload[pos + 1]]);

            let ext_size =
                u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;

            pos += 4;

            if pos + ext_size > payload.len() {
                break;
            }

            // ALPN extension
            if ext_type == 16 {

                if ext_size > 3 {

                    let proto_len = payload[pos + 2] as usize;

                    if pos + 3 + proto_len <= payload.len() {

                        let proto = String::from_utf8_lossy(
                            &payload[pos + 3..pos + 3 + proto_len],
                        );

                        ctx.tls_alpn = Some(proto.to_string());

                        if config.output.show_packet_logs {
                            println!("TLS ALPN detected: {}", proto);
                        }
                    }
                }
            }

            pos += ext_size;
        }
    }

    fn version_to_string(v: u16) -> String {
        match v {
            0x0300 => "SSL 3.0",
            0x0301 => "TLS 1.0",
            0x0302 => "TLS 1.1",
            0x0303 => "TLS 1.2",
            0x0304 => "TLS 1.3",
            _ => "Unknown",
        }
        .to_string()
    }
}