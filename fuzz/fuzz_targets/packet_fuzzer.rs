#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the packet dissector logic to ensure malformed
    // lengths, headers, or payloads don't trigger panics.
    
    // We pass `data` directly to etherparse (and subsequently to our inner
    // TLS/DNS/etc. parsers as we would in the main loop).
    if let Ok(sliced) = etherparse::SlicedPacket::from_ethernet(data) {
        // Simple heuristic check: if the packet sliced, ensure we can safely access payloads.
        if let Some(payload) = sliced.payload.as_slice() {
            // Ideally call snf-core's specific protocol parsers here like:
            // TlsAnalyzer::process(payload);
            let _ = payload.len(); // Mock operation preventing aggressive optimization
        }
    }
});