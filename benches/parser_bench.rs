use criterion::{black_box, criterion_group, criterion_main, Criterion};
use snf_core::core::packet_context::PacketContext;
use snf_core::discovery::dns_cache::DnsCache;
use snf_core::config::engine_config::EngineConfig;
use snf_core::analyzers::dns;
use std::net::{IpAddr, Ipv4Addr};

// Micro-benchmark 1: SNF DNS parser (PacketContext path)
// Proves the high-level analysis pipeline speed.
fn bench_dns_parser(c: &mut Criterion) {
    let dummy_dns_payload: &[u8] = &[
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x61,
        0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
        0x00, 0x00, 0x01, 0x00, 0x01,
    ];

    let mut dns_cache = DnsCache::new();
    let config = EngineConfig::default();

    c.bench_function("snf_dns_analyze", |b| {
        b.iter(|| {
            let mut ctx = PacketContext::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                54321,
                53,
                "udp",
                dummy_dns_payload.len(),
                123456789,
            );
            dns::analyze(
                black_box(&mut ctx),
                black_box(dummy_dns_payload),
                black_box(&mut dns_cache),
                black_box(&config),
            )
        })
    });
}

// Micro-benchmark 2: etherparse layer (raw packet ingestion path)
// Proves the capture/decode throughput before SNF analysis.
fn bench_etherparse_dns(c: &mut Criterion) {
    // Raw bytes: Ethernet + IPv4 + UDP + DNS query for www.example.com
    let packet: [u8; 73] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00, // Ethernet
        0x45, 0x00, 0x00, 0x3b, 0x1a, 0x2b, 0x00, 0x00, 0x40, 0x11, 0x42, 0xa6,
        0xc0, 0xa8, 0x01, 0x02, 0x08, 0x08, 0x08, 0x08,                                     // IPv4
        0x90, 0x38, 0x00, 0x35, 0x00, 0x27, 0xfe, 0x8c,                                     // UDP
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,             // DNS header
        0x03, 0x77, 0x77, 0x77, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x03, 0x63, 0x6f, 0x6d, 0x00,                                                        // Query: www.example.com
        0x00, 0x01, 0x00, 0x01,                                                              // QTYPE A, QCLASS IN
    ];

    c.bench_function("etherparse_dns_decode", |b| {
        b.iter(|| {
            if let Ok(value) = etherparse::SlicedPacket::from_ethernet(black_box(&packet)) {
                black_box(value);
            }
        });
    });
}

criterion_group!(benches, bench_dns_parser, bench_etherparse_dns);
criterion_main!(benches);