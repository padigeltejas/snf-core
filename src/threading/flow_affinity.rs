// src/threading/flow_affinity.rs
//
// Flow-affinity routing for the capture thread.
//
// ── The Problem Round-Robin Routing Causes ────────────────────────────────────
//
//   With round-robin (packet_seq % N), consecutive packets from the same TCP
//   connection can go to different workers. Worker A sees SYN + data packets,
//   Worker B sees ACK + more data. Each worker has its own FlowTable, so:
//     - TCP reassembly buffer is split — TLS handshake parsing fails
//     - flow.packets is wrong on both workers
//     - Beacon detection has incomplete inter-packet timing
//     - JA3/JA4 only sees the ClientHello (SYN+data) but not the ServerHello
//
//   This is not just a statistics problem — it is a correctness problem.
//   Flow-affinity routing MUST be in place before the multi-threaded path
//   can be used for forensic-grade analysis.
//
// ── Solution: Hash the 5-Tuple ────────────────────────────────────────────────
//
//   compute_worker_for_packet() parses the IP+port 5-tuple from raw Ethernet
//   frame bytes before the packet is queued. It then hashes the 5-tuple using
//   FNV-1a and returns worker_idx = hash % num_workers.
//
//   The same 5-tuple always produces the same worker_idx — so all packets for
//   a given flow (identified by the normalised 5-tuple) always go to the same
//   worker. This is exactly the routing done by:
//     - AF_PACKET FANOUT_HASH in the Linux kernel
//     - Suricata's AF_PACKET runmode
//     - Zeek's PF_RING balanced mode
//
// ── Zero-Copy Frame Parsing ───────────────────────────────────────────────────
//
//   The capture thread parses only what is needed for routing — IP version,
//   source/destination IP, and source/destination port. It does NOT call
//   etherparse (which allocates and validates the full frame). Instead it
//   uses direct byte-offset arithmetic on the raw frame slice.
//
//   Ethernet II: dst(6) + src(6) + ethertype(2) = 14 bytes header
//   IPv4 header starts at offset 14. IHL field gives header length.
//   IPv6 header starts at offset 14. Fixed 40-byte header.
//
//   On any parse failure (frame too short, unknown ethertype, fragmented IP),
//   we fall back to packet_seq % num_workers — the packet still gets processed,
//   just not with flow affinity. This is safe: the worker's FlowTable will
//   create a new flow entry for these packets.
//
// ── Normalisation ────────────────────────────────────────────────────────────
//
//   The 5-tuple is normalised before hashing: the smaller (IP, port) pair
//   comes first. This matches normalize_flow() in flow_key.rs — a packet
//   going A→B and a packet going B→A produce the same worker_idx. This is
//   essential: both directions of a TCP connection must reach the same worker.
//
// Phase 11C addition.

// ── CONSTANTS ─────────────────────────────────────────────────────────────────

/// Ethernet II header size in bytes.
const ETH_HEADER_LEN: usize = 14;

/// EtherType for IPv4.
const ETHERTYPE_IPV4: u16 = 0x0800;

/// EtherType for IPv6.
const ETHERTYPE_IPV6: u16 = 0x86DD;

/// Minimum IPv4 header length in bytes (IHL=5, no options).
const IPV4_MIN_HEADER_LEN: usize = 20;

/// Fixed IPv6 header length in bytes.
const IPV6_HEADER_LEN: usize = 40;

/// IP protocol number for TCP.
const IP_PROTO_TCP: u8 = 6;

/// IP protocol number for UDP.
const IP_PROTO_UDP: u8 = 17;

// ── FNV-1a for routing (same algorithm as FlowKeyHasher) ──────────────────────

#[inline]
fn fnv1a_routing(data: &[u8]) -> u64 {
    const OFFSET_BASIS: u64 = 14_695_981_039_346_656_037;
    const FNV_PRIME:    u64 = 1_099_511_628_211;
    let mut hash = OFFSET_BASIS;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

// ── 5-Tuple ───────────────────────────────────────────────────────────────────

/// Normalised 5-tuple for routing purposes.
/// "Normalised" means the smaller (ip, port) is always in the first position —
/// matching normalize_flow() in flow_key.rs.
struct FiveTuple {
    ip1:   [u8; 16],
    port1: u16,
    ip2:   [u8; 16],
    port2: u16,
    proto: u8,
    /// Reserved for Phase 14 IPv6 extension header handling.
    #[allow(dead_code)]
    is_v6: bool,
}

impl FiveTuple {
    /// Hash this 5-tuple for worker routing.
    #[inline]
    fn hash(&self) -> u64 {
        // Build a flat byte array of the canonical fields for hashing.
        // Layout: ip1(16) + port1(2) + ip2(16) + port2(2) + proto(1) = 37 bytes.
        let mut buf = [0u8; 37];
        buf[0..16].copy_from_slice(&self.ip1);
        buf[16..18].copy_from_slice(&self.port1.to_be_bytes());
        buf[18..34].copy_from_slice(&self.ip2);
        buf[34..36].copy_from_slice(&self.port2.to_be_bytes());
        buf[36] = self.proto;
        fnv1a_routing(&buf)
    }
}

// ── compute_worker_for_packet ──────────────────────────────────────────────────

/// Compute the worker index for a raw Ethernet frame.
///
/// Parses the 5-tuple from the frame, normalises it, hashes it, and returns
/// `hash % num_workers`. All packets with the same 5-tuple always return the
/// same worker index — flow affinity guaranteed.
///
/// Falls back to `packet_seq % num_workers` on any parse error (malformed
/// frame, non-IP, fragmented IP, unknown ethertype).
#[inline]
pub fn compute_worker_for_packet(
    frame:       &[u8],
    packet_seq:  u64,
    num_workers: usize,
) -> usize {
    match extract_five_tuple(frame) {
        Some(tuple) => (tuple.hash() as usize) % num_workers,
        None        => (packet_seq as usize)   % num_workers,
    }
}

/// Extract and normalise the 5-tuple from a raw Ethernet frame.
/// Returns None if the frame is too short, non-IP, or fragmented.
fn extract_five_tuple(frame: &[u8]) -> Option<FiveTuple> {
    // Need at least the Ethernet header.
    if frame.len() < ETH_HEADER_LEN + 1 {
        return None;
    }

    // EtherType is at bytes 12–13.
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);

    match ethertype {
        ETHERTYPE_IPV4 => extract_ipv4(frame),
        ETHERTYPE_IPV6 => extract_ipv6(frame),
        _              => None, // ARP, VLAN, etc — fall back to round-robin
    }
}

fn extract_ipv4(frame: &[u8]) -> Option<FiveTuple> {
    let ip_start = ETH_HEADER_LEN;

    // Need at least minimal IPv4 header.
    if frame.len() < ip_start + IPV4_MIN_HEADER_LEN {
        return None;
    }

    let ihl_bytes    = ((frame[ip_start] & 0x0F) as usize) * 4;
    let protocol     = frame[ip_start + 9];
    let src_ip_bytes = &frame[ip_start + 12 .. ip_start + 16];
    let dst_ip_bytes = &frame[ip_start + 16 .. ip_start + 20];

    // Skip fragmented packets (MF flag set OR fragment offset non-zero).
    // Fragments don't have the full transport header — can't extract ports.
    let flags_frag = u16::from_be_bytes([frame[ip_start + 6], frame[ip_start + 7]]);
    if flags_frag & 0x3FFF != 0 {
        return None; // Fragment — fall back to round-robin
    }

    let transport_start = ip_start + ihl_bytes;

    extract_ports(frame, transport_start, protocol, src_ip_bytes, dst_ip_bytes, false)
}

fn extract_ipv6(frame: &[u8]) -> Option<FiveTuple> {
    let ip_start = ETH_HEADER_LEN;

    if frame.len() < ip_start + IPV6_HEADER_LEN {
        return None;
    }

    let next_header  = frame[ip_start + 6];
    let src_ip_bytes = &frame[ip_start + 8  .. ip_start + 24];
    let dst_ip_bytes = &frame[ip_start + 24 .. ip_start + 40];

    let transport_start = ip_start + IPV6_HEADER_LEN;

    // Note: IPv6 extension headers are not walked here — we only handle
    // the common case where the transport header immediately follows.
    // Packets with extension headers fall back to round-robin (safe).
    extract_ports(frame, transport_start, next_header, src_ip_bytes, dst_ip_bytes, true)
}

fn extract_ports(
    frame:           &[u8],
    transport_start: usize,
    protocol:        u8,
    src_ip:          &[u8],
    dst_ip:          &[u8],
    is_v6:           bool,
) -> Option<FiveTuple> {
    // TCP and UDP both have src_port at +0 and dst_port at +2.
    match protocol {
        IP_PROTO_TCP | IP_PROTO_UDP => {
            if frame.len() < transport_start + 4 {
                return None;
            }
            let src_port = u16::from_be_bytes([frame[transport_start],     frame[transport_start + 1]]);
            let dst_port = u16::from_be_bytes([frame[transport_start + 2], frame[transport_start + 3]]);

            // Build 16-byte IP arrays (IPv4 in first 4 bytes, rest zero).
            let mut ip1_bytes = [0u8; 16];
            let mut ip2_bytes = [0u8; 16];
            let copy_len = src_ip.len().min(16);
            ip1_bytes[..copy_len].copy_from_slice(&src_ip[..copy_len]);
            ip2_bytes[..copy_len].copy_from_slice(&dst_ip[..copy_len]);

            // Normalise: smaller (ip, port) first.
            // Compare as raw bytes — same ordering as normalize_flow().
            let normalised = if (ip1_bytes, src_port) <= (ip2_bytes, dst_port) {
                FiveTuple {
                    ip1: ip1_bytes, port1: src_port,
                    ip2: ip2_bytes, port2: dst_port,
                    proto: protocol, is_v6,
                }
            } else {
                FiveTuple {
                    ip1: ip2_bytes, port1: dst_port,
                    ip2: ip1_bytes, port2: src_port,
                    proto: protocol, is_v6,
                }
            };

            Some(normalised)
        }
        _ => None, // ICMP, etc — fall back to round-robin
    }
}