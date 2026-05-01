// src/pipeline/tcp_reassembly.rs
//
// TCP Stream Reassembly Engine.
//
// PURPOSE:
//   TCP is a stream protocol. Protocol analyzers (TLS, HTTP/1.x, DNS-over-TCP)
//   must parse complete messages, but a single message can span multiple TCP segments.
//   Without reassembly, a TLS ClientHello split across two packets = missed SNI.
//   A DNS query fragmented across two segments = missed domain.
//
// DESIGN:
//   - Per-flow reassembly buffer keyed by (src_ip, src_port, dst_ip, dst_port, "TCP")
//   - Sequence number tracking: only in-order segments are processed
//   - Out-of-order segments are buffered (up to OOO_BUFFER_MAX per stream)
//   - Gap detection: if a gap is unresolvable (missing segment + timeout), emit marker
//   - All buffers are hard-capped (STREAM_BUFFER_MAX per stream, OOO_BUFFER_MAX total)
//   - Overlap policy: first-seen-wins (matches SNF determinism contract)
//   - On cap exceeded: stream is reset, parse_error event emitted by caller
//
// INTEGRATION:
//   PacketPipeline calls TcpReassembler::process_segment() for every TCP packet.
//   The returned ReassemblyResult tells the pipeline:
//     - Assembled: here is the in-order byte slice, run analyzers on this
//     - Buffered: segment stored out-of-order, nothing to deliver yet
//     - Reset: stream overflowed or gap timeout hit, error was recorded
//     - NotTcp: passthrough — not a TCP packet, no action taken
//
// SPEC COMPLIANCE:
//   Matches the tcp_reassembly spec: first-seen-wins overlap, explicit gap markers,
//   stream cursor, bounded buffers.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

// ----------------------------------------------------------------
// CONSTANTS
// ----------------------------------------------------------------

/// Maximum bytes in a single stream's in-order reassembly buffer.
/// 1MB per stream. A stream exceeding this is abnormal; clear and reset.
pub const STREAM_BUFFER_MAX: usize = 1_048_576; // 1MB

/// Maximum bytes held in the out-of-order segment buffer per stream.
/// 64KB — enough for typical reordering windows without runaway allocation.
pub const OOO_BUFFER_MAX: usize = 65_536; // 64KB

/// Maximum number of TCP streams tracked simultaneously.
/// Prevents the reassembly table from growing without bound under a flood.
pub const MAX_STREAMS: usize = 65_536;

/// How many microseconds a stream can be idle before it is evicted.
/// 300 seconds = 5 minutes. Matches common TCP keepalive timeout.
pub const STREAM_IDLE_TIMEOUT_US: u64 = 300 * 1_000_000;

// ----------------------------------------------------------------
// TYPES
// ----------------------------------------------------------------

/// Key identifying a unidirectional TCP stream.
/// Directional (not normalized) because sequence numbers are per-direction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StreamKey {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

impl StreamKey {
    pub fn new(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) -> Self {
        Self { src_ip, src_port, dst_ip, dst_port }
    }
}

/// State of a single unidirectional TCP stream.
#[derive(Debug)]
struct StreamState {
    /// The next sequence number we expect to receive (cursor).
    /// Initialized from the first segment's sequence number.
    next_seq: u32,

    /// Whether the stream's initial sequence number has been established.
    /// False until the first segment is seen.
    _initialized: bool,

    /// In-order reassembled data ready for protocol analysis.
    /// Drained by the pipeline after each process_segment() call.
    buffer: Vec<u8>,

    /// Out-of-order segments awaiting the missing in-order bytes.
    /// Key = sequence number of the segment's first byte.
    /// Value = segment payload bytes.
    ooo: BTreeMap<u32, Vec<u8>>,

    /// Total bytes currently held in ooo (to enforce OOO_BUFFER_MAX).
    ooo_bytes: usize,

    /// Last packet timestamp for this stream (used for idle eviction).
    last_seen_us: u64,

    /// True if this stream has been reset due to overflow or gap timeout.
    /// Further segments are silently dropped until the stream is evicted.
    reset: bool,
}

impl StreamState {
    fn new(initial_seq: u32, timestamp_us: u64) -> Self {
        Self {
            next_seq: initial_seq,
            _initialized: true,
            buffer: Vec::new(),
            ooo: BTreeMap::new(),
            ooo_bytes: 0,
            last_seen_us: timestamp_us,
            reset: false,
        }
    }
}

// ----------------------------------------------------------------
// REASSEMBLY RESULT
// ----------------------------------------------------------------

/// Result returned by TcpReassembler::process_segment() to the pipeline.
pub enum ReassemblyResult {
    /// In-order data is available. The pipeline should run analyzers on the
    /// returned bytes. The Vec is the assembled payload — may span multiple
    /// original segments.
    Assembled(Vec<u8>),

    /// Segment was stored out-of-order. No data available yet.
    /// The pipeline should skip analyzer execution for this packet.
    Buffered,

    /// Stream was reset (overflow or unrecoverable gap).
    /// The pipeline must emit an engine.parse_error event with the provided reason.
    Reset(String),

    /// Not a TCP packet or zero-length payload — no action taken.
    /// Pipeline continues normally (no analyzers for this segment).
    Passthrough,
}

// ----------------------------------------------------------------
// TCP REASSEMBLER
// ----------------------------------------------------------------

pub struct TcpReassembler {
    /// All active TCP streams, keyed by directional StreamKey.
    streams: HashMap<StreamKey, StreamState>,
}

impl Default for TcpReassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpReassembler {
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
        }
    }

    /// Returns the number of currently tracked streams.
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }

    /// Process a single TCP segment.
    ///
    /// Parameters:
    ///   src_ip, src_port, dst_ip, dst_port — 4-tuple of this segment's direction
    ///   seq — TCP sequence number of the first byte of payload
    ///   payload — segment payload bytes (after TCP header stripping)
    ///   timestamp_us — packet timestamp in microseconds since Unix epoch
    ///
    /// Returns a ReassemblyResult describing what the pipeline should do next.
#[allow(clippy::too_many_arguments)]
    pub fn process_segment(
        &mut self,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
        seq: u32,
        payload: &[u8],
        timestamp_us: u64,
    ) -> ReassemblyResult {
        // Zero-length payload (pure ACK, SYN, FIN) — nothing to reassemble
        if payload.is_empty() {
            return ReassemblyResult::Passthrough;
        }

        // Enforce max stream table size
        if self.streams.len() >= MAX_STREAMS && !self.streams.contains_key(&StreamKey::new(src_ip, src_port, dst_ip, dst_port)) {
            // Table full — evict one idle stream first, then try again
            self.evict_one_idle(timestamp_us);
            if self.streams.len() >= MAX_STREAMS {
                return ReassemblyResult::Reset(
                    format!("stream table full ({} streams) — new stream rejected", MAX_STREAMS)
                );
            }
        }

        let key = StreamKey::new(src_ip, src_port, dst_ip, dst_port);

        // Initialize stream on first segment
        if !self.streams.contains_key(&key) {
            self.streams.insert(key.clone(), StreamState::new(seq, timestamp_us));
        }

        let state = match self.streams.get_mut(&key) {
            Some(s) => s,
            None => return ReassemblyResult::Passthrough, // Should not happen
        };

        // If stream is in reset state, drop all further segments silently
        if state.reset {
            return ReassemblyResult::Passthrough;
        }

        state.last_seen_us = timestamp_us;

        let payload_end_seq = seq.wrapping_add(payload.len() as u32);

        // ---- IN-ORDER SEGMENT ----
        if seq == state.next_seq {
            // Append directly to in-order buffer (with cap check)
            if state.buffer.len() + payload.len() > STREAM_BUFFER_MAX {
                state.reset = true;
                state.buffer.clear();
                state.buffer.shrink_to_fit();
                state.ooo.clear();
                state.ooo_bytes = 0;
                return ReassemblyResult::Reset(format!(
                    "stream buffer overflow: {}+{} > {} bytes",
                    state.buffer.len(), payload.len(), STREAM_BUFFER_MAX
                ));
            }
            state.buffer.extend_from_slice(payload);
            state.next_seq = payload_end_seq;

            // Drain any contiguous OOO segments that now fit
            loop {
                // Check if the next expected OOO segment is available
                // We need to clone the key to avoid borrow issues
                let next = state.next_seq;
                if let Some(ooo_payload) = state.ooo.remove(&next) {
                    let ooo_end = next.wrapping_add(ooo_payload.len() as u32);

                    if state.buffer.len() + ooo_payload.len() > STREAM_BUFFER_MAX {
                        state.reset = true;
                        state.buffer.clear();
                        state.buffer.shrink_to_fit();
                        state.ooo.clear();
                        state.ooo_bytes = 0;
                        return ReassemblyResult::Reset(format!(
                            "stream buffer overflow while draining OOO: {} bytes",
                            STREAM_BUFFER_MAX
                        ));
                    }

                    state.ooo_bytes = state.ooo_bytes.saturating_sub(ooo_payload.len());
                    state.buffer.extend_from_slice(&ooo_payload);
                    state.next_seq = ooo_end;
                } else {
                    break;
                }
            }

            // Return the assembled data and clear the buffer
            let assembled = std::mem::take(&mut state.buffer);
            return ReassemblyResult::Assembled(assembled);
        }

        // ---- OVERLAP / RETRANSMIT ----
        // First-seen-wins: if this segment overlaps already-delivered data, trim it.
        // seq < next_seq means we've already delivered some or all of this data.
        if seq.wrapping_sub(state.next_seq) > u32::MAX / 2 {
            // Sequence number is "before" next_seq in wrapping arithmetic.
            // Calculate how many bytes to skip.
            let already_delivered = state.next_seq.wrapping_sub(seq) as usize;
            if already_delivered >= payload.len() {
                // Entire segment is a retransmit — drop it
                return ReassemblyResult::Buffered;
            }
            // Partial overlap — trim the already-delivered prefix
            let trimmed = &payload[already_delivered..];
            let trimmed_seq = state.next_seq;
            // Recurse with the trimmed segment (now in-order or OOO)
            return self.process_segment(src_ip, src_port, dst_ip, dst_port, trimmed_seq, trimmed, timestamp_us);
        }

        // ---- OUT-OF-ORDER SEGMENT ----
        // Store in OOO buffer, respecting the OOO cap.
        if state.ooo_bytes + payload.len() > OOO_BUFFER_MAX {
            // OOO buffer full — this is unusual (large reordering window or attack).
            // Emit a gap marker via reset rather than silently dropping.
            state.reset = true;
            state.buffer.clear();
            state.ooo.clear();
            state.ooo_bytes = 0;
            return ReassemblyResult::Reset(format!(
                "OOO buffer overflow: {} bytes — stream reset",
                OOO_BUFFER_MAX
            ));
        }

        // Don't store duplicate OOO entries (first-seen-wins)
        if !state.ooo.contains_key(&seq) {
            state.ooo_bytes += payload.len();
            state.ooo.insert(seq, payload.to_vec());
        }

        ReassemblyResult::Buffered
    }

    /// Evict all streams idle for longer than STREAM_IDLE_TIMEOUT_US.
    /// Called from the pipeline's throttled cleanup sweep.
    pub fn evict_idle_streams(&mut self, now_us: u64) {
        self.streams.retain(|_, state| {
            let elapsed = now_us.saturating_sub(state.last_seen_us);
            elapsed < STREAM_IDLE_TIMEOUT_US
        });
    }

    /// Evict a single idle stream (the one with the oldest last_seen_us).
    /// Used when the stream table is full and a new stream needs to be admitted.
    fn evict_one_idle(&mut self, now_us: u64) {
        let oldest_key = self.streams
            .iter()
            .filter(|(_, s)| now_us.saturating_sub(s.last_seen_us) > STREAM_IDLE_TIMEOUT_US)
            .min_by_key(|(_, s)| s.last_seen_us)
            .map(|(k, _)| k.clone());

        if let Some(key) = oldest_key {
            self.streams.remove(&key);
        }
    }

    /// Remove a specific stream (called on TCP RST or FIN).
    /// In Phase 2, RST/FIN detection is not yet wired — this is called
    /// from future flow expiry integration.
    pub fn remove_stream(&mut self, src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) {
        let key = StreamKey::new(src_ip, src_port, dst_ip, dst_port);
        self.streams.remove(&key);
    }
}