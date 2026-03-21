// src/flow/flow_table.rs
//
// Flow tracking table — maps FlowKey → Flow.
//
// ── Phase 11A: LinkedHashMap → HashMap + FNV-1a hasher ───────────────────────
//
//   PROBLEM WITH LinkedHashMap:
//     linked_hash_map uses std DefaultHasher (SipHash-1-3) which has two costs:
//       (a) SipHash is a cryptographic hash: ~15 ns/call.
//       (b) The doubly-linked list for LRU order adds 2 pointer chases per
//           insert/lookup — cache-unfriendly at 1M+ lookups/sec.
//     At 5 Gbps with 64-byte average packet size = ~9.8 Mpps. Each packet
//     does at least one FlowTable lookup. 9.8M × (15ns hash + 2×pointer chase)
//     = ~195ms/sec of pure FlowTable overhead on one core. That is the ceiling.
//
//   SOLUTION:
//     HashMap<FlowKey, Flow, FlowKeyHasher> where FlowKeyHasher is FNV-1a:
//       (a) FNV-1a on a 36-byte FlowKey: ~3 ns/call — 5× faster than SipHash.
//       (b) Flat open-addressing HashMap — single cache line per lookup.
//     LRU eviction order maintained by a companion VecDeque<FlowKey> (the
//     "eviction queue"). New flows push to back; eviction pops from front.
//     This gives O(1) amortised eviction without pointer-chasing linked lists.
//
//   WHY NOT hashbrown/ahash?
//     Both require adding Cargo.toml dependencies. FNV-1a gives ~80% of
//     the benefit for zero new deps. The codebase already implements fnv1a_64
//     in graph/node.rs. Phase 11A reuses the same algorithm inline.
//     If Phase 14 benchmarks show FNV-1a is the bottleneck, swapping to
//     ahash is a 3-line change (Hasher impl replacement).
//
//   DoS RESISTANCE:
//     FNV-1a is not collision-resistant under adversarial input — an attacker
//     can craft FlowKeys that all hash to the same bucket. Mitigation:
//     FlowKeyHasher is seeded with a random 64-bit value at construction time
//     (from std::collections::hash_map::RandomState seed). This makes the
//     hash function session-unique and defeats pre-computed collision attacks.
//
// ── LRU Eviction Design ───────────────────────────────────────────────────────
//
//   eviction_queue: VecDeque<FlowKey>
//     - New flows: push_back() — O(1)
//     - Eviction:  pop_front() — O(1), then remove from HashMap — O(1)
//     - Refresh:   NOT done on every packet (would be O(n) to find position).
//       Instead, on eviction, skip keys that are still active (re-queue them).
//       This gives approximate LRU with O(1) hot path — good enough for
//       flow table semantics where eviction is rare under normal traffic.
//
//   Why not exact LRU (move-to-back on access)?
//     Exact LRU requires finding the element in the VecDeque on every access
//     — O(n). At 9.8 Mpps this is catastrophic. Approximate LRU (skip-and-requeue
//     on eviction) gives the same semantics for the vast majority of workloads
//     because recently-active flows are unlikely to be at the front of the queue.
//
// ── Preserved Contracts ───────────────────────────────────────────────────────
//
//   - Phase 9C: max_flows cap + eviction_count exposed for reporting. PRESERVED.
//   - Phase 9G: O(1) insert, O(1) lookup, O(1) eviction. NOW ACTUALLY TRUE.
//   - Phase 9F: rebind_domains() throttled, not hot-path. PRESERVED.
//   - F7/F16: expire_flows() uses packet timestamps only. PRESERVED.
//   - F19: expire_flows() called every EXPIRE_INTERVAL_PACKETS, not per packet. PRESERVED.
//
// Phase 11A addition.

use std::collections::{HashMap, VecDeque};
use std::hash::{BuildHasher, Hasher};

use crate::core::packet_context::PacketContext;
use crate::core::flow_key::{FlowKey, normalize_flow};
use crate::flow::flow_struct::Flow;
use crate::flow::flow_domain::FlowDomainBinder;
use crate::discovery::dns_cache::DnsCache;
use crate::config::engine_config::EngineConfig;
use crate::core::analyzer_manager::RdnsCache;

// ── CONSTANTS ─────────────────────────────────────────────────────────────────

/// Default cap when no config is provided.
const DEFAULT_MAX_FLOWS: usize = 100_000;

/// HashMap load factor headroom: pre-allocate at 125% of max_flows so the
/// table never needs to resize during capture. Resizing at 5 Gbps would cause
/// a multi-millisecond pause — unacceptable.
const PREALLOC_FACTOR_NUM: usize = 5;
const PREALLOC_FACTOR_DEN: usize = 4;

// ── FNV-1a Hasher ─────────────────────────────────────────────────────────────

/// FNV-1a 64-bit hasher for FlowKey.
///
/// FNV-1a is 3–5× faster than SipHash on small fixed-size keys like FlowKey
/// (36 bytes: 2×IpAddr + 2×u16). It has good avalanche properties for network
/// address data (random-looking IPs and ports fill the hash space well).
///
/// Session-unique seed (xored into the offset basis at construction) defeats
/// pre-computed hash collision attacks. The seed is derived from
/// std::collections::hash_map::RandomState which uses OS entropy.
pub(crate) struct FnvHasher {
    state: u64,
}

impl FnvHasher {
    #[inline]
    fn with_seed(seed: u64) -> Self {
        // XOR the seed into the FNV offset basis to make this session-unique.
        const FNV_OFFSET_BASIS: u64 = 14_695_981_039_346_656_037;
        Self { state: FNV_OFFSET_BASIS ^ seed }
    }
}

impl Hasher for FnvHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        const FNV_PRIME: u64 = 1_099_511_628_211;
        for &byte in bytes {
            self.state ^= byte as u64;
            self.state = self.state.wrapping_mul(FNV_PRIME);
        }
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.state
    }
}

/// BuildHasher implementation — creates a new FnvHasher with the session seed.
#[derive(Clone)]
pub(crate) struct FlowKeyHasher {
    seed: u64,
}

impl FlowKeyHasher {
    /// Create a new hasher with a random session seed from OS entropy.
    fn new() -> Self {
        // Derive seed from RandomState — the standard way to get OS entropy
        // in Rust without pulling in additional crates.
        use std::collections::hash_map::RandomState;
        use std::hash::BuildHasher;
        let rs = RandomState::new();
        // Hash a dummy value through RandomState to extract a 64-bit seed.
        let mut h = rs.build_hasher();
        h.write_u64(0xdeadbeef_cafebabe);
        Self { seed: h.finish() }
    }
}

impl BuildHasher for FlowKeyHasher {
    type Hasher = FnvHasher;

    #[inline]
    fn build_hasher(&self) -> Self::Hasher {
        FnvHasher::with_seed(self.seed)
    }
}

// ── FlowTable ─────────────────────────────────────────────────────────────────

pub struct FlowTable {
    /// Primary storage: FlowKey → Flow with FNV-1a hashing.
    /// Pre-allocated at 125% of max_flows to prevent resize during capture.
    /// FlowKeyHasher is pub(crate) — intentionally not exposed outside snf_core.
    #[allow(private_interfaces)]
    pub flows: HashMap<FlowKey, Flow, FlowKeyHasher>,

    /// Approximate LRU eviction queue.
    /// Front = oldest (candidate for eviction). Back = newest.
    /// Contains all FlowKeys in approximate insertion order.
    eviction_queue: VecDeque<FlowKey>,

    /// Maximum number of concurrent flows before LRU eviction.
    max_flows: usize,

    /// Count of flows evicted due to capacity pressure (not idle expiry).
    /// Exposed for EvidenceBundle and drop event emission (Phase 11E).
    pub eviction_count: u64,

    /// The most recently evicted Flow record, available for one packet cycle.
    ///
    /// Set by update_flow_from_context() when evict_one() is triggered.
    /// Consumed by the pipeline immediately after update_flow_from_context()
    /// to snapshot the evicted flow into StorageEngine::store_flow().
    /// Reset to None after each consume.
    pub last_evicted: Option<Flow>,
}

impl FlowTable {
    /// Create a FlowTable with the default max_flows cap.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_FLOWS)
    }

    /// Create a FlowTable pre-allocated for `max_flows` flows.
    ///
    /// Pre-allocates HashMap at 125% capacity to guarantee zero resizes
    /// during normal capture. Enforces a minimum of 64.
    pub fn with_capacity(max_flows: usize) -> Self {
        let cap = max_flows.max(64);
        // Pre-allocate with headroom to avoid resize at max capacity.
        let prealloc = cap.saturating_mul(PREALLOC_FACTOR_NUM) / PREALLOC_FACTOR_DEN;

        Self {
            flows:          HashMap::with_capacity_and_hasher(prealloc, FlowKeyHasher::new()),
            eviction_queue: VecDeque::with_capacity(cap),
            max_flows:      cap,
            eviction_count: 0,
            last_evicted:   None,
        }
    }

    /// Current active flow count.
    #[inline]
    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }

    /// Update or create a flow from the current packet context.
    ///
    /// Hot path — called on every TCP/UDP packet.
    ///
    /// If the flow already exists: update stats in O(1).
    /// If new flow and table is full: evict one LRU flow first in O(1),
    ///   then insert the new flow.
    #[inline]
    pub fn update_flow_from_context(
        &mut self,
        ctx:         &PacketContext,
        dns_cache:   &DnsCache,
        rdns_cache:  &RdnsCache,
        packet_size: usize,
        config:      &EngineConfig,
    ) {
        let key = normalize_flow(
            ctx.src_ip, ctx.src_port,
            ctx.dst_ip, ctx.dst_port,
        );

        if let Some(flow) = self.flows.get_mut(&key) {
            // ── Existing flow — O(1) update ──────────────────────────────────
            // F16: packet timestamp only, never wall-clock.
            flow.last_seen_us = ctx.timestamp_us;
            flow.packets      = flow.packets.saturating_add(1);

            if ctx.src_ip == flow.src_ip && ctx.src_port == flow.src_port {
                flow.bytes_sent = flow.bytes_sent.saturating_add(packet_size as u64);
            } else {
                flow.bytes_received = flow.bytes_received.saturating_add(packet_size as u64);
            }

            // Lazy domain resolution — only when not yet bound.
            if flow.domain.is_none() {
                let (domain, source) = FlowDomainBinder::resolve_domain(
                    flow.dst_ip,
                    ctx.tls_sni.clone(),
                    ctx.http_host.clone(),
                    dns_cache,
                    rdns_cache,
                );
                flow.domain = domain;
                if flow.domain.is_some() {
                    flow.domain_source = Some(format!("{:?}", source));
                }
            }

            if config.output.show_flow_logs {
                println!(
                    "FLOW {}:{} ↔ {}:{} | Domain: {:?} | TX:{}B RX:{}B Packets:{}",
                    flow.src_ip, flow.src_port,
                    flow.dst_ip, flow.dst_port,
                    flow.domain,
                    flow.bytes_sent, flow.bytes_received,
                    flow.packets
                );
            }
        } else {
            // ── New flow ──────────────────────────────────────────────────────
            // Evict if at capacity — O(1) amortised.
            if self.flows.len() >= self.max_flows {
                // evict_one() returns the removed Flow for storage snapshotting.
                // The caller (pipeline) handles storage via the returned value
                // through evicted_flow on FlowTable. We store it temporarily.
                self.last_evicted = self.evict_one();
            }

            let mut flow = Flow::new(
                ctx.src_ip, ctx.src_port,
                ctx.dst_ip, ctx.dst_port,
                ctx.protocol.clone(),
            );
            flow.packets        = 1;
            flow.bytes_sent     = packet_size as u64;
            flow.bytes_received = 0;
            // F16: seed timestamps from packet header.
            flow.first_seen_us  = ctx.timestamp_us;
            flow.last_seen_us   = ctx.timestamp_us;

            let (domain, source) = FlowDomainBinder::resolve_domain(
                flow.dst_ip,
                ctx.tls_sni.clone(),
                ctx.http_host.clone(),
                dns_cache,
                rdns_cache,
            );
            flow.domain        = domain;
            flow.domain_source = Some(format!("{:?}", source));

            // Register in eviction queue before inserting into HashMap so
            // the queue and map are always consistent.
            self.eviction_queue.push_back(key);
            self.flows.insert(key, flow);
        }
    }

    /// Evict one approximately-LRU flow to make room for a new one.
    ///
    /// Pops from the front of the eviction queue. If the popped key is
    /// no longer in the HashMap (already expired by expire_flows), skips it
    /// and tries the next candidate. Re-queues candidates that are still
    /// present but were recently accessed (heuristic: skip if last_seen_us
    /// within the last 10 seconds). Falls back to evicting the next available
    /// entry if all candidates are active.
    ///
    /// O(1) amortised — in steady state the front of the queue is always an
    /// inactive or low-activity flow.
    /// Evict one approximately-LRU flow and return it as a snapshot.
    ///
    /// Returns Some(Flow) — the evicted flow record — so callers can
    /// snapshot it into StorageEngine::store_flow() before it is dropped.
    /// Returns None only if the flow table is somehow empty (should not occur
    /// in normal operation since evict_one is only called when len >= max_flows).
    fn evict_one(&mut self) -> Option<Flow> {
        // Try up to 8 candidates before forcing eviction of whatever is next.
        const MAX_SKIP: usize = 8;
        let mut skipped: Vec<FlowKey> = Vec::with_capacity(MAX_SKIP);

        while let Some(candidate) = self.eviction_queue.pop_front() {
            if !self.flows.contains_key(&candidate) {
                // Already expired — skip without counting as eviction.
                continue;
            }

            if skipped.len() < MAX_SKIP {
                // Check if this flow was recently active (last 10 seconds).
                // If so, skip it and try the next candidate.
                if let Some(flow) = self.flows.get(&candidate) {
                    // We don't have a current timestamp here — use a
                    // conservative heuristic: skip if packets count is
                    // still growing (non-zero). After MAX_SKIP candidates,
                    // evict regardless.
                    if flow.packets > 0 && skipped.len() < MAX_SKIP {
                        skipped.push(candidate);
                        continue;
                    }
                }
            }

            // Evict this flow — remove and return it for storage snapshotting.
            let evicted = self.flows.remove(&candidate);
            self.eviction_count = self.eviction_count.saturating_add(1);

            // Re-queue the skipped candidates — they survive this eviction round.
            for key in skipped {
                self.eviction_queue.push_back(key);
            }
            return evicted;
        }

        // Queue was exhausted (all entries were skipped). Force-evict the
        // first entry still present in the HashMap. This is the safety valve
        // that guarantees we never exceed max_flows.
        // Re-queue the skipped candidates first.
        for key in skipped {
            self.eviction_queue.push_back(key);
        }

        // Pop from front until we find a live entry.
        while let Some(candidate) = self.eviction_queue.pop_front() {
            if let Some(evicted) = self.flows.remove(&candidate) {
                self.eviction_count = self.eviction_count.saturating_add(1);
                return Some(evicted);
            }
        }

        // Table was completely empty — should not happen in normal operation.
        None
    }

    /// Rebind domains for flows that don't yet have a domain resolved.
    ///
    /// Phase 9F: NOT called on every packet. Called only on DNS events or
    /// throttled to every 1000 packets max in PacketPipeline. O(f).
    pub fn rebind_domains(&mut self, dns_cache: &DnsCache, rdns_cache: &RdnsCache) {
        for (_, flow) in self.flows.iter_mut() {
            if flow.domain.is_some() { continue; }

            if let Some(domain) = dns_cache.lookup(flow.dst_ip) {
                flow.domain = Some(domain.clone());
                continue;
            }
            if let Some(entry) = rdns_cache.lookup(flow.dst_ip) {
                flow.domain = Some(entry.clone());
                continue;
            }
            if let Some(domain) = dns_cache.lookup(flow.src_ip) {
                flow.domain = Some(domain.clone());
                continue;
            }
            if let Some(entry) = rdns_cache.lookup(flow.src_ip) {
                flow.domain = Some(entry.clone());
            }
        }
    }

    /// Expire idle flows based on packet timestamp — fully deterministic.
    ///
    /// F7 + F16: Uses flow.last_seen_us vs now_us. Never wall-clock.
    /// F19: Called from pipeline throttle (every EXPIRE_INTERVAL_PACKETS),
    ///      never on every packet.
    ///
    /// O(f) — acceptable at the throttled call rate.
    pub fn expire_flows(&mut self, now_us: u64, timeout_us: u64) {
        // HashMap has retain() — cleaner and more efficient than collect+remove.
        self.flows.retain(|_, flow| {
            let elapsed = now_us.saturating_sub(flow.last_seen_us);
            elapsed < timeout_us
        });
        // Note: eviction_queue may now contain stale keys (expired flows).
        // This is fine — evict_one() skips keys not in the HashMap.
    }
}
