// src/discovery/dns_cache.rs
//
// DNS IP→domain cache used for flow domain attribution.
//
// Phase 9B: Enforce dns_cache_size from config. FIFO eviction when full —
// oldest inserted entry is removed first. Uses a VecDeque as an insertion-order
// queue alongside the HashMap so eviction is O(1) amortized.
//
// Security: cache is bounded — a flood of unique DNS responses cannot cause
// unbounded memory growth. Default cap is 5000 entries (from DnsConfig).

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

/// Default cap used when no config is provided (e.g. in tests).
const DEFAULT_MAX_ENTRIES: usize = 5_000;

pub struct DnsCache {
    /// IP → domain lookup table. O(1) average lookup.
    table: HashMap<IpAddr, String>,
    /// Insertion-order queue for FIFO eviction. Front = oldest.
    order: VecDeque<IpAddr>,
    /// Maximum number of entries before eviction kicks in.
    max_size: usize,
}

impl DnsCache {
    /// Create a new DnsCache with the default cap.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_ENTRIES)
    }

    /// Create a new DnsCache with an explicit cap (from config.dns.dns_cache_size).
    /// Enforces a minimum of 16 to prevent misconfiguration footguns.
    pub fn with_capacity(max_size: usize) -> Self {
        let cap = max_size.max(16);
        Self {
            table: HashMap::with_capacity(cap),
            order: VecDeque::with_capacity(cap),
            max_size: cap,
        }
    }

    /// Insert an IP→domain mapping.
    ///
    /// If the IP already exists, the domain is updated in place without
    /// changing insertion order (no duplicate in the eviction queue).
    ///
    /// If the cache is full, the oldest entry is evicted (FIFO) before
    /// inserting the new one. This keeps memory strictly bounded.
    pub fn insert(&mut self, ip: IpAddr, domain: String) {
        if self.table.contains_key(&ip) {
            // Update existing entry — no change to eviction order.
            self.table.insert(ip, domain);
            return;
        }

        // Evict oldest entry if at capacity.
        if self.table.len() >= self.max_size {
            if let Some(oldest_ip) = self.order.pop_front() {
                self.table.remove(&oldest_ip);
            }
        }

        // Insert new entry and record in eviction queue.
        self.order.push_back(ip);
        self.table.insert(ip, domain);
    }

    /// Look up a domain by IP address. O(1) average.
    pub fn lookup(&self, ip: IpAddr) -> Option<&String> {
        self.table.get(&ip)
    }

    /// Alias for lookup — used by flow domain rebinding code.
    pub fn get(&self, ip: &IpAddr) -> Option<&String> {
        self.table.get(ip)
    }

    /// Current number of cached entries.
    pub fn len(&self) -> usize {
        self.table.len()
    }

    /// True if cache is empty.
    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }
}