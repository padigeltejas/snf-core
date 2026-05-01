use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::time::Instant;

/// Unique identifier for a network connection (5‑tuple)
#[derive(Eq, Clone)]
pub struct FlowKey {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
}

impl PartialEq for FlowKey {
    fn eq(&self, other: &Self) -> bool {
        self.src_ip == other.src_ip
            && self.dst_ip == other.dst_ip
            && self.src_port == other.src_port
            && self.dst_port == other.dst_port
            && self.protocol == other.protocol
    }
}

impl Hash for FlowKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.src_ip.hash(state);
        self.dst_ip.hash(state);
        self.src_port.hash(state);
        self.dst_port.hash(state);
        self.protocol.hash(state);
    }
}

/// Stores statistics for a connection
pub struct FlowState {
    pub packets: u64,
    pub bytes: u64,
    pub first_seen: Instant,
    pub last_seen: Instant,
    pub domain: Option<String>,   // domain bound to this flow
}

/// Table storing all active flows
pub struct FlowTable {
    pub flows: HashMap<FlowKey, FlowState>,
}

impl FlowTable {
    /// Create new empty flow table
    pub fn new() -> Self {
        FlowTable {
            flows: HashMap::new(),
        }
    }

    /// Update flow stats when a packet arrives
    pub fn process_packet(&mut self, key: FlowKey, size: u32) {
        let now = Instant::now();

        let key = key.normalize();

        let flow = self.flows.entry(key).or_insert(FlowState {
    packets: 0,
    bytes: 0,
    first_seen: now,
    last_seen: now,
    domain: None,
});

        flow.packets += 1;
        flow.bytes += size as u64;
        flow.last_seen = now;
    }
    pub fn bind_domain(&mut self, key: &FlowKey, domain: String) {
    let normalized = key.clone().normalize();

    if let Some(flow) = self.flows.get_mut(&normalized) {
        flow.domain = Some(domain);
    }
}

    pub fn expire_flows(&mut self) {
        let timeout = std::time::Duration::from_secs(2);
        let now = Instant::now();

        self.flows.retain(|key, flow| {
            if now.duration_since(flow.last_seen) > timeout {
                println!("FLOW CLOSED");
                println!(
                    "{}:{} -> {}:{}",
                    key.src_ip, key.src_port, key.dst_ip, key.dst_port
                );
                if let Some(domain) = &flow.domain {
    println!("Domain: {}", domain);
}
                println!("Protocol: {}", key.protocol);
                println!("Packets: {}", flow.packets);
                println!("Bytes: {}", flow.bytes);
                println!("--------------------------------");

                false
            } else {
                true
            }
        });
    }
}
impl FlowKey {
    /// Normalize flow so both directions map to the same key
    pub fn normalize(self) -> FlowKey {
        if self.src_ip < self.dst_ip
            || (self.src_ip == self.dst_ip && self.src_port <= self.dst_port)
        {
            self
        } else {
            FlowKey {
                src_ip: self.dst_ip,
                dst_ip: self.src_ip,
                src_port: self.dst_port,
                dst_port: self.src_port,
                protocol: self.protocol,
            }
        }
    }
}
impl Default for FlowTable {
    fn default() -> Self { Self::new() }
}
