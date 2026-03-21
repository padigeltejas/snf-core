#[derive(Clone)]
pub struct DebugConfig {
    pub debug_packets: bool,
    pub dump_raw_packets: bool,
}

impl Default for DebugConfig {
    fn default() -> Self {
        Self {
            debug_packets: false,
            dump_raw_packets: false,
        }
    }
}
