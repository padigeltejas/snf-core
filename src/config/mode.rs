// src/config/mode.rs
//
// SNF Operation Modes — four named presets that configure all 7 engine layers.
//
// Forensic : Full depth analysis. All analyzers, all events, max detail.
//            Intended for DFIR, post-incident analysis, court-admissible output.
//
// Monitor  : Lightweight continuous monitoring. Flow-level visibility,
//            reduced event verbosity. Intended for 24/7 SOC deployments.
//
// Stealth  : Minimal footprint. No console output, no logging to disk unless
//            explicitly configured. Passive only — no active queries.
//            Intended for covert sensor deployments.
//
// Replay   : Deterministic PCAP replay. Strict timestamp ordering enforced.
//            All randomness disabled. SHA-256 of input + config + output
//            must be identical across runs. Intended for reproducible analysis.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationMode {
    /// Full forensic depth — all analyzers, all events, max verbosity.
    Forensic,

    /// Lightweight monitoring — flow-level, reduced event output.
    Monitor,

    /// Minimal footprint — no output unless explicitly configured.
    Stealth,

    /// Deterministic PCAP replay — reproducible output guaranteed.
    Replay,
}

impl OperationMode {
    /// Parse an operation mode from a string (case-insensitive).
    /// Returns None if the string does not match a known mode.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "forensic" => Some(Self::Forensic),
            "monitor"  => Some(Self::Monitor),
            "stealth"  => Some(Self::Stealth),
            "replay"   => Some(Self::Replay),
            _          => None,
        }
    }

    /// Returns the canonical string name for this mode.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Forensic => "forensic",
            Self::Monitor  => "monitor",
            Self::Stealth  => "stealth",
            Self::Replay   => "replay",
        }
    }
}

impl std::fmt::Display for OperationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Default for OperationMode {
    fn default() -> Self {
        Self::Forensic
    }
}