// src/config/capture_mode.rs
//
// CaptureMode enum — replaces the String capture_mode field in CaptureConfig.
//
// Phase 10D: Strings like "realtime"/"pcap"/"snapshot"/"replay" scattered across
// the codebase are replaced by a proper enum. String comparisons are eliminated
// from hot paths. Pattern matching is exhaustive — the compiler enforces that
// all modes are handled everywhere.

/// Operating mode for the SNF capture engine.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Default)]
pub enum CaptureMode {
    /// Live interface capture — continuous packet ingestion from a network device.
    #[default]
    Realtime,
    /// Offline PCAP file replay — deterministic, court-admissible analysis.
    Pcap,
    /// Single burst capture — capture N packets then exit cleanly.
    Snapshot,
    /// Replay with timing simulation — replays PCAP at original packet timestamps.
    Replay,
}

impl CaptureMode {
    /// Parse from a string. Case-insensitive.
    /// Returns None on unrecognized input — caller should emit a config error.
#[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "realtime" | "live"     => Some(CaptureMode::Realtime),
            "pcap"     | "offline"  => Some(CaptureMode::Pcap),
            "snapshot" | "burst"    => Some(CaptureMode::Snapshot),
            "replay"                => Some(CaptureMode::Replay),
            _                       => None,
        }
    }

    /// Canonical string representation — used in session headers and reports.
    pub fn as_str(&self) -> &'static str {
        match self {
            CaptureMode::Realtime => "realtime",
            CaptureMode::Pcap     => "pcap",
            CaptureMode::Snapshot => "snapshot",
            CaptureMode::Replay   => "replay",
        }
    }

    /// Human-readable label for session headers and UI output.
    pub fn display_label(&self) -> &'static str {
        match self {
            CaptureMode::Realtime => "Live",
            CaptureMode::Pcap     => "PCAP",
            CaptureMode::Snapshot => "Snapshot",
            CaptureMode::Replay   => "Replay",
        }
    }

    /// Returns true if this mode involves reading from a PCAP file.
    pub fn is_file_based(&self) -> bool {
        matches!(self, CaptureMode::Pcap | CaptureMode::Replay)
    }

    /// Returns true if this mode reads from a live network interface.
    pub fn is_live(&self) -> bool {
        matches!(self, CaptureMode::Realtime | CaptureMode::Snapshot)
    }
}


impl std::fmt::Display for CaptureMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}