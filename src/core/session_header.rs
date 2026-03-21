use std::collections::BTreeMap;

/// SNF version string - updated on each release.
pub const SNF_VERSION: &str = "0.1.0";

/// The session header is the first JSON line written to every SNF output file.
///
/// It contains:
/// - SNF version (semver)
/// - Session start timestamp (from first packet, microseconds UTC)
/// - Operating mode (Live, PcapReplay, etc.)
/// - SHA-256 of the serialized config at session start
/// - Input source (interface name or PCAP file path)
///
/// A valid SNF output file always begins with exactly one session header line.
/// Any file missing this line is considered corrupt or incomplete.
pub struct SessionHeader {
    pub snf_version: String,
    pub session_start_us: u64,
    pub operating_mode: String,
    pub config_sha256: String,
    pub input_source: String,
}

impl SessionHeader {
    pub fn new(
        session_start_us: u64,
        operating_mode: impl Into<String>,
        config_sha256: impl Into<String>,
        input_source: impl Into<String>,
    ) -> Self {
        Self {
            snf_version: SNF_VERSION.to_string(),
            session_start_us,
            operating_mode: operating_mode.into(),
            config_sha256: config_sha256.into(),
            input_source: input_source.into(),
        }
    }

    /// Serialize to a single compact JSON line.
    /// Uses BTreeMap for deterministic key ordering - same config always
    /// produces the same header string.
    pub fn to_json_line(&self) -> String {
        // BTreeMap sorts keys - deterministic output guaranteed.
        let mut fields: BTreeMap<&str, String> = BTreeMap::new();
        fields.insert("record_type",      "\"snf_session_header\"".to_string());
        fields.insert("snf_version",      format!("\"{}\"", self.snf_version));
        fields.insert("session_start_us", self.session_start_us.to_string());
        fields.insert("operating_mode",   format!("\"{}\"", self.operating_mode));
        fields.insert("config_sha256",    format!("\"{}\"", self.config_sha256));
        // Escape backslashes so Windows paths produce valid JSON strings.
        // e.g. C:\Users\foo -> C:\\Users\\foo
        let json_safe_source = self.input_source.replace('\\', "\\\\");
        fields.insert("input_source",     format!("\"{}\"", json_safe_source));

        let body: Vec<String> = fields.iter()
            .map(|(k, v)| format!("\"{}\":{}", k, v))
            .collect();

        format!("{{{}}}", body.join(","))
    }
}