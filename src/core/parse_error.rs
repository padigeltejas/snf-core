use std::fmt;

#[derive(Debug, Clone)]
pub struct SnfParseError {
    pub protocol: &'static str,
    pub reason: String,
    pub offset: usize,
}

impl SnfParseError {
    pub fn new(protocol: &'static str, reason: impl Into<String>, offset: usize) -> Self {
        let mut r = reason.into();
        if r.len() > 256 {
            r.truncate(256);
            r.push_str("...[truncated]");
        }
        Self { protocol, reason: r, offset }
    }

    pub fn without_offset(protocol: &'static str, reason: impl Into<String>) -> Self {
        Self::new(protocol, reason, 0)
    }
}

impl fmt::Display for SnfParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.offset > 0 {
            write!(f, "[{}] {} (at offset {})", self.protocol, self.reason, self.offset)
        } else {
            write!(f, "[{}] {}", self.protocol, self.reason)
        }
    }
}

pub type ParseResult = Result<(), SnfParseError>;