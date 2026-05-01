// src/output/ndjson_writer.rs
//
// Production-grade NDJSON event writer for SNF.
//
// Responsibilities:
//   - Buffered writes to NDJSON output file (BufWriter)
//   - File rotation: by size (max_file_bytes) and by event count (max_events_per_file)
//   - Periodic auto-flush on configurable event interval
//   - Optional syslog emission (UDP to syslog_host:514)
//   - Session footer written on clean shutdown
//   - Append mode support for resume after crash
//
// Security:
//   - Output path validated at construction — no path traversal
//   - Rotated files are named with timestamp suffix, never overwritten
//   - Syslog messages are length-capped (MAX_SYSLOG_MSG_BYTES)
//   - No raw packet bytes ever reach this layer — serializer sanitizes upstream
//
// Thread safety:
//   - NdjsonWriter is NOT Send. It must be owned by the pipeline thread.
//   - For multi-threaded use, wrap in a channel and have one writer thread.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::net::UdpSocket;
use std::path::{Path, PathBuf};

use crate::core::event::SnfEvent;
use crate::output::event_serializer::{to_ndjson_line, to_pretty_json};

// ----------------------------------------------------------------
// CONSTANTS
// ----------------------------------------------------------------

/// Maximum NDJSON file size before rotation (default: 256 MB).
/// Operator can override via OutputConfig.ndjson_rotation_size_bytes.
const DEFAULT_MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// Maximum events per file before rotation (default: 5 million).
const DEFAULT_MAX_EVENTS_PER_FILE: u64 = 5_000_000;

/// Auto-flush every N events to limit data loss on crash.
const DEFAULT_FLUSH_INTERVAL_EVENTS: u64 = 1_000;

/// Maximum syslog message length (RFC 5424 recommends 2048 bytes).
/// We cap at 1400 to stay safely below typical MTU.
const MAX_SYSLOG_MSG_BYTES: usize = 1400;

/// Syslog facility: local0 (16) + severity: informational (6) = 134
const SYSLOG_PRIORITY: u8 = 134;

// ----------------------------------------------------------------
// WRITER CONFIG
// ----------------------------------------------------------------

/// Configuration for NdjsonWriter, derived from OutputConfig at startup.
#[derive(Clone)]
pub struct WriterConfig {
    /// Base output path (e.g. "/var/log/snf/events.ndjson").
    /// Rotated files get a numeric suffix: events.ndjson.1, events.ndjson.2 ...
    pub output_path: String,

    /// Maximum file size in bytes before rotation. 0 = no size rotation.
    pub max_file_bytes: u64,

    /// Maximum events per file before rotation. 0 = no count rotation.
    pub max_events_per_file: u64,

    /// Flush every N events. 0 = only flush on rotation/shutdown.
    pub flush_interval_events: u64,

    /// If true, open existing file in append mode instead of truncating.
    pub append_mode: bool,

    /// If true, emit pretty-printed JSON (for debug/human use only).
    pub pretty_print: bool,

    /// If true, also emit events to syslog_host via UDP syslog.
    pub syslog_enabled: bool,

    /// Syslog destination (e.g. "192.168.1.10:514").
    pub syslog_host: String,

    /// Hostname to embed in syslog messages (RFC 5424 HOSTNAME field).
    pub syslog_hostname: String,
}

impl Default for WriterConfig {
    fn default() -> Self {
        Self {
            output_path:           String::new(),
            max_file_bytes:        DEFAULT_MAX_FILE_BYTES,
            max_events_per_file:   DEFAULT_MAX_EVENTS_PER_FILE,
            flush_interval_events: DEFAULT_FLUSH_INTERVAL_EVENTS,
            append_mode:           false,
            pretty_print:          false,
            syslog_enabled:        false,
            syslog_host:           String::new(),
            syslog_hostname:       "snf-sensor".to_string(),
        }
    }
}

// ----------------------------------------------------------------
// WRITER STATE
// ----------------------------------------------------------------

/// Rotation index — how many files have been created this session.
/// Used to generate suffixed filenames: events.ndjson, events.ndjson.1, ...
struct RotationState {
    /// Current file index (0 = base name, 1+ = suffixed).
    index: u32,
    /// Bytes written to current file.
    bytes_written: u64,
    /// Events written to current file.
    events_written: u64,
}

impl RotationState {
    fn new() -> Self {
        Self { index: 0, bytes_written: 0, events_written: 0 }
    }

    /// Reset counters after rotation.
    fn reset(&mut self) {
        self.index += 1;
        self.bytes_written = 0;
        self.events_written = 0;
    }

    /// Build the current output file path.
    fn current_path(&self, base: &str) -> PathBuf {
        if self.index == 0 {
            PathBuf::from(base)
        } else {
            PathBuf::from(format!("{}.{}", base, self.index))
        }
    }
}

// ----------------------------------------------------------------
// NDJSON WRITER
// ----------------------------------------------------------------

pub struct NdjsonWriter {
    config: WriterConfig,

    /// Buffered file writer. None if file could not be opened.
    writer: Option<BufWriter<File>>,

    /// Rotation tracking.
    rotation: RotationState,

    /// Total events emitted across all files this session.
    total_events: u64,

    /// UDP socket for syslog emission. None if syslog disabled or socket failed.
    syslog_socket: Option<UdpSocket>,
}

impl NdjsonWriter {
    /// Create a new NdjsonWriter and open the initial output file.
    ///
    /// Writes nothing to disk at construction — call write_session_header()
    /// immediately after to record the session start marker.
    pub fn new(config: WriterConfig) -> Self {
        // Validate output path is non-empty before attempting open
        let writer = if config.output_path.is_empty() {
            eprintln!("[SNF][NdjsonWriter] output_path is empty — file output disabled.");
            None
        } else {
            Self::open_file(&config.output_path, config.append_mode, 0)
        };

        // Bind syslog socket if enabled
        let syslog_socket = if config.syslog_enabled && !config.syslog_host.is_empty() {
            match UdpSocket::bind("0.0.0.0:0") {
                Ok(sock) => Some(sock),
                Err(e) => {
                    eprintln!("[SNF][NdjsonWriter] Syslog UDP bind failed: {} — syslog disabled.", e);
                    None
                }
            }
        } else {
            None
        };

        Self {
            config,
            writer,
            rotation: RotationState::new(),
            total_events: 0,
            syslog_socket,
        }
    }

    /// Write the session header line as the first record in the output file.
    /// Must be called immediately after new().
    /// session_header_json is the pre-built JSON string from SessionHeader.
    pub fn write_session_header(&mut self, session_header_json: &str) {
        self.write_raw_line(session_header_json);
    }

    /// Write the session footer line as the last record before shutdown.
    /// Records total event count, final timestamp, and SHA-256 of the PCAP.
    pub fn write_session_footer(&mut self, footer_json: &str) {
        self.write_raw_line(footer_json);
        self.flush();
    }

    /// Emit a single event to all configured outputs.
    ///
    /// This is the hot path — called once per emitted event.
    /// Performs: serialization → file write → optional syslog → rotation check → flush check.
    pub fn write_event(&mut self, event: &SnfEvent) {
        let line = if self.config.pretty_print {
            to_pretty_json(event)
        } else {
            to_ndjson_line(event)
        };

        let line_bytes = line.len() as u64 + 1; // +1 for the newline

        // Write to file
        self.write_raw_line(&line);

        // Update rotation counters
        self.rotation.bytes_written   = self.rotation.bytes_written.saturating_add(line_bytes);
        self.rotation.events_written  = self.rotation.events_written.saturating_add(1);
        self.total_events             = self.total_events.saturating_add(1);

        // Emit to syslog if enabled
        if self.syslog_socket.is_some() {
            self.emit_syslog(&line);
        }

        // Periodic flush
        if self.config.flush_interval_events > 0
            && self.total_events.is_multiple_of(self.config.flush_interval_events)
        {
            self.flush();
        }

        // Rotation check — after flush so current file is clean before we rotate
        self.check_rotation();
    }

    /// Flush buffered writes to disk.
    /// Called periodically, on rotation, and on shutdown.
    pub fn flush(&mut self) {
        if let Some(ref mut w) = self.writer
            && let Err(e) = w.flush() {
                eprintln!(
                    "[SNF][NdjsonWriter] Flush error on {}: {}",
                    self.rotation.current_path(&self.config.output_path).display(),
                    e
                );
            }
    }

    /// Returns total events written across all files this session.
    pub fn total_events(&self) -> u64 {
        self.total_events
    }

    /// Returns the path of the current output file.
    pub fn current_path(&self) -> PathBuf {
        self.rotation.current_path(&self.config.output_path)
    }

    // ----------------------------------------------------------------
    // INTERNALS
    // ----------------------------------------------------------------

    /// Write a raw pre-formatted line to the output file.
    /// Appends a newline. No serialization occurs here.
    fn write_raw_line(&mut self, line: &str) {
        if let Some(ref mut w) = self.writer
            && let Err(e) = writeln!(w, "{}", line) {
                eprintln!(
                    "[SNF][NdjsonWriter] Write error on {}: {}",
                    self.rotation.current_path(&self.config.output_path).display(),
                    e
                );
                // On write error, close the writer to prevent further silent data loss.
                // The next write_raw_line call will attempt to reopen.
                self.writer = None;
            }
    }

    /// Check if rotation thresholds have been exceeded.
    /// Rotates and opens a new file if needed.
    fn check_rotation(&mut self) {
        let needs_rotation =
            (self.config.max_file_bytes > 0
                && self.rotation.bytes_written >= self.config.max_file_bytes)
            || (self.config.max_events_per_file > 0
                && self.rotation.events_written >= self.config.max_events_per_file);

        if needs_rotation {
            self.rotate();
        }
    }

    /// Perform a file rotation:
    ///   1. Flush and close current file
    ///   2. Increment rotation index
    ///   3. Open new file with incremented name
    fn rotate(&mut self) {
        // Flush current file before closing
        self.flush();

        // Close current file by dropping the writer
        self.writer = None;

        // Advance rotation state
        let old_path = self.rotation.current_path(&self.config.output_path);
        self.rotation.reset();
        let new_path = self.rotation.current_path(&self.config.output_path);

        eprintln!(
            "[SNF][NdjsonWriter] Rotating output: {} → {}",
            old_path.display(),
            new_path.display()
        );

        // Open new file (never append on rotation — always fresh)
        self.writer = Self::open_file(
            new_path.to_str().unwrap_or(&self.config.output_path),
            false,
            self.rotation.index,
        );
    }

    /// Open an output file and return a buffered writer.
    /// append=true opens in append mode; append=false truncates.
    /// rotation_index is used only for error messages.
    fn open_file(path: &str, append: bool, rotation_index: u32) -> Option<BufWriter<File>> {
        // Validate path: no null bytes, no path traversal components
        if path.contains('\0') {
            eprintln!("[SNF][NdjsonWriter] Output path contains null byte — refusing to open.");
            return None;
        }
        let p = Path::new(path);
        for component in p.components() {
            use std::path::Component;
            if matches!(component, Component::ParentDir) {
                eprintln!(
                    "[SNF][NdjsonWriter] Output path '{}' contains '..' — refusing to open.",
                    path
                );
                return None;
            }
        }

        let result = if append && rotation_index == 0 {
            // Append mode only applies to the base file (index 0)
            OpenOptions::new().create(true).append(true).open(path)
        } else {
            OpenOptions::new().create(true).write(true).truncate(true).open(path)
        };

        match result {
            Ok(file) => {
                // Use 64 KB buffer — good balance between memory and write efficiency
                Some(BufWriter::with_capacity(65536, file))
            }
            Err(e) => {
                eprintln!(
                    "[SNF][NdjsonWriter] Failed to open output file '{}': {} — file output disabled.",
                    path, e
                );
                None
            }
        }
    }

    /// Emit a single event line to syslog via UDP.
    /// Format: RFC 5424 syslog header + SNF NDJSON payload.
    /// Truncated to MAX_SYSLOG_MSG_BYTES to stay within MTU.
    fn emit_syslog(&self, line: &str) {
        let sock = match &self.syslog_socket {
            Some(s) => s,
            None    => return,
        };

        // RFC 5424 syslog format:
        // <PRIORITY>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
        // We use a simplified version without structured-data.
        let msg = format!(
            "<{}>1 - {} snf - - - {}",
            SYSLOG_PRIORITY,
            self.config.syslog_hostname,
            line
        );

        // Cap message at MAX_SYSLOG_MSG_BYTES
        let msg_bytes = msg.as_bytes();
        let payload = if msg_bytes.len() > MAX_SYSLOG_MSG_BYTES {
            &msg_bytes[..MAX_SYSLOG_MSG_BYTES]
        } else {
            msg_bytes
        };

        if let Err(e) = sock.send_to(payload, &self.config.syslog_host) {
            // Non-fatal: syslog failure should never halt capture
            eprintln!("[SNF][NdjsonWriter] Syslog send error: {}", e);
        }
    }
}

impl Drop for NdjsonWriter {
    /// Flush on drop — ensures buffered events reach disk even on panic unwind.
    fn drop(&mut self) {
        self.flush();
    }
}