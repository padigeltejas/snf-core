use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use crate::core::event::SnfEvent;

/// The EventBus is the single authoritative write path for all SNF events.
///
/// Responsibilities:
/// - Assigns monotonically increasing event_ids
/// - Writes events as newline-delimited JSON to the output file
/// - Holds the session header (SHA-256, timestamps, config hash)
///
/// All protocol analyzers, flow engine components, and error handlers
/// must emit events through this bus — never write directly to files or stdout.
pub struct EventBus {
    /// Monotonically increasing counter. Assigned to each event before write.
    event_counter: u64,

    /// Buffered writer to the output NDJSON file.
    /// None if output file could not be opened — events are dropped with a stderr warning.
    writer: Option<BufWriter<File>>,

    /// Path to the output file, stored for error reporting.
    output_path: String,
}

impl EventBus {
    /// Initialize the EventBus and write the session header to the output file.
    ///
    /// `output_path`: path to the NDJSON output file.
    /// `session_meta`: pre-built session header JSON string (from SessionHeader::to_json_line()).
    ///
    /// If the file cannot be opened, a warning is printed to stderr and the bus
    /// operates in no-op mode — events are counted but not written.
    pub fn new(output_path: &str, session_meta: &str) -> Self {
        let writer = match OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(output_path)
        {
            Ok(file) => {
                let mut w = BufWriter::new(file);
                // Write session header as first line — always present in valid output files.
                if let Err(e) = writeln!(w, "{}", session_meta) {
                    eprintln!("[SNF][EventBus] Failed to write session header to {}: {}", output_path, e);
                }
                Some(w)
            }
            Err(e) => {
                eprintln!("[SNF][EventBus] Failed to open output file {}: {}. Events will not be written.", output_path, e);
                None
            }
        };

        Self {
            event_counter: 0,
            writer,
            output_path: output_path.to_string(),
        }
    }

    /// Emit an event. Assigns the next event_id, then writes to output.
    ///
    /// This is the only method protocol analyzers should call.
    /// Thread safety: EventBus is not Send — it must be owned by a single thread.
    pub fn emit(&mut self, mut event: SnfEvent) {
        self.event_counter += 1;
        event.event_id = self.event_counter;

        if let Some(ref mut w) = self.writer {
            let line = event.to_json_line();
            if let Err(e) = writeln!(w, "{}", line) {
                eprintln!("[SNF][EventBus] Write error on {}: {}", self.output_path, e);
            }
        }
    }

    /// Flush all buffered writes to disk.
    /// Must be called on clean shutdown and periodically for long captures.
    pub fn flush(&mut self) {
        if let Some(ref mut w) = self.writer {
            if let Err(e) = w.flush() {
                eprintln!("[SNF][EventBus] Flush error on {}: {}", self.output_path, e);
            }
        }
    }

    /// Returns the total number of events emitted this session.
    pub fn event_count(&self) -> u64 {
        self.event_counter
    }
}

impl Drop for EventBus {
    /// Flush on drop — ensures buffered events reach disk even on panic unwind.
    fn drop(&mut self) {
        self.flush();
    }
}
