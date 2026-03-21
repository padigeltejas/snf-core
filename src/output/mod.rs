// src/output/mod.rs
//
// Output module — NDJSON writing, serialization, and flush management.
//
// Public surface:
//   NdjsonWriter   — production NDJSON file writer with rotation and syslog
//   WriterConfig   — configuration struct for NdjsonWriter
//   FlushGuard     — RAII flush-on-drop wrapper
//   to_ndjson_line — hot-path event serializer
//   to_pretty_json — human-readable event serializer (debug only)

pub mod event_serializer;
pub mod ndjson_writer;
pub mod flush_guard;

pub use ndjson_writer::{NdjsonWriter, WriterConfig};
pub use flush_guard::FlushGuard;
pub use event_serializer::{to_ndjson_line, to_pretty_json};