// src/output/flush_guard.rs
//
// RAII flush guard for NdjsonWriter.
//
// FlushGuard holds a mutable reference to an NdjsonWriter and flushes it
// when dropped. Used to guarantee a final flush on clean shutdown even
// when the shutdown path is complex (early returns, error paths, etc.).
//
// Usage:
//   let _guard = FlushGuard::new(&mut writer);
//   // ... do work ...
//   // writer.flush() called automatically when _guard goes out of scope
//
// The guard does NOT close the file — it only flushes the BufWriter.
// The NdjsonWriter itself closes the file when it is dropped.

use super::ndjson_writer::NdjsonWriter;

/// RAII guard that flushes an NdjsonWriter on drop.
pub struct FlushGuard<'a> {
    writer: &'a mut NdjsonWriter,
}

impl<'a> FlushGuard<'a> {
    /// Acquire the guard. The writer will be flushed when this guard is dropped.
    pub fn new(writer: &'a mut NdjsonWriter) -> Self {
        Self { writer }
    }

    /// Manually trigger the flush early without dropping the guard.
    /// Useful for checkpointing during long-running captures.
    pub fn flush_now(&mut self) {
        self.writer.flush();
    }
}

impl<'a> Drop for FlushGuard<'a> {
    fn drop(&mut self) {
        self.writer.flush();
    }
}