#!/usr/bin/env python3
"""
patch_snf_core.py — SNF-Core Public Repo Patcher
=================================================
Run this from INSIDE the snf-core directory:
    python patch_snf_core.py

Patches applied
  P1  main.rs                      Windows UTF-8 console fix (SetConsoleOutputCP)
  P2  src/capture/mod.rs           Timestamped run_<ts>/ output directory (created once per session)
  P3  src/capture/mod.rs           Final session summary box printed after run completes
  P4  src/pipeline/packet_pipeline.rs  Fix garbled Unicode (→  and ─ chars)
  P5  src/reporting/mod.rs         Add print_final_summary() method to SessionReporter

Each patch is idempotent — safe to re-run.  Original files are backed up as <file>.bak
"""

import os
import sys
import shutil

# ── helpers ───────────────────────────────────────────────────────────────────

BOLD  = "\033[1m"
GREEN = "\033[92m"
RED   = "\033[91m"
CYAN  = "\033[96m"
RESET = "\033[0m"

def banner(msg):
    print(f"\n{BOLD}{CYAN}{'='*60}{RESET}")
    print(f"{BOLD}{CYAN}  {msg}{RESET}")
    print(f"{BOLD}{CYAN}{'='*60}{RESET}")

def ok(msg):   print(f"  {GREEN}[OK]{RESET}  {msg}")
def skip(msg): print(f"  {CYAN}[--]{RESET}  {msg} (already applied)")
def fail(msg): print(f"  {RED}[ERR]{RESET} {msg}")

def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()

def write(path, text):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)

def backup(path):
    bak = path + ".bak"
    if not os.path.exists(bak):
        shutil.copy2(path, bak)

def patch_file(path, search, replace, patch_name):
    """Apply a single search-replace patch. Returns True on success."""
    if not os.path.exists(path):
        fail(f"{patch_name}: file not found: {path}")
        return False
    text = read(path)
    if search not in text:
        if replace in text or replace.strip() in text:
            skip(patch_name)
            return True
        fail(f"{patch_name}: search string not found in {path}")
        return False
    backup(path)
    write(path, text.replace(search, replace, 1))
    ok(patch_name)
    return True

# ── verify we are in the right directory ──────────────────────────────────────

def check_cwd():
    if not os.path.exists("src/main.rs") or not os.path.exists("Cargo.toml"):
        fail("Run this script from inside the snf-core directory (where Cargo.toml lives).")
        sys.exit(1)
    with open("Cargo.toml") as f:
        toml = f.read()
    if "snf-core" not in toml and "snf_core" not in toml:
        fail("This doesn't look like the snf-core repo (Cargo.toml doesn't mention snf-core).")
        sys.exit(1)
    ok("Working directory verified — snf-core repo detected.")

# ═════════════════════════════════════════════════════════════════════════════
#  P1 — main.rs  Windows UTF-8 console fix
# ═════════════════════════════════════════════════════════════════════════════

P1_SEARCH = '''\
fn main() {
    // No args: print help and exit cleanly'''

P1_REPLACE = '''\
fn main() {
    // ── Windows: force console to UTF-8 so box-drawing chars render correctly ──
    #[cfg(windows)]
    {
        unsafe extern "system" {
            fn SetConsoleOutputCP(wCodePageID: u32) -> i32;
            fn SetConsoleCP(wCodePageID: u32) -> i32;
        }
        // SAFETY: called at program start, before any threads spawn.
        unsafe {
            SetConsoleOutputCP(65001); // CP_UTF8
            SetConsoleCP(65001);       // CP_UTF8
        }
    }

    // No args: print help and exit cleanly'''

# ═════════════════════════════════════════════════════════════════════════════
#  P2 — capture/mod.rs  Timestamped run_<ts>/ directory
# ═════════════════════════════════════════════════════════════════════════════

P2A_SEARCH = '''\
fn default_output_path(config: &EngineConfig) -> String {
    if let Some(ref p) = config.output.ndjson_output_path { return p.clone(); }
    if let Ok(dir) = std::env::var("SNF_OUTPUT_DIR") {
        return format!("{}/snf_output.ndjson", dir.trim_end_matches('/'));
    }
    "output/snf_output.ndjson".to_string()
}'''

P2A_REPLACE = '''\
fn default_output_path(config: &EngineConfig) -> String {
    if let Some(ref p) = config.output.ndjson_output_path { return p.clone(); }
    // SNF_RUN_DIR is set once in run_capture() — use it for a consistent
    // timestamped path across all calls in the same session.
    if let Ok(run_dir) = std::env::var("SNF_RUN_DIR") {
        let ts = std::env::var("SNF_RUN_TS").unwrap_or_else(|_| "session".to_string());
        return format!("{}/snf_output_{}.ndjson", run_dir.trim_end_matches('/'), ts);
    }
    if let Ok(dir) = std::env::var("SNF_OUTPUT_DIR") {
        return format!("{}/snf_output.ndjson", dir.trim_end_matches('/'));
    }
    "output/snf_output.ndjson".to_string()
}'''

P2B_SEARCH = '''\
pub fn run_capture(ports_db: &HashMap<u16, String>, config: &EngineConfig) {
    if config.is_replay() && config.performance.worker_threads != 1 {'''

P2B_REPLACE = '''\
pub fn run_capture(ports_db: &HashMap<u16, String>, config: &EngineConfig) {
    // ── Timestamped run directory ─────────────────────────────────────────────
    // Generate run_<timestamp> subfolder ONCE before any threads spawn.
    // All calls to default_output_path() read SNF_RUN_DIR for consistency.
    {
        use chrono::Local;
        let ts      = Local::now().format("%Y-%m-%d_%H-%M-%S").to_string();
        let base    = std::env::var("SNF_OUTPUT_DIR").unwrap_or_else(|_| "output".to_string());
        let run_dir = format!("{}/run_{}", base.trim_end_matches('/'), ts);
        let _       = std::fs::create_dir_all(&run_dir);
        // SAFETY: called before any threads are spawned.
        unsafe {
            std::env::set_var("SNF_RUN_DIR", &run_dir);
            std::env::set_var("SNF_RUN_TS",  &ts);
        }
    }

    if config.is_replay() && config.performance.worker_threads != 1 {'''

# ═════════════════════════════════════════════════════════════════════════════
#  P3 — capture/mod.rs  Final session summary in shutdown()
# ═════════════════════════════════════════════════════════════════════════════

P3_SEARCH = '''\
    fn shutdown(mut self, config: &EngineConfig, output_path: &str) {
        if let Some(ref mut bus) = self.event_bus { bus.flush(); }
        match config.operation_mode {
            OperationMode::Stealth => {}
            OperationMode::Replay => {
                println!("[SNF] Replay complete - {} packets processed", self.packet_count);
            }
            _ => {
                println!("[SNF] Session complete - {} packets -> {}", self.packet_count, output_path);
            }
        }
    }'''

P3_REPLACE = '''\
    fn shutdown(mut self, config: &EngineConfig, output_path: &str) {
        if let Some(ref mut bus) = self.event_bus { bus.flush(); }
        match config.operation_mode {
            OperationMode::Stealth => {}
            OperationMode::Replay => {
                println!("[SNF] Replay complete - {} packets processed", self.packet_count);
            }
            _ => {
                println!("[SNF] Session complete - {} packets -> {}", self.packet_count, output_path);
                // Print the end-of-run summary box (non-stealth, non-replay only).
                self.session_reporter.print_final_summary(
                    self.last_timestamp_us,
                    config.operation_mode.as_str(),
                    output_path,
                );
            }
        }
    }'''

# ═════════════════════════════════════════════════════════════════════════════
#  P4 — pipeline/packet_pipeline.rs  Fix garbled Unicode
#  The source file contains valid UTF-8 literals (→ U+2192, ─ U+2500).
#  We replace them with ASCII equivalents that render correctly on every platform.
# ═════════════════════════════════════════════════════════════════════════════

def patch_pipeline(path):
    """Handle all Unicode replacements in packet_pipeline.rs.

    Root cause: the file was committed with wrong encoding, so ─ (U+2500) and
    → (U+2192) are stored as their garbled Windows-1252 re-encoded equivalents.
    We therefore cannot search for the original codepoints — instead we use
    a regex that matches any println!("...") whose string argument contains a
    run of non-ASCII characters, and replace the whole call with ASCII.
    """
    import re

    if not os.path.exists(path):
        fail(f"P4: file not found: {path}")
        return False

    # Read with errors='replace' so we don't blow up on any residual bad bytes.
    with open(path, encoding="utf-8", errors="replace") as f:
        text = f.read()

    if "print_final_summary" in text:
        # Nothing left to do — fresh build
        skip("P4 — pipeline/packet_pipeline.rs (already clean)")
        return True

    changed = False

    # ── 4a: separator println!("<<<non-ascii-only content>>>"); ──────────────
    # Matches lines like:  println!("─────────────");
    # The string arg is ONE run of non-ASCII chars with nothing else (no spaces,
    # no letters, no digits).  We replace with a fixed-count ASCII separator.
    sep_pattern = re.compile(
        r'([ \t]*)println!\("([^\x00-\x7F]+)"\);',
        re.MULTILINE
    )
    def sep_replacer(m):
        indent     = m.group(1)
        raw_chars  = m.group(2)
        # Approximate original dash count: each ─ encodes to ~3-7 non-ASCII
        # bytes garbled into several chars.  We just use 42 as the standard
        # separator length used throughout SNF.
        count = min(max(len(raw_chars) // 3, 10), 72)
        return f'{indent}println!("{{}}", "-".repeat({count}));'

    new_text = sep_pattern.sub(sep_replacer, text)
    if new_text != text:
        text = new_text
        changed = True

    # ── 4b: arrow in log lines:  "IP → IP" style strings ────────────────────
    # The → (U+2192) garbles to something containing \u2122 (™) or similar.
    # Strategy: replace any non-ASCII char that appears inside a format string
    # that also has IP-address-like context with ASCII "->".
    # We do a broad replacement: any non-ASCII char inside a Rust string that
    # sits between whitespace/digits and whitespace/digits → replace with "->".
    arrow_pattern = re.compile(
        r'([0-9a-zA-Z\}\]"\']):([^\x00-\x7F]+):([0-9a-zA-Z\{"\'])'
    )
    new_text2 = arrow_pattern.sub(r'\1->\3', text)
    if new_text2 != text:
        text = new_text2
        changed = True

    # ── 4c: any remaining stray non-ASCII in println!/eprintln! strings ──────
    # Belt-and-suspenders: catch anything the above missed.
    stray_pattern = re.compile(
        r'((?:println|eprintln|print)!\s*\([^)]*)"([^"]*[^\x00-\x7F][^"]*)"'
    )
    def stray_replacer(m):
        prefix  = m.group(1)
        content = m.group(2)
        # Replace each non-ASCII char with a plain hyphen
        cleaned = re.sub(r'[^\x00-\x7F]', '-', content)
        return f'{prefix}"{cleaned}"'

    new_text3 = stray_pattern.sub(stray_replacer, text)
    if new_text3 != text:
        text = new_text3
        changed = True

    if changed:
        backup(path)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        ok("P4 — pipeline/packet_pipeline.rs garbled Unicode chars replaced with ASCII")
        return True
    else:
        skip("P4 — pipeline/packet_pipeline.rs (no garbled chars found)")
        return True

# ═════════════════════════════════════════════════════════════════════════════
#  P5 — reporting/mod.rs  Add print_final_summary() to SessionReporter
# ═════════════════════════════════════════════════════════════════════════════

# The closing brace of the SessionReporter impl block — insert the new method before it.
# We detect the end of the last method (print_report closes with "└──...┘" then "    }").

P5_SEARCH = '''\
        println!("\\u{2514}{}\\u{2518}", "\\u{2500}".repeat(63));
    }
}'''

FINAL_SUMMARY_METHOD = '''
    /// Print a structured summary box at the END of a capture session.
    ///
    /// Called once from CaptureEngine::shutdown() after all packets are processed.
    /// Suppressed in Stealth mode (shutdown() never calls this in stealth).
    pub fn print_final_summary(&self, end_timestamp_us: u64, mode: &str, output_path: &str) {
        let elapsed_secs = end_timestamp_us
            .saturating_sub(self.session_start_us)
            .saturating_div(1_000_000);
        let pps = if elapsed_secs > 0 { self.packets / elapsed_secs } else { self.packets };

        let sep = "=".repeat(62);
        println!();
        println!("{}", sep);
        println!("  SNF-Core  |  Session Complete");
        println!("{}", sep);
        println!("  Mode      : {}", mode);
        println!("  Output    : {}", output_path);
        println!("{}", "-".repeat(62));
        println!("  Packets   : {}", self.packets);
        println!("  Events    : {}", self.events);
        println!("  Flows     : {}", self.active_flows);
        if elapsed_secs > 0 {
            println!("  Duration  : {}s  ({} pps avg)", elapsed_secs, pps);
        }
        if self.capture_drops > 0 {
            println!("  Drops     : {} (queue/ring full)", self.capture_drops);
        }

        // Protocol / event-type breakdown
        if !self.event_type_counts.is_empty() {
            println!("{}", "-".repeat(62));
            println!("  Protocol Breakdown (top 8):");
            let mut types: Vec<(&String, &u64)> = self.event_type_counts.iter().collect();
            types.sort_by(|a, b| b.1.cmp(a.1));
            for (et, count) in types.iter().take(8) {
                println!("    {:<38} {:>8}", et, count);
            }
        }

        // Top talkers
        if !self.ip_bytes.is_empty() {
            println!("{}", "-".repeat(62));
            println!("  Top Source IPs (by bytes):");
            let mut talkers: Vec<(std::net::IpAddr, u64)> =
                self.ip_bytes.iter().map(|(&ip, &b)| (ip, b)).collect();
            talkers.sort_by(|a, b| b.1.cmp(&a.1));
            for (ip, bytes) in talkers.iter().take(5) {
                let kb = bytes / 1024;
                if kb > 0 {
                    println!("    {:<38} {:>8} KB", ip, kb);
                } else {
                    println!("    {:<38} {:>8} B", ip, bytes);
                }
            }
        }

        // Behavior/anomaly findings
        if !self.finding_counts.is_empty() {
            println!("{}", "-".repeat(62));
            println!("  Findings:");
            let mut findings: Vec<(&String, &u64)> = self.finding_counts.iter().collect();
            findings.sort_by(|a, b| b.1.cmp(a.1));
            for (f, count) in findings.iter() {
                println!("    {:<38} {:>8} alerts", f, count);
            }
        }

        println!("{}", sep);
        println!();
    }
'''

def patch_reporting(path):
    """Add print_final_summary() to reporting/mod.rs."""
    if not os.path.exists(path):
        fail(f"P5: file not found: {path}")
        return False

    text = read(path)

    # Skip if already applied
    if "print_final_summary" in text:
        skip("P5 — reporting/mod.rs print_final_summary() (already present)")
        return True

    # The impl block ends with the closing brace of print_report(), then the impl closes.
    # We insert the new method just before the final closing brace of the impl block.
    # Strategy: find the last `    }\n}` in the file (end of impl block).
    last_brace_idx = text.rfind("\n    }\n}")
    if last_brace_idx == -1:
        # Try alternate endings
        last_brace_idx = text.rfind("    }\n}\n")
    if last_brace_idx == -1:
        fail("P5: could not locate end of SessionReporter impl block in reporting/mod.rs")
        return False

    backup(path)
    # Insert the new method before the final `    }` (close of print_report) and `}` (close of impl)
    insert_at = last_brace_idx + len("\n    }")   # after the print_report closing brace
    new_text = text[:insert_at] + FINAL_SUMMARY_METHOD + text[insert_at:]
    write(path, new_text)
    ok("P5 — reporting/mod.rs print_final_summary() added to SessionReporter")
    return True

# ═════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═════════════════════════════════════════════════════════════════════════════

# ══ P6/P7 patch strings ══════════════════════════════════════════════════════

P6_SEARCH  = '    /// Human-readable summary for session report.\n    pub fn summary_line(&self) -> String {\n        format!(\n            "Workers: {} | Packets: {} | Events: {} | Flows: {} | \\\\\n             Drops: {} | PPS: {:.0} | Balance: {:.2}",\n            self.worker_count,\n            self.total_packets_processed,\n            self.total_events_emitted,\n            self.total_flows_created,\n            self.total_upstream_drops,\n            self.avg_packets_per_second,\n            self.load_balance_ratio,\n        )\n    }\n}'

P6_REPLACE = '    /// Human-readable summary for session report.\n    pub fn summary_line(&self) -> String {\n        format!(\n            "Workers: {} | Packets: {} | Events: {} | Flows: {} | \\\\\n             Drops: {} | PPS: {:.0} | Balance: {:.2}",\n            self.worker_count,\n            self.total_packets_processed,\n            self.total_events_emitted,\n            self.total_flows_created,\n            self.total_upstream_drops,\n            self.avg_packets_per_second,\n            self.load_balance_ratio,\n        )\n    }\n\n    /// Print a full structured summary box at end of a multi-threaded session.\n    pub fn print_final_summary(&self, mode: &str, output_path: &str, pcap_sha256: &str) {\n        let sep  = "=".repeat(62);\n        let dsep = "-".repeat(62);\n        println!();\n        println!("{}", sep);\n        println!("  SNF-Core  |  Session Complete");\n        println!("{}", sep);\n        println!("  Mode      : {}", mode);\n        println!("  Output    : {}", output_path);\n        if !pcap_sha256.is_empty() && pcap_sha256 != "live" {\n            println!("  SHA-256   : {}", pcap_sha256);\n        }\n        println!("{}", dsep);\n        println!("  Workers   : {}", self.worker_count);\n        println!("  Packets   : {}", self.total_packets_processed);\n        println!("  Events    : {}", self.total_events_emitted);\n        println!("  Flows     : {} (across all workers)", self.total_flows_created);\n        if let Some(dur) = self.session_duration {\n            let secs = dur.as_secs_f64();\n            if secs > 0.0 {\n                println!("  Duration  : {:.1}s  ({:.0} pps avg)", secs, self.avg_packets_per_second);\n            }\n        }\n        if self.total_upstream_drops > 0 {\n            println!("  Drops     : {} (queue full)", self.total_upstream_drops);\n        }\n        if self.per_worker_packets.len() > 1 {\n            println!("{}", dsep);\n            println!("  Worker Distribution (balance: {:.2}):", self.load_balance_ratio);\n            for (i, pkts) in self.per_worker_packets.iter().enumerate() {\n                println!("    Worker {:>2}   {} pkts", i, pkts);\n            }\n        }\n        println!("{}", sep);\n        println!();\n    }\n}'

P7A_SEARCH  = '        drop(tx);\n        let stats = pool.shutdown();\n        merge_worker_shards(&output_path, num_workers);\n        snf_log!(config, "[SNF] {}", stats.summary_line());\n    } else {\n        let mut engine = CaptureEngine::new(config, &output_path, &pcap_path, capture_mode, pcap_sha256);'

P7A_REPLACE = '        drop(tx);\n        let stats = pool.shutdown();\n        merge_worker_shards(&output_path, num_workers);\n        snf_log!(config, "[SNF] {}", stats.summary_line());\n        if !config.is_stealth() {\n            stats.print_final_summary(\n                config.operation_mode.as_str(),\n                &output_path,\n                &pcap_sha256,\n            );\n        }\n    } else {\n        let mut engine = CaptureEngine::new(config, &output_path, &pcap_path, capture_mode, pcap_sha256);'

P7B_SEARCH  = '        drop(tx);\n        let stats = pool.shutdown();\n        merge_worker_shards(&output_path, num_workers);\n        snf_log!(config, "[SNF] {}", stats.summary_line());\n        return;\n    }'

P7B_REPLACE = '        drop(tx);\n        let stats = pool.shutdown();\n        merge_worker_shards(&output_path, num_workers);\n        snf_log!(config, "[SNF] {}", stats.summary_line());\n        if !config.is_stealth() {\n            stats.print_final_summary(\n                config.operation_mode.as_str(),\n                &output_path,\n                "live",\n            );\n        }\n        return;\n    }'


def patch_thread_stats(path):
    """Add print_final_summary() to AggregateStats in thread_stats.rs.
    Uses end-of-impl-block detection — avoids fragile string matching."""
    if not os.path.exists(path):
        fail(f"P6: file not found: {path}")
        return False
    text = read(path)
    if "print_final_summary" in text:
        skip("P6 — threading/thread_stats.rs (already present)")
        return True
    # Find end of AggregateStats impl block — the very last `}` in the file.
    last_brace = text.rfind("\n}")
    if last_brace == -1:
        fail("P6: could not locate end of AggregateStats impl block")
        return False
    # Insert new method before the final closing brace.
    insert_at = last_brace + 1   # after the \n, before the }
    new_text = text[:insert_at] + '\n    /// Print a full structured summary box at end of a multi-threaded session.\n    ///\n    /// Called from capture/mod.rs after pool.shutdown() + merge_worker_shards().\n    pub fn print_final_summary(&self, mode: &str, output_path: &str, pcap_sha256: &str) {\n        let sep  = "=".repeat(62);\n        let dsep = "-".repeat(62);\n        println!();\n        println!("{}", sep);\n        println!("  SNF-Core  |  Session Complete");\n        println!("{}", sep);\n        println!("  Mode      : {}", mode);\n        println!("  Output    : {}", output_path);\n        if !pcap_sha256.is_empty() && pcap_sha256 != "live" {\n            println!("  SHA-256   : {}", pcap_sha256);\n        }\n        println!("{}", dsep);\n        println!("  Workers   : {}", self.worker_count);\n        println!("  Packets   : {}", self.total_packets_processed);\n        println!("  Events    : {}", self.total_events_emitted);\n        println!("  Flows     : {} (across all workers)", self.total_flows_created);\n        if let Some(dur) = self.session_duration {\n            let secs = dur.as_secs_f64();\n            if secs > 0.0 {\n                println!("  Duration  : {:.1}s  ({:.0} pps avg)", secs, self.avg_packets_per_second);\n            }\n        }\n        if self.total_upstream_drops > 0 {\n            println!("  Drops     : {} (queue full)", self.total_upstream_drops);\n        }\n        if self.per_worker_packets.len() > 1 {\n            println!("{}", dsep);\n            println!("  Worker Distribution (balance: {:.2}):", self.load_balance_ratio);\n            for (i, pkts) in self.per_worker_packets.iter().enumerate() {\n                println!("    Worker {:>2}   {} pkts", i, pkts);\n            }\n        }\n        println!("{}", sep);\n        println!();\n    }\n' + text[insert_at:]
    backup(path)
    write(path, new_text)
    ok("P6 — threading/thread_stats.rs print_final_summary() added to AggregateStats")
    return True

def main():
    banner("SNF-Core Patcher")
    print("  Applying bug fixes and improvements to the public repo.\n")

    check_cwd()

    results = []

    # P1 — main.rs Windows UTF-8 fix
    banner("P1  main.rs — Windows UTF-8 console fix")
    results.append(patch_file(
        "src/main.rs",
        P1_SEARCH,
        P1_REPLACE,
        "P1 — main.rs SetConsoleOutputCP"
    ))

    # P2a — capture/mod.rs default_output_path
    banner("P2a  capture/mod.rs — timestamped default_output_path()")
    results.append(patch_file(
        "src/capture/mod.rs",
        P2A_SEARCH,
        P2A_REPLACE,
        "P2a — capture/mod.rs default_output_path()"
    ))

    # P2b — capture/mod.rs run_capture() timestamp setup
    banner("P2b  capture/mod.rs — run_<ts>/ directory setup in run_capture()")
    results.append(patch_file(
        "src/capture/mod.rs",
        P2B_SEARCH,
        P2B_REPLACE,
        "P2b — capture/mod.rs run_<ts>/ directory in run_capture()"
    ))

    # P3 — capture/mod.rs final session summary
    banner("P3  capture/mod.rs — final session summary in shutdown()")
    results.append(patch_file(
        "src/capture/mod.rs",
        P3_SEARCH,
        P3_REPLACE,
        "P3 — capture/mod.rs shutdown() final summary call"
    ))

    # P4 — pipeline/packet_pipeline.rs Unicode fix
    banner("P4  pipeline/packet_pipeline.rs — fix garbled Unicode chars")
    results.append(patch_pipeline("src/pipeline/packet_pipeline.rs"))

    # P5 — reporting/mod.rs add print_final_summary()
    banner("P5  reporting/mod.rs — add print_final_summary()")
    results.append(patch_reporting("src/reporting/mod.rs"))

    # P6 — thread_stats.rs add print_final_summary() to AggregateStats
    banner("P6  threading/thread_stats.rs — add print_final_summary() to AggregateStats")
    results.append(patch_thread_stats("src/threading/thread_stats.rs"))

    # P7a — capture/mod.rs multi-threaded pcap path calls summary
    banner("P7a  capture/mod.rs — multi-thread PCAP path prints summary box")
    results.append(patch_file(
        "src/capture/mod.rs",
        P7A_SEARCH,
        P7A_REPLACE,
        "P7a — run_pcap_file() multi-thread summary"
    ))

    # P7b — capture/mod.rs multi-threaded live path calls summary
    banner("P7b  capture/mod.rs — multi-thread live path prints summary box")
    results.append(patch_file(
        "src/capture/mod.rs",
        P7B_SEARCH,
        P7B_REPLACE,
        "P7b — run_live_capture() multi-thread summary"
    ))

    # Summary
    banner("Patch Summary")
    passed = sum(1 for r in results if r)
    failed = len(results) - passed
    print(f"  Applied : {passed}/{len(results)} patches")
    if failed:
        print(f"  {RED}Failed  : {failed} — review errors above{RESET}")
        print(f"\n  {RED}Fix errors before running cargo build.{RESET}")
        sys.exit(1)
    else:
        print(f"\n  {GREEN}All patches applied. Now run:{RESET}")
        print(f"    cargo build --release 2>&1 | Select-String 'error|warning|Finished'")
        print(f"\n  Backup files created as <file>.bak")

if __name__ == "__main__":
    main()
