// src/determinism/mod.rs
//
// Phase 13B — PCAP Replay Determinism Test Harness.
//
// Verifies the SNF determinism contract:
//
//   F(pcap, config, snf_version) => byte-identical NDJSON event sequence every run.
//
// Invoked from main.rs when --determinism-check is passed.
// Requires --pcap-file. Output base path is derived from --output or defaults to
// "snf_determinism" in the current working directory.
//
// Procedure:
//   1. Clone config into two identical replay configs.
//   2. Run capture pass 1 → <base>_pass1.ndjson
//   3. Run capture pass 2 → <base>_pass2.ndjson
//   4. SHA-256 both output files.
//   5. Compare hashes — constant-time to prevent timing side-channels.
//   6. If mismatch, scan for the first diverging line and report it.
//   7. Print verdict. Exit 0 on PASS, exit 1 on FAIL, exit 2 on setup ERROR.
//
// Security constraints enforced here:
//   - PCAP path validated (no null bytes, no parent-dir components).
//   - Output paths sanitized (no null bytes).
//   - SHA-256 comparison uses constant-time fold — no early-exit on mismatch.
//   - Intermediate files are cleaned up on both success and failure unless
//     --keep-determinism-files is set.
//   - File scan for divergence is capped at MAX_SCAN_LINES (10M) to prevent
//     OOM on adversarially large output files.
//   - Diverging line samples are truncated to MAX_SAMPLE_LEN chars before print.

use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use sha2::{Sha256, Digest};

use crate::config::engine_config::EngineConfig;


// ----------------------------------------------------------------
// CONSTANTS
// ----------------------------------------------------------------

/// Maximum number of lines scanned when looking for first divergence.
/// Prevents OOM on adversarially large output files.
const MAX_SCAN_LINES: usize = 10_000_000;

/// Maximum chars from a diverging line included in the report.
/// Prevents huge terminal output from embedding enormous JSON blobs.
const MAX_SAMPLE_LEN: usize = 200;

/// I/O chunk size for SHA-256 hashing.
const HASH_BUF_SIZE: usize = 65_536;

// ----------------------------------------------------------------
// RESULT TYPE
// ----------------------------------------------------------------

/// Full result of a determinism check run.
#[derive(Debug)]
pub struct DeterminismResult {
    /// True if both passes produced byte-identical NDJSON output.
    pub passed: bool,

    /// SHA-256 hex of pass 1 output file.
    pub hash_pass1: String,

    /// SHA-256 hex of pass 2 output file.
    pub hash_pass2: String,

    /// Non-empty line count in pass 1 output (≈ event count).
    pub event_count_pass1: usize,

    /// Non-empty line count in pass 2 output (≈ event count).
    pub event_count_pass2: usize,

    /// 1-indexed line number where pass1 and pass2 first diverged, if any.
    pub first_divergence_line: Option<usize>,

    /// Truncated content of the diverging line in pass 1.
    pub divergence_pass1_sample: Option<String>,

    /// Truncated content of the diverging line in pass 2.
    pub divergence_pass2_sample: Option<String>,

    /// Human-readable one-line verdict for logging.
    pub message: String,
}

// ----------------------------------------------------------------
// INTERNAL HELPERS
// ----------------------------------------------------------------

/// Compute SHA-256 of a file, streaming in HASH_BUF_SIZE chunks.
/// Returns lowercase hex string, or an error string on I/O failure.
fn sha256_file(path: &str) -> Result<String, String> {
    let file = fs::File::open(path)
        .map_err(|e| format!("cannot open '{}' for hashing: {}", path, e))?;

    let mut reader = BufReader::with_capacity(HASH_BUF_SIZE, file);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; HASH_BUF_SIZE];

    loop {
        match reader.read(&mut buf) {
            Ok(0)  => break,
            Ok(n)  => hasher.update(&buf[..n]),
            Err(e) => return Err(format!("read error in '{}': {}", path, e)),
        }
    }

    Ok(format!("{:x}", hasher.finalize()))
}

/// Count non-empty lines in a file. Used to report approximate event counts.
fn count_nonempty_lines(path: &str) -> Result<usize, String> {
    let file = fs::File::open(path)
        .map_err(|e| format!("cannot open '{}': {}", path, e))?;

    let count = BufReader::new(file)
        .lines()
        .filter(|l| l.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false))
        .count();

    Ok(count)
}

/// Scan two NDJSON files line-by-line and return the first differing position.
/// Returns Ok(None) if files are identical up to MAX_SCAN_LINES.
/// Returns Ok(Some((line_number, pass1_sample, pass2_sample))) on first mismatch.
/// Line number is 1-indexed.
fn find_first_divergence(
    path1: &str,
    path2: &str,
) -> Result<Option<(usize, String, String)>, String> {
    let f1 = fs::File::open(path1)
        .map_err(|e| format!("cannot open pass1 '{}': {}", path1, e))?;
    let f2 = fs::File::open(path2)
        .map_err(|e| format!("cannot open pass2 '{}': {}", path2, e))?;

    let lines1 = BufReader::new(f1).lines();
    let lines2 = BufReader::new(f2).lines();

    for (idx, (l1_res, l2_res)) in lines1.zip(lines2).enumerate().take(MAX_SCAN_LINES) {
        let l1 = l1_res
            .map_err(|e| format!("read error in pass1 at line {}: {}", idx + 1, e))?;
        let l2 = l2_res
            .map_err(|e| format!("read error in pass2 at line {}: {}", idx + 1, e))?;

        if l1 != l2 {
            // Truncate samples to MAX_SAMPLE_LEN to avoid flooding the terminal.
            let s1 = l1.chars().take(MAX_SAMPLE_LEN).collect::<String>();
            let s2 = l2.chars().take(MAX_SAMPLE_LEN).collect::<String>();
            return Ok(Some((idx + 1, s1, s2)));
        }
    }

    Ok(None)
}

/// Constant-time byte-slice equality comparison.
/// Returns true if slices are identical, never short-circuiting on mismatch.
/// Prevents timing side-channels in automated test pipelines.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a.iter().zip(b.iter()).fold(0u8, |acc, (&x, &y)| acc | (x ^ y));
    diff == 0
}

/// Validate an output path: no null bytes, parent dir component check.
/// Returns Err with a human-readable message if invalid.
fn validate_output_path(path: &str) -> Result<(), String> {
    if path.contains('\0') {
        return Err(format!("output path '{}' contains null byte", path));
    }
    // Ensure parent directory exists or can be created.
    let parent = Path::new(path).parent().unwrap_or(Path::new("."));
    if !parent.as_os_str().is_empty() && !parent.exists() {
        return Err(format!(
            "output directory '{}' does not exist for path '{}'",
            parent.display(),
            path
        ));
    }
    Ok(())
}

// ----------------------------------------------------------------
// PUBLIC API
// ----------------------------------------------------------------

/// Run the full determinism check against a PCAP file.
///
/// `config` must already have `capture.pcap_file` set and
/// `capture.capture_mode` = "pcap". The output base path for the two
/// intermediate files is derived from `output_base`.
///
/// This function calls `crate::capture::run_capture` twice with identical
/// configs (except for the output path) and compares the resulting NDJSON files.
///
/// Returns a `DeterminismResult` — the caller is responsible for printing
/// it and deciding the exit code.
pub fn run_determinism_check(
    config: &EngineConfig,
    ports_db: &std::collections::HashMap<u16, String>,
    output_base: &str,
    keep_files: bool,
) -> DeterminismResult {
    let pass1_path = format!("{}_pass1.ndjson", output_base);
    let pass2_path = format!("{}_pass2.ndjson", output_base);

    // ---- Validate PCAP path ----
    let pcap_path = match &config.capture.pcap_file {
        Some(p) => p.clone(),
        None => {
            return error_result(
                "--determinism-check requires --pcap-file to be set.",
            );
        }
    };

    if pcap_path.contains('\0') {
        return error_result("PCAP path contains a null byte — refusing.");
    }

    // Parent-dir traversal check
    for component in Path::new(&pcap_path).components() {
        use std::path::Component;
        if matches!(component, Component::ParentDir) {
            return error_result(&format!(
                "PCAP path '{}' contains '..' — refusing for security.",
                pcap_path
            ));
        }
    }

    if !Path::new(&pcap_path).exists() {
        return error_result(&format!(
            "PCAP file '{}' does not exist.",
            pcap_path
        ));
    }

    // ---- Validate output paths ----
    if let Err(e) = validate_output_path(&pass1_path) {
        return error_result(&format!("Pass 1 output path invalid: {}", e));
    }
    if let Err(e) = validate_output_path(&pass2_path) {
        return error_result(&format!("Pass 2 output path invalid: {}", e));
    }

    // ---- Build two identical replay configs (only output path differs) ----
    // Both passes are forced to single-threaded replay mode — this is the
    // only valid configuration for determinism testing.
    let mut cfg1 = config.clone();
    cfg1.capture.capture_mode       = "pcap".to_string();
    cfg1.capture.pcap_file          = Some(pcap_path.clone());
    cfg1.performance.worker_threads = 1;
    cfg1.output.ndjson_output_path  = Some(pass1_path.clone());

    let mut cfg2 = cfg1.clone();
    cfg2.output.ndjson_output_path  = Some(pass2_path.clone());

    // ---- Pass 1 ----
    eprintln!("[SNF DETERMINISM] Pass 1 → {}", pass1_path);
    crate::capture::run_capture(ports_db, &cfg1);

    // Confirm output file was written before proceeding.
    if !Path::new(&pass1_path).exists() {
        return error_result(&format!(
            "Pass 1 did not produce output file '{}'. \
             Check that capture ran successfully and ndjson_output_path is writable.",
            pass1_path
        ));
    }

    // ---- Pass 2 ----
    eprintln!("[SNF DETERMINISM] Pass 2 → {}", pass2_path);
    crate::capture::run_capture(ports_db, &cfg2);

    if !Path::new(&pass2_path).exists() {
        return error_result(&format!(
            "Pass 2 did not produce output file '{}'. \
             Check that capture ran successfully.",
            pass2_path
        ));
    }

    // ---- Hash both outputs ----
    let hash1 = match sha256_file(&pass1_path) {
        Ok(h)  => h,
        Err(e) => return error_result(&format!("SHA-256 error on pass1: {}", e)),
    };

    let hash2 = match sha256_file(&pass2_path) {
        Ok(h)  => h,
        Err(e) => return error_result(&format!("SHA-256 error on pass2: {}", e)),
    };

    // ---- Count events ----
    let count1 = count_nonempty_lines(&pass1_path).unwrap_or(0);
    let count2 = count_nonempty_lines(&pass2_path).unwrap_or(0);

    // ---- Constant-time hash comparison ----
    let hashes_match = constant_time_eq(hash1.as_bytes(), hash2.as_bytes());

    // ---- Clean up on success ----
    if hashes_match {
        if !keep_files {
            if let Err(e) = fs::remove_file(&pass1_path) {
                eprintln!("[SNF DETERMINISM] Warning: could not remove pass1 file: {}", e);
            }
            if let Err(e) = fs::remove_file(&pass2_path) {
                eprintln!("[SNF DETERMINISM] Warning: could not remove pass2 file: {}", e);
            }
        }

        return DeterminismResult {
            passed: true,
            hash_pass1: hash1.clone(),
            hash_pass2: hash2,
            event_count_pass1: count1,
            event_count_pass2: count2,
            first_divergence_line: None,
            divergence_pass1_sample: None,
            divergence_pass2_sample: None,
            message: format!(
                "[SNF DETERMINISM] PASS — {} events, SHA-256: {}",
                count1,
                hash1
            ),
        };
    }

    // ---- Hashes differ — find first diverging line ----
    // (we leave the files in place regardless of keep_files so the operator can diff them)
    let divergence = find_first_divergence(&pass1_path, &pass2_path)
        .unwrap_or(None);

    let (div_line, div_s1, div_s2) = match divergence {
        Some((ln, s1, s2)) => (Some(ln), Some(s1), Some(s2)),
        None               => (None, None, None),
    };

    let message = match div_line {
        Some(ln) => format!(
            "[SNF DETERMINISM] FAIL — diverged at line {}. \
             Pass1: {} events sha256={} | Pass2: {} events sha256={}",
            ln, count1, hash1, count2, hash2
        ),
        None => format!(
            "[SNF DETERMINISM] FAIL — SHA-256 mismatch, line scan inconclusive. \
             Pass1: {} events sha256={} | Pass2: {} events sha256={}",
            count1, hash1, count2, hash2
        ),
    };

    DeterminismResult {
        passed: false,
        hash_pass1: hash1,
        hash_pass2: hash2,
        event_count_pass1: count1,
        event_count_pass2: count2,
        first_divergence_line: div_line,
        divergence_pass1_sample: div_s1,
        divergence_pass2_sample: div_s2,
        message,
    }
}

/// Print the full determinism verdict to stdout/stderr.
///
/// PASS diagnostics go to stdout. FAIL and ERROR diagnostics go to stderr.
/// Called by main.rs after run_determinism_check returns.
pub fn print_result(result: &DeterminismResult) {
    if result.passed {
        // PASS — stdout only
        println!("{}", result.message);
        println!("[SNF DETERMINISM] Contract verified:");
        println!("  F(pcap, config, snf_version) = identical output — every run.");
    } else {
        // FAIL — full diagnostic to stderr
        eprintln!("{}", result.message);

        if let (Some(line), Some(s1), Some(s2)) = (
            result.first_divergence_line,
            &result.divergence_pass1_sample,
            &result.divergence_pass2_sample,
        ) {
            eprintln!("[SNF DETERMINISM] First divergence at line {}:", line);
            eprintln!("  Pass1: {}", s1);
            eprintln!("  Pass2: {}", s2);
        }

        eprintln!("[SNF DETERMINISM] Determinism contract VIOLATED.");
        eprintln!("[SNF DETERMINISM] Common root causes:");
        eprintln!("  - HashMap used for attributes — fix: BTreeMap (already enforced in SnfEvent)");
        eprintln!("  - SystemTime / Instant used for timestamps — fix: use pcap header ts only");
        eprintln!("  - Random seed not fixed — fix: set flow_hash_seed = 0 in replay config");
        eprintln!("  - Thread-local / global state not reset between runs");
        eprintln!("  - RDNS learning enabled — fix: set rdns_learning_enabled = false in replay");
        eprintln!("  - worker_threads > 1 — fix: replay requires single-threaded execution");
        eprintln!("[SNF DETERMINISM] Intermediate files kept for manual diff:");
        eprintln!("  diff <pass1_file> <pass2_file>");
    }
}

// ----------------------------------------------------------------
// INTERNAL: error convenience constructor
// ----------------------------------------------------------------

/// Build a DeterminismResult that represents a setup error (not a FAIL verdict).
fn error_result(msg: &str) -> DeterminismResult {
    DeterminismResult {
        passed: false,
        hash_pass1: String::new(),
        hash_pass2: String::new(),
        event_count_pass1: 0,
        event_count_pass2: 0,
        first_divergence_line: None,
        divergence_pass1_sample: None,
        divergence_pass2_sample: None,
        message: format!("[SNF DETERMINISM] ERROR: {}", msg),
    }
}