use std::process::Command;
use std::fs;

// ── helpers ──────────────────────────────────────────────────────────────────

fn snf_bin() -> std::path::PathBuf {
    // CARGO_BIN_EXE_snf-core is set by Cargo during `cargo test`
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_snf-core"))
}

fn sample_pcap() -> std::path::PathBuf {
    // Committed test fixture — small, deterministic, version-controlled
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("sample.pcap")
}

/// SHA-256 hash of a file's full contents.
fn sha256_file(path: &std::path::Path) -> String {
   
    // Using std sha2 via ring or sha2 crate. For zero extra deps we shell out.
    let output = Command::new("sha256sum")
        .arg(path)
        .output()
        .or_else(|_| {
            // Windows fallback: certutil
            Command::new("certutil")
                .args(["-hashfile", path.to_str().unwrap(), "SHA256"])
                .output()
        })
        .expect("No sha256 tool available (need sha256sum or certutil)");

    let stdout = String::from_utf8_lossy(&output.stdout);
    // sha256sum: "<hash>  <filename>"
    // certutil:  multi-line, hash on second line
    stdout
        .lines()
        .find(|l| l.len() >= 64 && l.chars().take(64).all(|c| c.is_ascii_hexdigit()))
        .unwrap_or_else(|| panic!("Could not parse SHA-256 from output:\n{}", stdout))
        .split_whitespace()
        .next()
        .unwrap()
        .to_lowercase()
}

/// Run snf-core in --replay mode against the sample PCAP.
/// Returns the path to the output NDJSON file.
fn run_replay(output_dir: &std::path::Path) -> std::path::PathBuf {
    let status = Command::new(snf_bin())
        .args([
            "--replay",
            "--pcap-file",
            sample_pcap().to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--no-auto-scale", // force single-threaded for determinism
        ])
        .status()
        .expect("Failed to launch snf-core binary");

    assert!(status.success(), "snf-core exited with non-zero status: {}", status);

    // Find the emitted NDJSON file
    let entries: Vec<_> = fs::read_dir(output_dir)
        .expect("Cannot read output dir")
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|x| x == "ndjson")
                .unwrap_or(false)
        })
        .collect();

    assert_eq!(
        entries.len(), 1,
        "Expected exactly 1 NDJSON output file, found {}",
        entries.len()
    );

    entries[0].path()
}

// ── tests ────────────────────────────────────────────────────────────────────

/// Core determinism proof:
/// Run the same PCAP twice in --replay mode and assert SHA-256 identical output.
///
/// This is the guarantee SNF-Core makes: F(dataset, config, version) → identical output.
/// If this test fails, the determinism contract is broken.
#[test]
fn test_determinism_identical_runs() {
    let dir1 = tempfile::tempdir().expect("Cannot create temp dir 1");
    let dir2 = tempfile::tempdir().expect("Cannot create temp dir 2");

    let out1 = run_replay(dir1.path());
    let out2 = run_replay(dir2.path());

    let hash1 = sha256_file(&out1);
    let hash2 = sha256_file(&out2);

    assert_eq!(
        hash1, hash2,
        "DETERMINISM VIOLATION: two identical runs produced different output.\n\
         Run 1: {}\n\
         Run 2: {}",
        hash1, hash2
    );
}

/// Sanity check: output must be non-empty (binary actually processed something).
#[test]
fn test_output_is_non_empty() {
    let dir = tempfile::tempdir().expect("Cannot create temp dir");
    let out = run_replay(dir.path());

    let metadata = fs::metadata(&out).expect("Cannot stat output file");
    assert!(
        metadata.len() > 0,
        "Output NDJSON is empty — binary produced no events"
    );
}

/// Sanity check: every line in the output must be valid JSON.
#[test]
fn test_output_is_valid_ndjson() {
    let dir = tempfile::tempdir().expect("Cannot create temp dir");
    let out = run_replay(dir.path());

    let content = fs::read_to_string(&out).expect("Cannot read output file");

    for (i, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        serde_json::from_str::<serde_json::Value>(line).unwrap_or_else(|e| {
            panic!("Line {} is not valid JSON: {}\nContent: {}", i + 1, e, line)
        });
    }
}

/// CLI smoke test: --version must exit 0 and print recognizable output.
#[test]
fn test_cli_version_flag() {
    let output = Command::new(snf_bin())
        .arg("--version")
        .output()
        .expect("Failed to execute snf-core --version");

    assert!(
        output.status.success(),
        "snf-core --version exited non-zero"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("snf-core") || stdout.contains("SNF"),
        "Unexpected --version output: {}",
        stdout
    );
}