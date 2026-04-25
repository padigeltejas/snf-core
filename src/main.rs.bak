pub mod capture;
pub mod analyzers;
pub mod core;
pub mod pipeline;
pub mod flow;
pub mod config;
pub mod dataset;
pub mod output;
pub mod parser;
pub mod platform;
pub mod threading;
pub mod reporting;
pub mod determinism;
pub mod discovery;

use config::cli::{parse_cli, print_help, print_version, apply_cli_to_builder};
use dataset::ports;
use crate::dataset::ja3_db::load_ja3_database;
use crate::dataset::ja4_db::load_ja4_database;

fn load_snf_toml() {
    let content = match std::fs::read_to_string("snf.toml") {
        Ok(c)  => c,
        Err(_) => return,
    };
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() { continue; }
        let mut parts = line.splitn(2, '=');
        let key   = match parts.next() { Some(k) => k.trim(), None => continue };
        let value = match parts.next() { Some(v) => v.trim().trim_matches('"'), None => continue };
        match key {
            "output_dir" => {
                if let Err(e) = std::fs::create_dir_all(value) {
                    eprintln!("[SNF] Warning: could not create output_dir '{}': {}", value, e);
                } else {
                    unsafe { std::env::set_var("SNF_OUTPUT_DIR", value); }
                }
            }
            "max_memory_mb" => {
                if let Ok(mb) = value.parse::<usize>() {
                    unsafe { std::env::set_var("SNF_MAX_MEMORY_MB", mb.to_string()); }
                }
            }
            _ => {}
        }
    }
}

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

    // No args: print help and exit cleanly
    if std::env::args().count() == 1 {
        println!("SNF-Core — Shadow Network Fingerprinting Engine");
        print_help();
        return;
    }

    load_snf_toml();

    println!("SNF-Core — Shadow Network Fingerprinting Engine");

    let args = parse_cli();

    if args.help    { print_help();    return; }
    if args.version { print_version(); return; }

    let builder = apply_cli_to_builder(&args);

    if args.dry_run {
        println!("[SNF DRY-RUN] Validating configuration...");
        let _config = builder.validate_and_build(true);
        println!("[SNF DRY-RUN] Validation complete.");
        return;
    }

    let mut config = builder.validate_and_build(false);

    let ports_db = ports::load_ports();
    println!("Loaded {} ports", ports_db.len());

    let ja3_db = load_ja3_database();
    println!("Loaded {} JA3 fingerprints", ja3_db.len());
    config.ja3_db = ja3_db;

    let ja4_db = load_ja4_database();
    println!("Loaded {} JA4 fingerprints", ja4_db.len());
    config.ja4_db = ja4_db;

    if args.determinism_check {
        let output_base = args.determinism_output
            .as_deref()
            .unwrap_or("snf_determinism")
            .to_string();
        let result = determinism::run_determinism_check(
            &config, &ports_db, &output_base, args.keep_determinism_files,
        );
        determinism::print_result(&result);
        if result.passed { std::process::exit(0); }
        else if result.hash_pass1.is_empty() || result.hash_pass2.is_empty() { std::process::exit(2); }
        else { std::process::exit(1); }
    }

    capture::run_capture(&ports_db, &config);
}
