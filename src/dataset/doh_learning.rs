// snf_core/src/dataset/doh_learning.rs

use std::collections::HashSet;
use std::fs::{OpenOptions, File};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

pub fn load_learned_doh(path: &str) -> HashSet<String> {
    let mut set = HashSet::new();

    if !Path::new(path).exists() {
        return set;
    }

    let file = File::open(path).expect("Failed to open learned DoH file");
    let reader = BufReader::new(file);

    for domain in reader.lines().map_while(Result::ok) {
        let domain = domain.trim().to_lowercase();
        if !domain.is_empty() {
            set.insert(domain);
        }
    }

    set
}

pub fn append_learned_doh(path: &str, domain: &str) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;

    writeln!(file, "{}", domain)?;

    Ok(())
}