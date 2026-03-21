// snf_core/src/dataset/dot_learning.rs

use std::collections::HashMap;
use std::fs::{OpenOptions, File};
use std::io::{Write, BufRead, BufReader};
use std::path::Path;
use chrono::Utc;
use crate::dataset::dot_db::DotEntry;

pub fn load_learned_dot(path: &str) -> HashMap<String, DotEntry> {

    let mut map = HashMap::new();

    if !Path::new(path).exists() {
        return map;
    }

    if let Ok(file) = File::open(path) {
        let reader = BufReader::new(file);

        for line in reader.lines().flatten() {
            let parts: Vec<&str> = line.split(',').collect();

            if parts.len() != 3 {
                continue;
            }

            let domain = parts[0].trim().to_lowercase();
            let classification = parts[1].trim().to_string();
            let timestamp = parts[2].trim().to_string();

            map.insert(
                domain,
                DotEntry {
                    classification,
                    first_seen_utc: timestamp,
                },
            );
        }
    }

    map
}

pub fn append_learned_dot(
    path: &str,
    domain: &str,
    classification: &str,
) -> std::io::Result<DotEntry> {

    let timestamp = Utc::now().to_rfc3339();

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;

    writeln!(file, "{},{},{}", domain, classification, timestamp)?;

    Ok(DotEntry {
        classification: classification.to_string(),
        first_seen_utc: timestamp,
    })
}