// ja4_db.rs
// Loads JA4 fingerprint database into memory at startup.
// Returns empty map (with warning) if the CSV is missing — JA4 lookups
// are disabled but SNF continues running normally.

use std::collections::HashMap;
use std::io::BufRead;

pub fn load_ja4_database() -> HashMap<String, String> {
    let path = "datasets/ja4/ja4_fingerprints.csv";
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!(
                "[SNF] Warning: JA4 database not found at '{}': {} — JA4 lookups disabled",
                path, e
            );
            return HashMap::new();
        }
    };
    let reader = std::io::BufReader::new(file);
    let mut map: HashMap<String, String> = HashMap::new();
    for line in reader.lines().skip(1) {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };
        let cols: Vec<&str> = line.splitn(3, ',').collect();
        if cols.len() >= 2 {
            map.insert(cols[0].trim().to_string(), cols[1].trim().to_string());
        }
    }
    eprintln!("[SNF] Loaded {} JA4 fingerprints", map.len());
    map
}