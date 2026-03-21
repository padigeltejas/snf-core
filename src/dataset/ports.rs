// ports.rs
// Loads IANA service names and port numbers dataset

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

pub fn load_ports() -> HashMap<u16, String> {

    // store port → service mapping
    let mut ports = HashMap::new();

    // build absolute dataset path
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("datasets/service-names-port-numbers.csv");

    // open CSV dataset
    let file = File::open(path)
        .expect("Failed to open ports dataset");

    let reader = BufReader::new(file);

    // skip CSV header
    for line in reader.lines().skip(1) {
        if let Ok(row) = line {

            let cols: Vec<&str> = row.split(',').collect();

            if cols.len() > 1 {
                if let Ok(port) = cols[1].parse::<u16>() {

                    let service = cols[0].to_string();

                    ports.insert(port, service);
                }
            }
        }
    }

    ports
}

pub fn get_service(port: u16, db: &HashMap<u16, String>) -> String {

    match db.get(&port) {
        Some(service) => service.clone(),
        None => "UNKNOWN".to_string(),
    }

}