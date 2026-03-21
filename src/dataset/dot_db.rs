// snf_core/src/dataset/dot_db.rs

use std::collections::HashMap;
use crate::dataset::dot_providers::builtin_dot_providers;
use crate::dataset::dot_learning::load_learned_dot;

#[derive(Clone)]
pub struct DotEntry {
    pub classification: String,      // "standard" | "non_standard"
    pub first_seen_utc: String,
}

pub struct DotDatabase {
    builtin: HashMap<String, DotEntry>,
    learned: HashMap<String, DotEntry>,
}

impl DotDatabase {

    pub fn new(learned_path: &str) -> Self {

        // ---- Load Builtin Providers ----
        let mut builtin_map = HashMap::new();

        for domain in builtin_dot_providers() {
            builtin_map.insert(
                domain,
                DotEntry {
                    classification: "standard".to_string(),
                    first_seen_utc: "builtin".to_string(),
                },
            );
        }

        // ---- Load Learned Providers ----
        let learned_map = load_learned_dot(learned_path);

        Self {
            builtin: builtin_map,
            learned: learned_map,
        }
    }

    pub fn is_known_builtin(&self, domain: &str) -> bool {
        self.builtin.contains_key(domain)
    }

    pub fn is_known_learned(&self, domain: &str) -> bool {
        self.learned.contains_key(domain)
    }

    pub fn insert_learned(&mut self, domain: String, entry: DotEntry) {
        self.learned.insert(domain, entry);
    }
}