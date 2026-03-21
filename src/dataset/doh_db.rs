// snf_core/src/dataset/doh_db.rs

use std::collections::HashSet;
use std::sync::Arc;

use super::doh_providers::builtin_doh_providers;
use super::doh_learning::load_learned_doh;

#[derive(Clone)]
pub struct DohDatabase {
    builtin: Arc<HashSet<String>>,
    learned: Arc<HashSet<String>>,
    runtime: Arc<HashSet<String>>,
}

impl DohDatabase {
    pub fn new(learned_path: &str) -> Self {
        let builtin = builtin_doh_providers();
        let learned = load_learned_doh(learned_path);

        let mut runtime = builtin.clone();
        runtime.extend(learned.iter().cloned());

        Self {
            builtin: Arc::new(builtin),
            learned: Arc::new(learned),
            runtime: Arc::new(runtime),
        }
    }

    pub fn is_known_builtin(&self, domain: &str) -> bool {
        self.builtin.contains(domain)
    }

    pub fn is_known_learned(&self, domain: &str) -> bool {
        self.learned.contains(domain)
    }

    pub fn is_known(&self, domain: &str) -> bool {
        self.runtime.contains(domain)
    }

    pub fn total_count(&self) -> usize {
        self.runtime.len()
    }
}