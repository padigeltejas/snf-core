// snf_core/src/analyzers/doh.rs

use crate::dataset::doh_db::DohDatabase;
use crate::dataset::doh_learning::append_learned_doh;

pub struct DohConfig {
    pub learned_path: String,
    pub learning_enabled: bool,
    pub min_confidence_score: u8,
}

pub struct DohIndicators<'a> {
    pub domain: &'a str,
    pub alpn: Option<&'a str>,
    pub http_path: Option<&'a str>,
    pub content_type: Option<&'a str>,
}

pub struct DohAnalyzer {
    db: DohDatabase,
    config: DohConfig,
}

impl DohAnalyzer {
    pub fn new(config: DohConfig) -> Self {
        let db = DohDatabase::new(&config.learned_path);
        Self { db, config }
    }

    pub fn analyze(&self, indicators: DohIndicators) {
        let domain = indicators.domain.trim().to_lowercase();

        // ---------------- STRICT DoH CONFIDENCE SCORING ----------------
        let mut score: u8 = 0;

        if indicators.alpn == Some("h2") {
            score += 1;
        }

        if indicators.http_path == Some("/dns-query") {
            score += 1;
        }

        if indicators.content_type == Some("application/dns-message") {
            score += 1;
        }

        let strong_detection = score >= self.config.min_confidence_score;

        if !strong_detection {
            return;
        }

        // ---------------- STATIC / LEARNED DATABASE CHECK ----------------
        if self.db.is_known_builtin(&domain) {
            println!("[DoH] Known Built-in Provider: {}", domain);
            return;
        }

        if self.db.is_known_learned(&domain) {
            println!("[DoH] Known Learned Provider: {}", domain);
            return;
        }

        // ---------------- NEW HIGH-CONFIDENCE PROVIDER ----------------
        println!("[DoH] High-confidence DoH detected: {}", domain);

        if self.config.learning_enabled {
            if let Err(e) = append_learned_doh(&self.config.learned_path, &domain) {
                eprintln!("[DoH] Failed to persist learned provider: {}", e);
            } else {
                println!("[DoH] NEW PROVIDER LEARNED: {}", domain);
            }
        }
    }
}