// snf_core/src/analyzers/dot.rs

use crate::dataset::dot_db::DotDatabase;
use crate::dataset::dot_learning::append_learned_dot;

pub struct DotConfig {
    pub learned_path: String,
    pub learning_enabled: bool,
    pub min_confidence_score: u8,
}

pub struct DotIndicators<'a> {
    pub domain: Option<&'a str>,
    pub dst_port: u16,
    pub tls_detected: bool,
}




pub struct DotAnalyzer {
    db: DotDatabase,
    config: DotConfig,
}

impl DotAnalyzer {
    pub fn new(config: DotConfig) -> Self {
        let db = DotDatabase::new(&config.learned_path);
        Self { db, config }
    }

    pub fn analyze(&mut self, indicators: DotIndicators) {
    // ---------------- HARD GATE ----------------
    // Port 853 is the only reliable DoT signal for unknown domains.
    // Non-standard port DoT is only valid if the domain is already
    // a confirmed provider in our database. Never fire on port 443.
    let is_standard_port = indicators.dst_port == 853;
    let is_known_provider = indicators.domain
        .map(|d| {
            let d = d.trim().to_lowercase();
            self.db.is_known_builtin(&d) || self.db.is_known_learned(&d)
        })
        .unwrap_or(false);

    if !is_standard_port && !is_known_provider {
        return;
    }

    // ---------------- SCORING ----------------
    let mut score: u8 = 0;

    if indicators.tls_detected {
        score += 1;
    }
    if is_standard_port {
        score += 1;
    }
    if indicators.domain.is_some() {
        score += 1;
    }
    if score < self.config.min_confidence_score {
        return;
    }

    let domain = match indicators.domain {
        Some(d) => d.trim().to_lowercase(),
        None => return,
    };

    // ---------------- KNOWN PROVIDER LOGGING ----------------
    if self.db.is_known_builtin(&domain) {
        if is_standard_port {
            println!("[DoT] Known Built-in Provider: {}", domain);
        }
        return;
    }
    if self.db.is_known_learned(&domain) {
        if is_standard_port {
            println!("[DoT] Known Learned Provider: {}", domain);
        }
        return;
    }

    // ---------------- NEW DETECTION ----------------
    // Only reaches here if port 853 and unknown domain.
    let classification = if is_standard_port {
        println!("[DoT] Standard DoT detected: {}", domain);
        "standard"
    } else {
        // This branch is now unreachable due to the hard gate above,
        // but kept for exhaustiveness.
        println!(
            "[DoT] Non-Standard DoT Port detected: {} (Port {})",
            domain, indicators.dst_port
        );
        "non_standard"
    };

    // ---------------- LEARNING ----------------
    if !self.config.learning_enabled {
        return;
    }

    if let Ok(entry) = append_learned_dot(
        &self.config.learned_path,
        &domain,
        classification,
    ) {
        self.db.insert_learned(domain.clone(), entry);
        println!("[DoT] NEW DoT provider learned: {}", domain);
    }
}
}
    
