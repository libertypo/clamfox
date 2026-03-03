use wasm_bindgen::prelude::*;
use std::collections::HashSet;

#[wasm_bindgen]
pub struct DetectionResult {
    pub is_threat: bool,
    reason: String,
}

#[wasm_bindgen]
impl DetectionResult {
    #[wasm_bindgen(getter)]
    pub fn reason(&self) -> String {
        self.reason.clone()
    }
}

/// Detect Punycode or non-ASCII characters in domains.
#[wasm_bindgen]
pub fn check_homograph_attack(url_str: &str) -> JsValue {
    let domain = match url_str.split("://").last() {
        Some(d) => d.split('/').next().unwrap_or("").to_lowercase(),
        None => url_str.to_lowercase(),
    };

    if domain.starts_with("xn--") {
        return serde_wasm_bindgen::to_value(&Some("Punycode Deception (Homoglyph Attack)".to_string())).unwrap();
    }

    if domain.chars().any(|c| !c.is_ascii()) {
        return serde_wasm_bindgen::to_value(&Some("Homoglyph Suspect (Non-ASCII Domain)".to_string())).unwrap();
    }

    serde_wasm_bindgen::to_value(&None::<String>).unwrap()
}

/// Calculate Shannon entropy of a string.
#[wasm_bindgen]
pub fn calculate_entropy(data: &str) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = std::collections::HashMap::new();
    for c in data.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }

    let len = data.chars().count() as f64;
    let mut entropy = 0.0;
    for &count in counts.values() {
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

/// Statistically detect DGA (Algorithmically Generated Domains).
#[wasm_bindgen]
pub fn check_dga_heuristics(url_str: &str) -> JsValue {
    let domain = match url_str.split("://").last() {
        Some(d) => d.split('/').next().unwrap_or("").to_lowercase(),
        None => url_str.to_lowercase(),
    };

    // Semi-naive label extraction
    let clean_domain = domain.split('.').next().unwrap_or("");
    
    if clean_domain.len() < 8 {
        return serde_wasm_bindgen::to_value(&None::<String>).unwrap();
    }

    let entropy = calculate_entropy(clean_domain);
    
    let vowels = "aeiouy";
    let consonant_count = clean_domain.chars()
        .filter(|c| c.is_alphabetic() && !vowels.contains(*c))
        .count();
    let consonant_ratio = consonant_count as f64 / clean_domain.len() as f64;

    let digit_count = clean_domain.chars().filter(|c| c.is_numeric()).count();
    let digit_ratio = digit_count as f64 / clean_domain.len() as f64;

    let mut reasons = Vec::new();

    if entropy > 3.9 && (digit_ratio > 0.25 || consonant_ratio > 0.7) {
        reasons.push(format!("High Statistical Randomness (Entropy: {:.2})", entropy));
    } else if digit_ratio > 0.35 {
        reasons.push(format!("High Digit Density ({:.1}%)", digit_ratio * 100.0));
    } else if consonant_ratio > 0.8 {
        reasons.push(format!("High Consonant Density ({:.1}%)", consonant_ratio * 100.0));
    }

    if !reasons.is_empty() {
        return serde_wasm_bindgen::to_value(&Some(reasons.join(" / "))).unwrap();
    }

    serde_wasm_bindgen::to_value(&None::<String>).unwrap()
}
