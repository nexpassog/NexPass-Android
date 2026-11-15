// NexPass — Password health audit.
//
// Runs entirely in Rust: decrypts every entry locally, analyzes
// passwords (strength, reuse, age, breaches), and hands the frontend
// only aggregate stats + per-entry FLAGS. Plaintext passwords never
// cross the IPC boundary — the UI can show which entries are affected,
// but has no new access to the secrets themselves.

use serde::Serialize;
use tauri::AppHandle;

use crate::crypto::VaultKey;
use crate::pwned;
use crate::vault;

/// Rough strength classes — deliberately conservative buckets rather
/// than a fake-precise entropy score. 12+ chars with mixed classes is
/// "strong"; everything shorter or single-class is flagged.
#[derive(PartialEq, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Strength {
    Strong,
    Fair,
    Weak,
}

fn classify_strength(pw: &str) -> Strength {
    let len = pw.chars().count();
    let classes = [
        pw.chars().any(|c| c.is_ascii_lowercase()),
        pw.chars().any(|c| c.is_ascii_uppercase()),
        pw.chars().any(|c| c.is_ascii_digit()),
        pw.chars().any(|c| !c.is_ascii_alphanumeric()),
    ]
    .iter()
    .filter(|b| **b)
    .count();

    if len >= 16 && classes >= 3 {
        Strength::Strong
    } else if len >= 12 && classes >= 2 {
        Strength::Fair
    } else {
        Strength::Weak
    }
}

#[derive(Serialize)]
pub struct HealthEntry {
    pub id: String,
    pub title: String,
    pub category: String,
    pub strength: Strength,
    /// Distinct issues, e.g. "reused", "weak", "old", "breached".
    pub issues: Vec<String>,
    /// HIBP occurrence count when the entry's password was found in a
    /// breach dump (None when breach checking was skipped/offline).
    pub breach_count: Option<i64>,
}

#[derive(Serialize)]
pub struct HealthReport {
    pub total: usize,
    pub weak: usize,
    pub reused: usize,
    pub old: usize,
    pub breached: usize,
    pub strong: usize,
    pub checked_breaches: bool,
    pub entries: Vec<HealthEntry>,
}

/// Entries older than this (never updated since creation) are flagged.
const OLD_AFTER_SECS: i64 = 365 * 24 * 3600;

pub fn audit(app: &AppHandle, key: &VaultKey, check_breaches: bool) -> Result<HealthReport, String> {
    let entries = vault::export_all(app, key)?;
    let now = now_unix();

    // Count password reuse across entries (exact match after decryption).
    let mut by_password: std::collections::HashMap<&str, Vec<&vault::EntryFull>> =
        std::collections::HashMap::new();
    for e in &entries {
        if !e.password.is_empty() {
            by_password.entry(e.password.as_str()).or_default().push(e);
        }
    }
    let reused_passwords: std::collections::HashSet<&str> = by_password
        .iter()
        .filter(|(_, group)| group.len() > 1)
        .map(|(pw, _)| *pw)
        .collect();

    // Breach check one UNIQUE password at a time (deduplicated — the
    // most expensive part is the network round trip, not the hashing).
    let mut breach_cache: std::collections::HashMap<&str, Option<i64>> =
        std::collections::HashMap::new();
    let mut checked_breaches = false;
    if check_breaches {
        for pw in reused_passwords.iter().chain(by_password.keys()) {
            if breach_cache.contains_key(*pw) {
                continue;
            }
            let result = pwned::breach_count(pw);
            checked_breaches = true;
            breach_cache.insert(*pw, result.ok());
            // Small delay keeps us well clear of HIBP rate limits on
            // large vaults (unique passwords only, so this is short).
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }

    let mut report = HealthReport {
        total: entries.len(),
        weak: 0,
        reused: 0,
        old: 0,
        breached: 0,
        strong: 0,
        checked_breaches,
        entries: Vec::new(),
    };

    for e in &entries {
        if e.password.is_empty() {
            continue; // secure-note style entries have no password to audit
        }
        let strength = classify_strength(&e.password);
        let mut issues = Vec::new();

        if strength == Strength::Weak {
            issues.push("weak".to_string());
            report.weak += 1;
        }
        if reused_passwords.contains(e.password.as_str()) {
            issues.push("reused".to_string());
            report.reused += 1;
        }
        if now - e.updated_at > OLD_AFTER_SECS {
            issues.push("old".to_string());
            report.old += 1;
        }
        let breach_count = breach_cache.get(e.password.as_str()).copied().flatten();
        if let Some(c) = breach_count {
            if c > 0 {
                issues.push("breached".to_string());
                report.breached += 1;
            }
        }
        if issues.is_empty() && strength == Strength::Strong {
            report.strong += 1;
        }

        report.entries.push(HealthEntry {
            id: e.id.clone(),
            title: e.title.clone(),
            category: e.category.clone(),
            strength,
            issues,
            breach_count,
        });
    }

    Ok(report)
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
