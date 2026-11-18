// NexPass — Have I Been Pwned breach check (k-anonymity range API).
//
// The password NEVER leaves the device. We SHA-1 it locally, send only
// the first 5 hex characters to api.pwnedpasswords.com, and match the
// remaining suffix against the returned list. A prefix of 40 bits of a
// hash reveals nothing about the password itself — this is the official
// k-anonymity design documented by HIBP. `Add-Padding: true` pads the
// response so even response size doesn't leak whether a prefix matched.

use sha1::{Digest, Sha1};
use std::time::Duration;

/// Returns how many times `password` appears in known data breaches,
/// or an error if the check couldn't complete (offline, rate limit…).
/// Rate-limit (429) responses honor Retry-After with bounded backoff so
/// batch audits (password health) don't fall over after a few checks.
pub fn breach_count(password: &str) -> Result<i64, String> {
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let hex = format!("{:X}", hasher.finalize());
    let (prefix, suffix) = hex.split_at(5);

    let client = reqwest::blocking::Client::builder()
        .user_agent("NexPass-PasswordManager")
        .build()
        .map_err(|e| e.to_string())?;

    let url = format!("https://api.pwnedpasswords.com/range/{prefix}");
    let mut last_error = String::new();

    // Up to 3 attempts: initial + 2 backoff retries on 429 only.
    for attempt in 0..3 {
        let result = client
            .get(&url)
            .header("Add-Padding", "true")
            .send();

        let resp = match result {
            Ok(r) => r,
            Err(e) => return Err(format!("breach check failed: {e}")),
        };

        let status = resp.status();
        if status.as_u16() == 429 {
            // Respect Retry-After (seconds), fall back to exponential wait.
            let wait = resp
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<u64>().ok())
                .unwrap_or(2u64.saturating_mul(1 << attempt))
                .min(15);
            last_error = "rate limited (429)".to_string();
            if attempt < 2 {
                std::thread::sleep(Duration::from_secs(wait));
                continue;
            }
            return Err(format!(
                "breach check rate limited — try again in {wait}s"
            ));
        }
        if !status.is_success() {
            return Err(format!(
                "breach check failed: HTTP {}",
                status.as_u16()
            ));
        }

        let body = resp.text().map_err(|e| e.to_string())?;
        for line in body.lines() {
            let mut parts = line.trim().split(':');
            if let (Some(s), Some(count)) = (parts.next(), parts.next()) {
                if s.eq_ignore_ascii_case(suffix) {
                    return Ok(count.trim().parse::<i64>().unwrap_or(0));
                }
            }
        }
        return Ok(0);
    }
    Err(last_error)
}
