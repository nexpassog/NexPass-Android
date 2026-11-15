// NexPass — Have I Been Pwned breach check (k-anonymity range API).
//
// The password NEVER leaves the device. We SHA-1 it locally, send only
// the first 5 hex characters to api.pwnedpasswords.com, and match the
// remaining suffix against the returned list. A prefix of 40 bits of a
// hash reveals nothing about the password itself — this is the official
// k-anonymity design documented by HIBP. `Add-Padding: true` pads the
// response so even response size doesn't leak whether a prefix matched.

use sha1::{Digest, Sha1};

/// Returns how many times `password` appears in known data breaches,
/// or an error if the check couldn't complete (offline, rate limit…).
pub fn breach_count(password: &str) -> Result<i64, String> {
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let hex = format!("{:X}", hasher.finalize());
    let (prefix, suffix) = hex.split_at(5);

    let client = reqwest::blocking::Client::builder()
        .user_agent("NexPass-PasswordManager")
        .build()
        .map_err(|e| e.to_string())?;

    let body = client
        .get(format!("https://api.pwnedpasswords.com/range/{prefix}"))
        .header("Add-Padding", "true")
        .send()
        .map_err(|e| format!("breach check failed: {e}"))?
        .text()
        .map_err(|e| e.to_string())?;

    for line in body.lines() {
        let mut parts = line.trim().split(':');
        if let (Some(s), Some(count)) = (parts.next(), parts.next()) {
            if s.eq_ignore_ascii_case(suffix) {
                return Ok(count.trim().parse::<i64>().unwrap_or(0));
            }
        }
    }
    Ok(0)
}
