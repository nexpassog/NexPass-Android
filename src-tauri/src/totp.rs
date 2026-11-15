// NexPass — TOTP (RFC 6238) generator for 2FA codes stored on entries.
//
// Standard parameters only, matching what every authenticator app
// (Google Authenticator, Authy, Aegis…) uses by default: HMAC-SHA1 over
// an 8-byte big-endian time counter, 30-second step, 6 digits. Secrets
// are the base32 blobs that otpauth:// QR codes encode — pasted in
// without padding, whitespace-tolerant, case-insensitive.

use base32::{decode as base32_decode, Alphabet};
use hmac::{Hmac, Mac};
use sha1::Sha1;

const STEP_SECS: u64 = 30;
const DIGITS: u32 = 6;

type HmacSha1 = Hmac<Sha1>;

/// Normalizes whatever the user pasted (otpauth URI param, spaced base32,
/// lowercase, padded) down to the raw base32 payload and decodes it.
fn secret_bytes(secret: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = secret
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .collect::<String>()
        .to_uppercase();

    // Tolerate a full otpauth:// URI being pasted instead of the bare
    // secret — grab just the secret param in that case.
    let candidate = if let Some(rest) = cleaned.strip_prefix("OTPAUTH://") {
        rest.split('?')
            .nth(1)
            .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("SECRET=")))
            .unwrap_or(&cleaned)
    } else {
        &cleaned
    };

    base32_decode(Alphabet::Rfc4648 { padding: false }, candidate)
        .ok_or_else(|| "invalid base32 TOTP secret".to_string())
}

/// Generates the current TOTP code. Returns the zero-padded 6-digit code
/// plus how many seconds remain before it rolls over, so the UI can draw
/// a countdown without recomputing.
pub fn generate(secret: &str, at_secs: Option<u64>) -> Result<(String, u32), String> {
    let key = secret_bytes(secret)?;
    let now = at_secs.unwrap_or_else(now_unix);
    let counter = now / STEP_SECS;

    let mut mac = HmacSha1::new_from_slice(&key).map_err(|_| "bad TOTP key".to_string())?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();

    // Dynamic truncation per RFC 4226 §5.4.
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let bin = ((digest[offset] as u32 & 0x7f) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | (digest[offset + 3] as u32);

    let code = format!("{:0width$}", bin % 10u32.pow(DIGITS), width = DIGITS as usize);
    let remaining = (STEP_SECS - (now % STEP_SECS)) as u32;
    Ok((code, remaining))
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 appendix B test vectors use ASCII secrets "12345678901234567890"
    // with 8 digits — not directly reproducible here, so instead verify the
    // algorithm against a known-good 6-digit vector computed independently
    // (secret base32 "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" = "12345678901234567890").
    #[test]
    fn known_vector() {
        // T=59s → counter=1 → expected code 287082 (6-digit truncation of the
        // RFC's 755224 / 287082 family for SHA-1 at T=59).
        let (code, remaining) = generate("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", Some(59)).unwrap();
        assert_eq!(code, "287082");
        assert!(remaining > 0 && remaining <= 30);
    }

    #[test]
    fn tolerates_formatting() {
        let (a, _) = generate("gezd gnbvgy 3tqo jqge zdgnbvgy3tqojq==", Some(59)).unwrap();
        let (b, _) = generate("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", Some(59)).unwrap();
        assert_eq!(a, b);
    }
}
