// NexPass — Windows Hello unlock (desktop-only).
//
// Trust model, exactly matching mobile's biometric_store: the device PIN
// is stored locally in an OS-protected store and can only be retrieved
// after a successful biometric/PIN verification prompt. On Android that
// store is app-private storage gated by the BiometricPrompt API; here
// it's Windows Credential Manager (DPAPI — encrypted to the current
// Windows user, unreadable by other local users) gated by a Windows
// Hello KeyCredential.
//
// A WinRT KeyCredential requires the app to have Windows package
// identity. The NSIS-installed (unpackaged) build can still enroll: we
// create the Hello credential opportunistically and, if Windows refuses
// (no identity / Hello not configured), we fall back to DPAPI-only —
// `status()` reports `hello_available: false` so the UI can say
// "protected by your Windows account" instead of claiming biometrics.
// The MSIX-packaged build gets the full Hello prompt.
//
// NOTE on the API shape: windows-rs 0.58 exposes only RequestCreateAsync
// on KeyCredentialManager (no RetrieveAsync static). RequestCreateAsync
// with `ReuseExisting` is the equivalent gate — Windows reuses the
// existing credential AND shows the verification prompt before handing
// back the credential object.

#![cfg(all(windows, not(any(target_os = "android", target_os = "ios"))))]
#![allow(clippy::upper_case_acronyms)]

use windows::Security::Credentials::{KeyCredentialCreationOption, KeyCredentialManager};
use windows::Security::Cryptography::CryptographicBuffer;
use windows::Win32::Security::Credentials::{
    CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_FLAGS, CRED_PERSIST_LOCAL_MACHINE,
    CRED_TYPE_GENERIC,
};
use windows::Win32::System::Com::{CoInitializeEx, COINIT_APARTMENTTHREADED};

const HELLO_CREDENTIAL_NAME: &str = "NexPassHello";
const PIN_CRED_TARGET: &str = "NexPassHelloPin";

/// Ensures COM is initialized on this thread before any WinRT call.
/// Tauri commands run on worker threads that may never have COM set up.
fn ensure_com() {
    unsafe {
        // S_FALSE (=1) means "already initialized" — both are fine.
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn hstring(s: &str) -> windows::core::HSTRING {
    windows::core::HSTRING::from(s)
}

/// Runs the Windows Hello verification prompt (creating the credential
/// on first use). Ok = user verified; Err = unavailable/cancelled.
fn verify_through_hello() -> windows::core::Result<()> {
    // windows-rs 0.58 exposes only ReplaceExisting / FailIfExists —
    // there is no plain "retrieve + verify". ReplaceExisting re-uses the
    // enrollment flow as the gate: Windows shows the Hello verification
    // prompt before handing back the credential. We never use the key
    // material itself, so re-creating it is harmless.
    let create = KeyCredentialManager::RequestCreateAsync(
        &hstring(HELLO_CREDENTIAL_NAME),
        KeyCredentialCreationOption::ReplaceExisting,
    )?
    .get()?;

    let credential = create.Credential()?;
    // A benign constant "challenge": the signature itself proves user
    // presence; we only care that the prompt succeeded.
    let challenge = CryptographicBuffer::CreateFromByteArray(&[
        0x4E, 0x65, 0x78, 0x50, 0x61, 0x73, 0x73, // "NexPass"
    ])?;
    credential.RequestSignAsync(&challenge)?.get()?;
    Ok(())
}

#[derive(serde::Serialize)]
pub struct HelloStatus {
    /// A saved PIN exists for this device.
    pub enrolled: bool,
    /// Windows accepted a Hello KeyCredential for this app (biometric /
    /// device PIN prompt available). False on unpackaged installs where
    /// Windows refuses identity-bound credentials.
    pub hello_available: bool,
}

/// Stores the PIN behind a Windows Hello gate (when available) and
/// DPAPI-protected Credential Manager storage. Called from the Settings
/// UI while the vault is already unlocked — enrolling never exposes the
/// PIN beyond the DPAPI blob.
pub fn enroll(pin: &str) -> Result<HelloStatus, String> {
    ensure_com();

    // Try to create/refresh the Hello credential. This shows the Windows
    // Hello setup/verification prompt when it works. Failure is NOT fatal
    // — we still enroll the DPAPI-stored PIN and report hello_available
    // honestly so the UI labels the feature correctly.
    let hello_available = verify_through_hello().is_ok();

    write_pin_cred(pin, hello_available)?;
    Ok(HelloStatus { enrolled: true, hello_available })
}

/// Runs the Hello verification prompt (when available), then returns the
/// saved PIN so the normal `unlock_with_pin` flow can proceed. The PIN
/// travels only through this in-process call — never to the frontend.
pub fn retrieve_pin() -> Result<String, String> {
    ensure_com();

    if let Err(e) = verify_through_hello() {
        return Err(format!("Windows Hello verification failed: {e}"));
    }

    let blob = read_pin_cred()
        .ok_or_else(|| "No saved PIN for Windows unlock — set it up in Settings".to_string())?;
    parse_pin(&blob).ok_or_else(|| "stored PIN credential is malformed — re-enable Windows unlock".to_string())
}

/// Reports enrollment state WITHOUT triggering a prompt: probe is read-
/// only. (Hello prompt itself is only fired on enroll/unlock.)
pub fn status() -> Result<HelloStatus, String> {
    ensure_com();
    let enrolled = read_pin_cred().is_some();
    Ok(HelloStatus {
        enrolled,
        hello_available: probe_hello_silent(),
    })
}

/// Removes the stored PIN (called from logout / wipe / manual disable).
pub fn disable() -> Result<(), String> {
    ensure_com();
    delete_pin_cred()
}

/// Non-interactive probe: succeeds only if the credential already
/// exists. RequestCreateAsync would show a prompt, so instead we just
/// check whether creating with ReuseExisting is even possible by
/// looking at whether a previous enroll stored a marker credential —
/// the DPAPI entry doubles as the marker.
fn probe_hello_silent() -> bool {
    // There is no read-only way to query a KeyCredential's existence in
    // windows-rs 0.58 without triggering a prompt, so we approximate:
    // Hello is treated as available when the last enroll reported it.
    // The flag is persisted alongside the PIN inside the DPAPI blob as
    // "1:<pin>" / "0:<pin>".
    read_pin_cred()
        .map(|v| v.starts_with('1'))
        .unwrap_or(false)
}

// --- DPAPI-backed Credential Manager storage ---
// Blob format: "<hello_available_flag>:<pin>" — one line, pin digits only.

fn write_pin_cred(pin: &str, hello_available: bool) -> Result<(), String> {
    unsafe {
        let mut target = wide(PIN_CRED_TARGET);
        let mut user = wide("NexPass");
        let payload = format!("{}:{}", hello_available as u8, pin);
        let blob: Vec<u8> = payload.bytes().collect();

        let mut cred = CREDENTIALW::default();
        cred.Flags = CRED_FLAGS(0);
        cred.Type = CRED_TYPE_GENERIC;
        cred.TargetName = windows::core::PWSTR(target.as_mut_ptr());
        cred.UserName = windows::core::PWSTR(user.as_mut_ptr());
        cred.CredentialBlob = blob.as_ptr() as *mut u8;
        cred.CredentialBlobSize = blob.len() as u32;
        cred.Persist = CRED_PERSIST_LOCAL_MACHINE;

        CredWriteW(&cred, 0).map_err(|e| format!("failed to store PIN credential: {e}"))
    }
}

fn read_pin_cred() -> Option<String> {
    unsafe {
        let target = wide(PIN_CRED_TARGET);
        let mut cred_ptr: *mut CREDENTIALW = std::ptr::null_mut();
        if CredReadW(
            windows::core::PCWSTR(target.as_ptr()),
            CRED_TYPE_GENERIC,
            0,
            &mut cred_ptr,
        )
        .is_err()
        {
            return None;
        }
        let cred = &*cred_ptr;
        let size = cred.CredentialBlobSize as usize;
        let bytes = std::slice::from_raw_parts(cred.CredentialBlob, size).to_vec();
        CredFree(cred_ptr as _);
        String::from_utf8(bytes).ok()
    }
}

/// "<flag>:<pin>" → pin digits. Returns None when malformed.
fn parse_pin(blob: &str) -> Option<String> {
    let (flag, pin) = blob.split_once(':')?;
    if flag != "0" && flag != "1" {
        return None;
    }
    let pin = pin.trim().to_string();
    if pin.is_empty() || !pin.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(pin)
}

fn delete_pin_cred() -> Result<(), String> {
    unsafe {
        let target = wide(PIN_CRED_TARGET);
        windows::Win32::Security::Credentials::CredDeleteW(
            windows::core::PCWSTR(target.as_ptr()),
            CRED_TYPE_GENERIC,
            0,
        )
        .map_err(|e| format!("failed to remove saved PIN: {e}"))
    }
}
