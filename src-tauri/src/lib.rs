// NexPass — Tauri backend library
mod biometric_store;
mod crypto;
mod google_auth;
mod health;
mod pwned;
mod profile_store;
mod secrets;
mod settings;
mod storage;
mod sync;
mod totp;
mod updater;
mod vault;
// Windows-unlock commands exist for command-registry parity; on mobile
// they're stubs (the real implementation lives in desktop's windows_hello.rs).
#[cfg(all(windows, not(any(target_os = "android", target_os = "ios"))))]
mod windows_hello;
#[cfg(not(all(windows, not(any(target_os = "android", target_os = "ios")))))]
mod windows_hello {
    #[derive(serde::Serialize)]
    pub struct HelloStatus {
        pub enrolled: bool,
        pub hello_available: bool,
    }
    pub fn enroll(_pin: &str) -> Result<HelloStatus, String> {
        Err("Windows unlock is only available on Windows".to_string())
    }
    pub fn retrieve_pin() -> Result<String, String> {
        Err("Windows unlock is only available on Windows".to_string())
    }
    pub fn status() -> Result<HelloStatus, String> {
        Ok(HelloStatus { enrolled: false, hello_available: false })
    }
    pub fn disable() -> Result<(), String> {
        Ok(())
    }
}

use std::sync::Mutex;
#[cfg(desktop)]
use tauri::menu::{Menu, MenuItem};
#[cfg(desktop)]
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Emitter, Manager, State, WindowEvent};
use tauri_plugin_nexpass_google_signin::NexpassGoogleSigninExt;

#[derive(Default)]
struct SessionState {
    key: Option<crypto::VaultKey>,
}
type Session = Mutex<SessionState>;

/// Wrong-PIN throttling state — enforced in Rust so the counter survives
/// an app restart (persisted) and can't be bypassed by reloading the UI.
#[derive(Default, serde::Serialize, serde::Deserialize)]
struct ThrottleState {
    consecutive_failures: u32,
    /// Unix seconds until which further unlock attempts are refused.
    lock_until: i64,
}

impl ThrottleState {
    fn path(app: &AppHandle) -> Result<std::path::PathBuf, String> {
        let dir = app
            .path()
            .app_data_dir()
            .map_err(|e| format!("could not resolve app data dir: {e}"))?;
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        Ok(dir.join("throttle.json"))
    }

    fn load(app: &AppHandle) -> ThrottleState {
        std::fs::read_to_string(Self::path(app).unwrap_or_default())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    fn save(&self, app: &AppHandle) -> Result<(), String> {
        let json = serde_json::to_string(self).map_err(|e| e.to_string())?;
        std::fs::write(Self::path(app)?, json).map_err(|e| e.to_string())
    }

    /// Free tries before locking, then 30s doubling per extra failure,
    /// capped at 15 minutes.
    fn register_failure(&mut self, app: &AppHandle) -> Result<UnlockResult, String> {
        self.consecutive_failures += 1;
        let over = self.consecutive_failures.saturating_sub(4);
        let now = now_unix();
        if over >= 1 {
            let secs = (30u64.saturating_mul(1u64 << (over - 1).min(5))).min(15 * 60);
            self.lock_until = now + secs as i64;
            let _ = self.save(app);
            Ok(UnlockResult { unlocked: false, lock_secs: secs, tries_left: 0 })
        } else {
            let _ = self.save(app);
            Ok(UnlockResult {
                unlocked: false,
                lock_secs: 0,
                tries_left: 4 - self.consecutive_failures,
            })
        }
    }

    fn remaining_lock(&self) -> i64 {
        (self.lock_until - now_unix()).max(0)
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[derive(serde::Serialize)]
struct UnlockResult {
    unlocked: bool,
    /// Seconds the unlock is locked out for (0 when not locked).
    lock_secs: u64,
    /// Free tries remaining before a lockout starts.
    tries_left: u32,
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let mut builder = tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        // Gives the frontend a real "Restart App" action after an
        // in-app update install (see updater.rs) instead of asking the
        // user to find NexPass again in their app drawer.
        .plugin(tauri_plugin_process::init())
        // Real Tauri plugin (Kotlin @TauriPlugin) that installs a
        // downloaded update APK — see tauri-plugin-nexpass-installer.
        .plugin(tauri_plugin_nexpass_installer::init())
        // Android Autofill provider + home-screen widget (Kotlin plugin;
        // the OS binds the service directly, the plugin exposes the
        // enable/status commands the Settings UI uses).
        .plugin(tauri_plugin_nexpass_autofill::init())
        // Native Android Google Sign-In using Google Identity Services
        // (account picker in-app, no browser redirect).
        .plugin(tauri_plugin_nexpass_google_signin::init())
        .manage(Session::default());

    // Biometric prompt (fingerprint / face) — Android + iOS only, no
    // desktop equivalent, so the plugin isn't even a dependency there.
    #[cfg(mobile)]
    {
        builder = builder.plugin(tauri_plugin_biometric::init());
    }

    builder
        .setup(|app| {
            // Tray icons don't exist on Android/iOS — this whole block
            // (and the imports above) only compiles in on desktop.
            #[cfg(desktop)]
            {
                let show_item = MenuItem::with_id(app, "show", "Show NexPass", true, None::<&str>)?;
                let quit_item = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
                let menu = Menu::with_items(app, &[&show_item, &quit_item])?;

                let mut tray = TrayIconBuilder::new().menu(&menu).on_menu_event(|app, event| {
                    match event.id.as_ref() {
                        "show" => {
                            if let Some(w) = app.get_webview_window("main") {
                                let _ = w.show();
                                let _ = w.set_focus();
                            }
                        }
                        "quit" => app.exit(0),
                        _ => {}
                    }
                });
                if let Some(icon) = app.default_window_icon() {
                    tray = tray.icon(icon.clone());
                }
                tray.build(app)?;
            }

            if let Some(window) = app.get_webview_window("main") {
                #[cfg(target_os = "windows")]
                {
                    use window_vibrancy::{apply_acrylic, apply_mica};
                    if apply_mica(&window, Some(true)).is_err() {
                        let _ = apply_acrylic(&window, Some((10, 10, 20, 125)));
                    }
                }
                #[cfg(target_os = "macos")]
                {
                    use window_vibrancy::{apply_vibrancy, NSVisualEffectMaterial};
                    let _ = apply_vibrancy(&window, NSVisualEffectMaterial::HudWindow, None, None);
                }
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                let app = window.app_handle();

                #[cfg(desktop)]
                {
                    let s = settings::load_settings(app);
                    if s.minimize_to_tray {
                        api.prevent_close();
                        let _ = window.hide();
                        if let Some(session) = app.try_state::<Session>() {
                            if let Ok(mut guard) = session.lock() {
                                guard.key = None;
                            }
                        }
                        return;
                    }
                }

                // On Android, the hardware/gesture back button surfaces here
                // when the WebView has no in-page history left to pop. Hand
                // it to the frontend instead of letting the OS kill the
                // activity outright, so it can step back a level inside the
                // app, or show a "press back again to exit" prompt at the
                // root and only actually quit (via the exit_app command)
                // on a genuine second press.
                #[cfg(mobile)]
                {
                    api.prevent_close();
                    let _ = app.emit("back-requested", ());
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            vault_exists,
            setup_pin,
            unlock_with_pin,
            lock_vault,
            google_sign_in,
            google_session_status,
            add_entry,
            list_entries,
            list_trash,
            get_entry,
            update_entry,
            soft_delete_entry,
            restore_entry,
            permanently_delete_entry,
            toggle_favorite,
            sync_now,
            check_sync_status,
            check_cloud_vault_key,
            adopt_cloud_vault_key,
            publish_local_vault_key,
            debug_vault_key_info,
            backup_to_cloud,
            restore_from_cloud,
            export_vault,
            import_vault,
            logout_and_wipe,
            delete_account,
            get_settings,
            save_settings,
            exit_app,
            set_biometric_pin,
            get_biometric_pin,
            clear_biometric_pin,
            check_for_update,
            fetch_release_notes,
            download_update,
            get_downloaded_update_info,
            delete_downloaded_update,
            install_update_apk,
            get_profile,
            save_profile,
            set_profile_avatar,
            clear_profile_avatar,
            generate_totp,
            check_password_breach,
            vault_health,
            list_conflicts,
            clear_conflict,
            hello_enroll,
            hello_unlock,
            hello_status,
            hello_disable
        ])
        .run(tauri::generate_context!())
        .expect("error while running NexPass");
}

fn require_key(s: &SessionState) -> Result<&crypto::VaultKey, String> {
    s.key.as_ref().ok_or_else(|| "Vault is locked".to_string())
}

#[tauri::command]
fn vault_exists(app: AppHandle) -> Result<bool, String> {
    storage::vault_exists(&app)
}

#[tauri::command]
fn setup_pin(app: AppHandle, session: State<Session>, pin: String) -> Result<(), String> {
    if pin.len() < 4 || !pin.chars().all(|c| c.is_ascii_digit()) {
        return Err("PIN must be at least 4 digits".to_string());
    }

    // If this device is already linked to a Google account that
    // already has vault key material in the cloud, adopt THAT
    // material instead of generating a new one — otherwise this
    // device would derive a different AES key from the same PIN and
    // would never be able to decrypt entries from other devices on
    // the same account (or vice versa).
    if storage::load_google_session(&app)?.is_some() {
        if let Ok(Some(material)) = sync::fetch_cloud_key_material(&app) {
            let key = crypto::unlock(&pin, &material).map_err(|_| {
                "This account's vault already uses a different PIN on another device — enter that PIN instead.".to_string()
            })?;
            storage::save_master(&app, &material)?;
            session.lock().map_err(|_| "lock poisoned".to_string())?.key = Some(key);
            return Ok(());
        }
    }

    let (material, key) =
        crypto::create_master_key(&pin).map_err(|_| "Failed to set up PIN".to_string())?;
    storage::save_master(&app, &material)?;
    // Best-effort: if already signed in, publish this device's key
    // material immediately so it becomes the account's canonical key.
    if storage::load_google_session(&app)?.is_some() {
        let _ = sync::push_cloud_key_material(&app, &material);
    }
    session.lock().map_err(|_| "lock poisoned".to_string())?.key = Some(key);
    let mut throttle = ThrottleState::load(&app);
    throttle.consecutive_failures = 0;
    throttle.lock_until = 0;
    let _ = throttle.save(&app);
    Ok(())
}

/// Backend-enforced wrong-PIN throttling (persists across restarts).
#[tauri::command]
fn unlock_with_pin(app: AppHandle, session: State<Session>, pin: String) -> Result<UnlockResult, String> {
    let mut throttle = ThrottleState::load(&app);

    let remaining = throttle.remaining_lock();
    if remaining > 0 {
        return Ok(UnlockResult {
            unlocked: false,
            lock_secs: remaining as u64,
            tries_left: 0,
        });
    }

    let material = storage::load_master(&app)?;
    match crypto::unlock(&pin, &material) {
        Ok(key) => {
            session.lock().map_err(|_| "lock poisoned".to_string())?.key = Some(key);
            throttle.consecutive_failures = 0;
            throttle.lock_until = 0;
            let _ = throttle.save(&app);
            Ok(UnlockResult { unlocked: true, lock_secs: 0, tries_left: 4 })
        }
        Err(_) => throttle.register_failure(&app),
    }
}

#[tauri::command]
fn lock_vault(session: State<Session>) -> Result<(), String> {
    session.lock().map_err(|_| "lock poisoned".to_string())?.key = None;
    Ok(())
}

#[tauri::command]
fn add_entry(app: AppHandle, session: State<Session>, input: vault::EntryInput) -> Result<String, String> {
    let s = session.lock().map_err(|_| "lock poisoned".to_string())?;
    vault::add_entry(&app, require_key(&s)?, input)
}

#[tauri::command]
fn list_entries(app: AppHandle, session: State<Session>) -> Result<Vec<vault::EntrySummary>, String> {
    let s = session.lock().map_err(|_| "lock poisoned".to_string())?;
    vault::list_entries(&app, require_key(&s)?)
}

#[tauri::command]
fn list_trash(app: AppHandle, session: State<Session>) -> Result<Vec<vault::EntrySummary>, String> {
    let s = session.lock().map_err(|_| "lock poisoned".to_string())?;
    vault::list_trash(&app, require_key(&s)?)
}

#[tauri::command]
fn get_entry(app: AppHandle, session: State<Session>, id: String) -> Result<vault::EntryFull, String> {
    let s = session.lock().map_err(|_| "lock poisoned".to_string())?;
    vault::get_entry(&app, require_key(&s)?, &id)
}

#[tauri::command]
fn update_entry(app: AppHandle, session: State<Session>, id: String, input: vault::EntryInput) -> Result<(), String> {
    let s = session.lock().map_err(|_| "lock poisoned".to_string())?;
    vault::update_entry(&app, require_key(&s)?, &id, input)
}

#[tauri::command]
fn soft_delete_entry(app: AppHandle, id: String) -> Result<(), String> {
    vault::soft_delete_entry(&app, &id)
}

#[tauri::command]
fn restore_entry(app: AppHandle, id: String) -> Result<(), String> {
    vault::restore_entry(&app, &id)
}

#[tauri::command]
fn permanently_delete_entry(app: AppHandle, id: String) -> Result<(), String> {
    // Queue first (survives a failed network call), then try to delete
    // the cloud document immediately; on failure every sync retries.
    vault::enqueue_pending_delete(&app, &id)?;
    vault::permanently_delete_entry(&app, &id)?;
    let _ = sync::delete_remote_entry(&app, &id);
    Ok(())
}

#[tauri::command]
fn toggle_favorite(app: AppHandle, id: String) -> Result<bool, String> {
    vault::toggle_favorite(&app, &id)
}

#[derive(serde::Serialize)]
struct GoogleSignInResult {
    email: String,
    local_id: String,
    display_name: Option<String>,
    photo_url: Option<String>,
}

#[tauri::command]
async fn google_sign_in(app: AppHandle) -> Result<GoogleSignInResult, String> {
    // Use native Android Google Sign-In plugin
    let result = app.nexpass_google_signin().sign_in()
        .map_err(|e| format!("Native Google Sign-In failed: {e}"))?;
    
    let user = result.user;
    
    // Convert to Firebase session using the ID token
    let firebase_session = google_auth::exchange_id_token_for_firebase_session(&user.id_token)
        .map_err(|e| format!("Firebase sign-in failed: {e}"))?;
    
    storage::save_google_session(&app, &firebase_session)?;
    
    Ok(GoogleSignInResult {
        email: firebase_session.email,
        local_id: firebase_session.local_id,
        display_name: firebase_session.display_name,
        photo_url: firebase_session.photo_url,
    })
}

#[tauri::command]
fn google_session_status(app: AppHandle) -> Result<Option<GoogleSignInResult>, String> {
    let session = storage::load_google_session(&app)?;
    Ok(session.map(|s| GoogleSignInResult {
        email: s.email,
        local_id: s.local_id,
        display_name: s.display_name,
        photo_url: s.photo_url,
    }))
}

/// Called right after a successful Google sign-in (when a local PIN/
/// vault already exists on this device, which is the normal flow —
/// PIN is set up before linking an account). Compares this device's
/// vault key material against whatever the account already has in the
/// cloud.
///
/// Returns:
/// - "match"     — nothing to do, this device already uses the account's key
/// - "published" — no cloud material existed yet; this device's key was published as canonical
/// - "mismatch"  — the account already has a DIFFERENT key from another device;
///                 the caller should prompt for that device's PIN and call
///                 `adopt_cloud_vault_key` to reconcile
#[tauri::command]
fn check_cloud_vault_key(app: AppHandle) -> Result<String, String> {
    let local = storage::load_master(&app)?;
    match sync::fetch_cloud_key_material(&app)? {
        None => {
            sync::push_cloud_key_material(&app, &local)?;
            Ok("published".to_string())
        }
        Some(cloud) => {
            if cloud.salt == local.salt {
                Ok("match".to_string())
            } else {
                Ok("mismatch".to_string())
            }
        }
    }
}

/// Resolves a "mismatch" from `check_cloud_vault_key`: verifies the
/// given PIN against the ACCOUNT's cloud key material, and if correct,
/// replaces this device's local key material with it and wipes this
/// device's local (now-undecryptable, since it was under a different
/// key) entries so a fresh pull from the cloud can repopulate them.
#[tauri::command]
fn adopt_cloud_vault_key(app: AppHandle, session: State<Session>, pin: String) -> Result<(), String> {
    let cloud = sync::fetch_cloud_key_material(&app)?
        .ok_or_else(|| "No cloud vault key found for this account".to_string())?;
    let key = crypto::unlock(&pin, &cloud)
        .map_err(|_| "That's not the PIN this account's vault was set up with".to_string())?;

    storage::save_master(&app, &cloud)?;
    vault::wipe_all_entries(&app)?;
    session.lock().map_err(|_| "lock poisoned".to_string())?.key = Some(key);
    Ok(())
}

/// The OTHER direction of a "mismatch": make THIS device's vault the
/// account's canonical one. Verifies the caller knows this device's PIN
/// (intent guard), publishes the local key material over the cloud's,
/// wipes the cloud entries (ciphertext under the OLD key), and marks
/// every local entry dirty so the next sync pushes everything under the
/// new key. The other device must then adopt with THIS device's PIN.
#[tauri::command]
async fn publish_local_vault_key(app: AppHandle, pin: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        let local = storage::load_master(&app)?;
        let key = crypto::unlock(&pin, &local)
            .map_err(|_| "That's not this device's PIN — the vault stays as-is".to_string())?;

        sync::push_cloud_key_material(&app, &local)?;
        sync::delete_all_remote(&app)?;
        vault::mark_all_entries_dirty(&app)?;

        if let Some(session) = app.try_state::<Session>() {
            if let Ok(mut guard) = session.lock() {
                guard.key = Some(key);
            }
        }
        Ok(())
    })
    .await
    .map_err(|e| format!("re-key task panicked: {e}"))?
}

/// Diagnostic only — shows exactly what this device's local salt and
/// the account's cloud salt currently are (short prefixes, not the
/// full secret material) so a real mismatch can be seen directly
/// instead of inferred from symptoms.
#[derive(serde::Serialize)]
struct VaultKeyDebugInfo {
    signed_in: bool,
    local_salt_prefix: Option<String>,
    cloud_salt_prefix: Option<String>,
    salts_match: bool,
    google_email: Option<String>,
}

#[tauri::command]
fn debug_vault_key_info(app: AppHandle) -> Result<VaultKeyDebugInfo, String> {
    let local = storage::load_master(&app).ok();
    let local_salt_prefix = local.as_ref().map(|m| m.salt.chars().take(12).collect::<String>());

    let google = storage::load_google_session(&app)?;
    let signed_in = google.is_some();
    let google_email = google.as_ref().map(|g| g.email.clone());

    let cloud_salt_prefix = if signed_in {
        sync::fetch_cloud_key_material(&app)
            .ok()
            .flatten()
            .map(|m| m.salt.chars().take(12).collect::<String>())
    } else {
        None
    };

    let salts_match = match (&local_salt_prefix, &cloud_salt_prefix) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    };

    Ok(VaultKeyDebugInfo { signed_in, local_salt_prefix, cloud_salt_prefix, salts_match, google_email })
}

// These are `async fn` + `spawn_blocking` rather than plain sync
// commands. Tauri already runs commands off the JS/UI thread, but a
// plain sync command occupies one of the async-runtime's worker
// threads for its entire (potentially many-second, many-request)
// duration; spawn_blocking moves that work to the dedicated blocking
// thread pool so it can't starve other commands (or Tauri's own event
// loop) while a big sync is in flight — this is part of the "advance
// error handling" fix for large vaults (50-60+ credentials) freezing
// the app.

#[tauri::command]
async fn sync_now(app: AppHandle) -> Result<sync::SyncSummary, String> {
    tauri::async_runtime::spawn_blocking(move || sync::sync_now(&app))
        .await
        .map_err(|e| format!("sync task panicked: {e}"))?
}

#[tauri::command]
async fn check_sync_status(app: AppHandle) -> Result<sync::SyncStatus, String> {
    tauri::async_runtime::spawn_blocking(move || sync::check_sync_status(&app))
        .await
        .map_err(|e| format!("sync status check panicked: {e}"))?
}

#[tauri::command]
async fn backup_to_cloud(app: AppHandle) -> Result<usize, String> {
    tauri::async_runtime::spawn_blocking(move || sync::backup_to_cloud(&app))
        .await
        .map_err(|e| format!("backup task panicked: {e}"))?
}

#[tauri::command]
async fn restore_from_cloud(app: AppHandle) -> Result<usize, String> {
    tauri::async_runtime::spawn_blocking(move || sync::restore_from_cloud(&app))
        .await
        .map_err(|e| format!("restore task panicked: {e}"))?
}

/// Exports all active entries as a password-protected encrypted JSON blob
/// (safe to share — nothing readable without the export password).
#[tauri::command]
fn export_vault(app: AppHandle, session: State<Session>, password: String) -> Result<String, String> {
    if password.len() < 6 {
        return Err("Export password must be at least 6 characters".to_string());
    }
    let entries = {
        let s = session.lock().map_err(|_| "lock poisoned".to_string())?;
        vault::export_all(&app, require_key(&s)?)?
    };
    let plaintext = serde_json::to_string(&entries).map_err(|e| e.to_string())?;
    let blob = crypto::encrypt_with_password(&plaintext, &password).map_err(|_| "export encryption failed".to_string())?;
    serde_json::to_string(&serde_json::json!({
        "nexpass_export": true,
        "version": 1,
        "salt": blob.salt,
        "nonce": blob.nonce_b64,
        "ciphertext": blob.ciphertext_b64
    }))
    .map_err(|e| e.to_string())
}

#[derive(serde::Deserialize)]
struct ImportedEntry {
    title: String,
    username: String,
    password: String,
    url: String,
    notes: String,
    #[serde(default = "vault::default_category")]
    category: String,
    #[serde(default)]
    fields_json: Option<String>,
}

/// Imports entries from a file produced by export_vault.
#[tauri::command]
fn import_vault(app: AppHandle, session: State<Session>, file_content: String, password: String) -> Result<usize, String> {
    let parsed: serde_json::Value = serde_json::from_str(&file_content).map_err(|_| "Not a valid NexPass export file".to_string())?;
    let blob = crypto::ExportBlob {
        salt: parsed["salt"].as_str().ok_or("missing salt")?.to_string(),
        ciphertext_b64: parsed["ciphertext"].as_str().ok_or("missing ciphertext")?.to_string(),
        nonce_b64: parsed["nonce"].as_str().ok_or("missing nonce")?.to_string(),
    };
    let plaintext = crypto::decrypt_with_password(&blob, &password).map_err(|_| "Wrong export password".to_string())?;
    let entries: Vec<ImportedEntry> = serde_json::from_str(&plaintext).map_err(|e| e.to_string())?;

    let s = session.lock().map_err(|_| "lock poisoned".to_string())?;
    let key = require_key(&s)?;
    let mut count = 0;
    for e in entries {
        vault::add_entry(&app, key, vault::EntryInput {
            title: e.title, username: e.username, password: e.password, url: e.url, notes: e.notes, category: e.category, fields_json: e.fields_json, totp_secret: None,
        })?;
        count += 1;
    }
    Ok(count)
}

/// Wipes ALL local data (vault, PIN, Google session) — used for logout
/// and as part of account deletion. Does not touch cloud data.
#[tauri::command]
async fn logout_and_wipe(app: AppHandle, session: State<'_, Session>) -> Result<(), String> {
    // Sign out from native Google Sign-In
    let _ = app.nexpass_google_signin().sign_out();
    
    session.lock().map_err(|_| "lock poisoned".to_string())?.key = None;
    storage::wipe_all_local_data(&app)
}

/// Deletes ALL of this user's data from Firestore, then wipes local data too.
#[tauri::command]
fn delete_account(app: AppHandle, session: State<Session>) -> Result<(), String> {
    sync::delete_all_remote(&app)?;
    session.lock().map_err(|_| "lock poisoned".to_string())?.key = None;
    storage::wipe_all_local_data(&app)
}

#[tauri::command]
fn get_settings(app: AppHandle) -> settings::AppSettings {
    settings::load_settings(&app)
}

#[tauri::command]
fn save_settings(app: AppHandle, settings: settings::AppSettings) -> Result<(), String> {
    settings::save_settings(&app, &settings)
}

#[tauri::command]
fn exit_app(app: AppHandle) {
    app.exit(0);
}

// See biometric_store.rs for the trust-model note on what this is (and
// isn't) protecting. `pin` here is stored so a successful biometric
// prompt can feed it straight into the existing unlock_with_pin flow
// without the user re-typing it.
#[tauri::command]
fn set_biometric_pin(app: AppHandle, pin: String) -> Result<(), String> {
    biometric_store::save_pin(&app, &pin)
}

#[tauri::command]
fn get_biometric_pin(app: AppHandle) -> Option<String> {
    biometric_store::load_pin(&app)
}

#[tauri::command]
fn clear_biometric_pin(app: AppHandle) -> Result<(), String> {
    biometric_store::clear_pin(&app)
}

#[tauri::command]
fn check_for_update() -> Result<Option<updater::UpdateInfo>, String> {
    updater::check_for_update()
}

#[tauri::command]
fn fetch_release_notes() -> Result<Vec<updater::ReleaseNote>, String> {
    updater::fetch_release_notes()
}

// async + spawn_blocking for the same reason sync_now/backup_to_cloud/etc.
// are — a multi-megabyte APK download run as a plain sync command would
// occupy one of the async-runtime's worker threads for the whole
// download; spawn_blocking moves it to the dedicated blocking pool
// instead so it can't starve other in-flight commands.
#[tauri::command]
async fn download_update(app: AppHandle, url: String, version: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || updater::download_update(&app, &url, &version))
        .await
        .map_err(|e| format!("download task panicked: {e}"))?
}

#[tauri::command]
fn get_downloaded_update_info(app: AppHandle) -> Result<Option<updater::DownloadedUpdateInfo>, String> {
    updater::get_downloaded_update_info(&app)
}

#[tauri::command]
fn delete_downloaded_update(app: AppHandle) -> Result<bool, String> {
    updater::delete_downloaded_update(&app)
}

// See the tauri-plugin-nexpass-installer crate — this goes through a real
// Tauri mobile plugin (Kotlin @TauriPlugin + FileProvider) instead of
// either the opener plugin (can't reach files in NexPass's own private
// storage on Android) or raw JNI (Tauri never initializes the ndk-context
// global in this Tauri version, so calling it directly crashes the app).
#[tauri::command]
fn install_update_apk(app: AppHandle, path: String) -> Result<(), String> {
    use tauri_plugin_nexpass_installer::NexpassInstallerExt;
    app.nexpass_installer()
        .install_apk(tauri_plugin_nexpass_installer::InstallApkRequest { path })
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn get_profile(app: AppHandle) -> profile_store::Profile {
    profile_store::load(&app)
}

#[tauri::command]
fn save_profile(app: AppHandle, name: Option<String>, bio: Option<String>) -> Result<(), String> {
    let mut p = profile_store::load(&app);
    p.name = name;
    p.bio = bio;
    profile_store::save(&app, &p)
}

#[tauri::command]
fn set_profile_avatar(app: AppHandle, path: String) -> Result<(), String> {
    let mut p = profile_store::load(&app);
    p.avatar_path = Some(path);
    profile_store::save(&app, &p)
}

#[tauri::command]
fn clear_profile_avatar(app: AppHandle) -> Result<(), String> {
    let mut p = profile_store::load(&app);
    p.avatar_path = None;
    profile_store::save(&app, &p)
}

// --- TOTP (2FA) ---

/// Live TOTP code for an entry's stored secret (6 digits + seconds left).
#[tauri::command]
fn generate_totp(secret: String) -> Result<(String, u32), String> {
    if secret.trim().is_empty() {
        return Err("no TOTP secret on this entry".to_string());
    }
    totp::generate(&secret, None)
}

// --- Breach check (HIBP k-anonymity) ---

/// Checks ONE password against HIBP. Only a SHA-1 prefix (5 hex chars of
/// a hash) ever leaves the device — the password itself never does.
#[tauri::command]
fn check_password_breach(password: String) -> Result<i64, String> {
    if password.is_empty() {
        return Ok(0);
    }
    pwned::breach_count(&password)
}

// --- Password health audit ---

/// Full vault audit. Runs on the blocking pool; decrypts under the
/// session lock, releases it, then does the (potentially slow, networked)
/// breach checks without holding anything else up.
#[tauri::command]
async fn vault_health(app: AppHandle, check_breaches: bool) -> Result<health::HealthReport, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let entries = {
            let session = app
                .try_state::<Session>()
                .ok_or_else(|| "no session".to_string())?;
            let s = session.lock().map_err(|_| "lock poisoned".to_string())?;
            vault::export_all(&app, require_key(&s)?)?
        };
        health::analyze(&entries, check_breaches)
    })
    .await
    .map_err(|e| format!("health task panicked: {e}"))?
}

// --- Sync conflict review ---

#[tauri::command]
fn list_conflicts(app: AppHandle, session: State<Session>) -> Result<Vec<vault::ConflictBackup>, String> {
    let s = session.lock().map_err(|_| "lock poisoned".to_string())?;
    vault::list_conflict_backups(&app, require_key(&s)?)
}

#[tauri::command]
fn clear_conflict(app: AppHandle, seq: i64) -> Result<(), String> {
    vault::clear_conflict_backup(&app, seq)
}

// --- Windows unlock (stub on mobile; parity with desktop command set) ---

#[tauri::command]
fn hello_enroll(pin: String) -> Result<windows_hello::HelloStatus, String> {
    windows_hello::enroll(&pin)
}

#[tauri::command]
fn hello_unlock(app: AppHandle, session: State<Session>) -> Result<bool, String> {
    let pin = windows_hello::retrieve_pin()?;
    let material = storage::load_master(&app)?;
    match crypto::unlock(&pin, &material) {
        Ok(key) => {
            session.lock().map_err(|_| "lock poisoned".to_string())?.key = Some(key);
            Ok(true)
        }
        Err(_) => Err("Saved PIN no longer matches this vault".to_string()),
    }
}

#[tauri::command]
fn hello_status() -> Result<windows_hello::HelloStatus, String> {
    windows_hello::status()
}

#[tauri::command]
fn hello_disable() -> Result<(), String> {
    windows_hello::disable()
}
