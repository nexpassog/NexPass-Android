// NexPass — Vault entries storage (SQLite, app-level encrypted fields)
//
// The database file itself is plain SQLite, but every sensitive field
// (title, username, password, url, notes) is AES-256-GCM encrypted
// with the session's vault key before it's written. The DB file alone
// is useless without the PIN-derived key, which only lives in memory
// while the vault is unlocked.

use crate::crypto::{self, EncryptedPayload, VaultKey};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Manager};
use uuid::Uuid;

fn db_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("could not resolve app data dir: {e}"))?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join("vault.sqlite3"))
}

fn open_db(app: &AppHandle) -> Result<Connection, String> {
    let conn = Connection::open(db_path(app)?).map_err(|e| e.to_string())?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS entries (
            id TEXT PRIMARY KEY,
            title_ct TEXT NOT NULL, title_nonce TEXT NOT NULL,
            username_ct TEXT, username_nonce TEXT,
            password_ct TEXT NOT NULL, password_nonce TEXT NOT NULL,
            url_ct TEXT, url_nonce TEXT,
            fields_ct TEXT, fields_nonce TEXT,
            notes_ct TEXT, notes_nonce TEXT,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            favorite INTEGER NOT NULL DEFAULT 0,
            deleted_at INTEGER,
            category TEXT NOT NULL DEFAULT 'login'
        )",
        [],
    )
    .map_err(|e| e.to_string())?;

    // Migration for DBs created before favorite/deleted_at existed —
    // ignore the error if the column is already there.
    let _ = conn.execute("ALTER TABLE entries ADD COLUMN favorite INTEGER NOT NULL DEFAULT 0", []);
    let _ = conn.execute("ALTER TABLE entries ADD COLUMN deleted_at INTEGER", []);

    // Migration for smart sync: tracks the last time THIS row was
    // successfully pushed to the cloud. NULL / less-than-updated_at
    // means the row is "dirty" and needs to be pushed on next sync.
    let _ = conn.execute("ALTER TABLE entries ADD COLUMN synced_at INTEGER", []);

    // Migration for categories (v5.0.2) — existing entries default to "login".
    let _ = conn.execute("ALTER TABLE entries ADD COLUMN category TEXT NOT NULL DEFAULT 'login'", []);

    // Migration for category-specific fields (v5.0.6) — an encrypted JSON
    // blob holding whatever fields that entry's category needs (card
    // number, API key, keystore alias, etc). Opaque to the backend; the
    // frontend owns the schema per category. Login keeps using the
    // classic username/password/url/notes columns instead.
    let _ = conn.execute("ALTER TABLE entries ADD COLUMN fields_ct TEXT", []);
    let _ = conn.execute("ALTER TABLE entries ADD COLUMN fields_nonce TEXT", []);

    // Migration for TOTP secrets (v6.1.0) — an encrypted base32 secret so
    // the app can generate live 2FA codes on the entry detail view.
    let _ = conn.execute("ALTER TABLE entries ADD COLUMN totp_ct TEXT", []);
    let _ = conn.execute("ALTER TABLE entries ADD COLUMN totp_nonce TEXT", []);

    // Queue of ids whose cloud documents still exist but whose local rows
    // were permanently deleted. `permanently_delete_entry` tries to remove
    // the cloud doc immediately; if that fails (offline, rate limit) the
    // id lands here and every sync retries the delete until it succeeds —
    // otherwise the next pull would resurrect the deleted entry.
    conn.execute(
        "CREATE TABLE IF NOT EXISTS pending_deletes (
            id TEXT PRIMARY KEY,
            deleted_at INTEGER NOT NULL
        )",
        [],
    )
    .map_err(|e| e.to_string())?;

    // Safety net for sync conflicts: before a remote entry overwrites a
    // locally-dirty row (both devices changed the same entry since the
    // last sync), the local version is archived here so NOTHING is ever
    // silently lost. Surfaced in the UI as a "conflicts" review list.
    conn.execute(
        "CREATE TABLE IF NOT EXISTS conflict_backups (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            id TEXT NOT NULL,
            reason TEXT NOT NULL,
            payload TEXT NOT NULL,
            saved_at INTEGER NOT NULL
        )",
        [],
    )
    .map_err(|e| e.to_string())?;

    Ok(conn)
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[derive(Serialize, Deserialize)]
pub struct EntryInput {
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    #[serde(default = "default_category")]
    pub category: String,
    #[serde(default)]
    pub fields_json: Option<String>,
    /// Raw base32 TOTP secret (RFC 6238) — encrypted at rest like every
    /// other sensitive field. None/empty removes the secret.
    #[serde(default)]
    pub totp_secret: Option<String>,
}

pub fn default_category() -> String {
    "login".to_string()
}

#[derive(Serialize)]
pub struct EntrySummary {
    pub id: String,
    pub title: String,
    pub username: String,
    pub url: String,
    pub updated_at: i64,
    pub favorite: bool,
    pub category: String,
}

#[derive(Serialize)]
pub struct EntryFull {
    pub id: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub updated_at: i64,
    pub favorite: bool,
    pub category: String,
    pub fields_json: Option<String>,
    pub totp_secret: Option<String>,
}

fn enc(text: &str, key: &VaultKey) -> Result<EncryptedPayload, String> {
    crypto::encrypt(text, key).map_err(|_| "encryption failed".to_string())
}

fn dec(ct: &str, nonce: &str, key: &VaultKey) -> Result<String, String> {
    crypto::decrypt(
        &EncryptedPayload {
            ciphertext_b64: ct.to_string(),
            nonce_b64: nonce.to_string(),
        },
        key,
    )
    .map_err(|_| "decryption failed".to_string())
}

fn dec_opt(ct: Option<String>, nonce: Option<String>, key: &VaultKey) -> Result<String, String> {
    match (ct, nonce) {
        (Some(c), Some(n)) => dec(&c, &n, key),
        _ => Ok(String::new()),
    }
}

// Like dec_opt, but for a value that's genuinely optional (returns None
// rather than an empty string when there's nothing stored) — used for
// fields_json, which shouldn't exist at all for Login-category entries.
fn dec_opt_none(ct: Option<String>, nonce: Option<String>, key: &VaultKey) -> Result<Option<String>, String> {
    match (ct, nonce) {
        (Some(c), Some(n)) => Ok(Some(dec(&c, &n, key)?)),
        _ => Ok(None),
    }
}

fn enc_opt(value: &Option<String>, key: &VaultKey) -> Result<(Option<String>, Option<String>), String> {
    match value {
        Some(v) => {
            let e = enc(v, key)?;
            Ok((Some(e.ciphertext_b64), Some(e.nonce_b64)))
        }
        None => Ok((None, None)),
    }
}

/// Encrypts the entry's TOTP secret (or None to clear it). An empty
/// string is treated the same as None so "user erased the field" works
/// naturally from the form.
fn normalize_totp(
    secret: &Option<String>,
    key: &VaultKey,
) -> Result<(Option<String>, Option<String>), String> {
    match secret {
        Some(s) if !s.trim().is_empty() => enc_opt(&Some(s.trim().to_string()), key),
        _ => Ok((None, None)),
    }
}

pub fn add_entry(app: &AppHandle, key: &VaultKey, input: EntryInput) -> Result<String, String> {
    let conn = open_db(app)?;
    let id = Uuid::new_v4().to_string();
    let now = now_unix();

    let title = enc(&input.title, key)?;
    let username = enc(&input.username, key)?;
    let password = enc(&input.password, key)?;
    let url = enc(&input.url, key)?;
    let notes = enc(&input.notes, key)?;
    let (fields_ct, fields_nonce) = enc_opt(&input.fields_json, key)?;
    let totp = normalize_totp(&input.totp_secret, key)?;

    conn.execute(
        "INSERT INTO entries (id, title_ct, title_nonce, username_ct, username_nonce,
            password_ct, password_nonce, url_ct, url_nonce, notes_ct, notes_nonce,
            created_at, updated_at, category, fields_ct, fields_nonce, totp_ct, totp_nonce)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)",
        params![
            id,
            title.ciphertext_b64,
            title.nonce_b64,
            username.ciphertext_b64,
            username.nonce_b64,
            password.ciphertext_b64,
            password.nonce_b64,
            url.ciphertext_b64,
            url.nonce_b64,
            notes.ciphertext_b64,
            notes.nonce_b64,
            now,
            now,
            input.category,
            fields_ct,
            fields_nonce,
            totp.0,
            totp.1
        ],
    )
    .map_err(|e| e.to_string())?;

    Ok(id)
}

pub fn list_entries(app: &AppHandle, key: &VaultKey) -> Result<Vec<EntrySummary>, String> {
    list_by_trash_state(app, key, false)
}

pub fn list_trash(app: &AppHandle, key: &VaultKey) -> Result<Vec<EntrySummary>, String> {
    list_by_trash_state(app, key, true)
}

fn list_by_trash_state(
    app: &AppHandle,
    key: &VaultKey,
    trashed: bool,
) -> Result<Vec<EntrySummary>, String> {
    let conn = open_db(app)?;
    let where_clause = if trashed {
        "deleted_at IS NOT NULL"
    } else {
        "deleted_at IS NULL"
    };
    let sql = format!(
        "SELECT id, title_ct, title_nonce, username_ct, username_nonce, url_ct, url_nonce, updated_at, favorite, category
         FROM entries WHERE {where_clause} ORDER BY updated_at DESC"
    );
    let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;

    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, String>(9)?,
            ))
        })
        .map_err(|e| e.to_string())?;

    let mut out = Vec::new();
    for row in rows {
        let (
            id,
            title_ct,
            title_nonce,
            username_ct,
            username_nonce,
            url_ct,
            url_nonce,
            updated_at,
            favorite,
            category,
        ) = row.map_err(|e| e.to_string())?;

        out.push(EntrySummary {
            id,
            title: dec(&title_ct, &title_nonce, key)?,
            username: dec_opt(username_ct, username_nonce, key)?,
            url: dec_opt(url_ct, url_nonce, key)?,
            updated_at,
            favorite: favorite != 0,
            category,
        });
    }

    Ok(out)
}

pub fn get_entry(app: &AppHandle, key: &VaultKey, id: &str) -> Result<EntryFull, String> {
    let conn = open_db(app)?;
    let mut stmt = conn
        .prepare(
            "SELECT title_ct, title_nonce, username_ct, username_nonce, password_ct, password_nonce,
                    url_ct, url_nonce, notes_ct, notes_nonce, updated_at, favorite, category,
                    fields_ct, fields_nonce, totp_ct, totp_nonce
             FROM entries WHERE id = ?1",
        )
        .map_err(|e| e.to_string())?;

    let row = stmt
        .query_row(params![id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, Option<String>>(9)?,
                row.get::<_, i64>(10)?,
                row.get::<_, i64>(11)?,
                row.get::<_, String>(12)?,
                row.get::<_, Option<String>>(13)?,
                row.get::<_, Option<String>>(14)?,
                row.get::<_, Option<String>>(15)?,
                row.get::<_, Option<String>>(16)?,
            ))
        })
        .map_err(|_| "entry not found".to_string())?;

    let (
        title_ct,
        title_nonce,
        username_ct,
        username_nonce,
        password_ct,
        password_nonce,
        url_ct,
        url_nonce,
        notes_ct,
        notes_nonce,
        updated_at,
        favorite,
        category,
        fields_ct,
        fields_nonce,
        totp_ct,
        totp_nonce,
    ) = row;

    Ok(EntryFull {
        id: id.to_string(),
        title: dec(&title_ct, &title_nonce, key)?,
        username: dec_opt(username_ct, username_nonce, key)?,
        password: dec(&password_ct, &password_nonce, key)?,
        url: dec_opt(url_ct, url_nonce, key)?,
        notes: dec_opt(notes_ct, notes_nonce, key)?,
        updated_at,
        favorite: favorite != 0,
        category,
        fields_json: dec_opt_none(fields_ct, fields_nonce, key)?,
        totp_secret: dec_opt_none(totp_ct, totp_nonce, key)?,
    })
}

pub fn update_entry(
    app: &AppHandle,
    key: &VaultKey,
    id: &str,
    input: EntryInput,
) -> Result<(), String> {
    let conn = open_db(app)?;
    let now = now_unix();

    let title = enc(&input.title, key)?;
    let username = enc(&input.username, key)?;
    let password = enc(&input.password, key)?;
    let url = enc(&input.url, key)?;
    let notes = enc(&input.notes, key)?;
    let (fields_ct, fields_nonce) = enc_opt(&input.fields_json, key)?;
    let totp = normalize_totp(&input.totp_secret, key)?;

    let affected = conn
        .execute(
            "UPDATE entries SET title_ct=?1, title_nonce=?2, username_ct=?3, username_nonce=?4,
                password_ct=?5, password_nonce=?6, url_ct=?7, url_nonce=?8,
                notes_ct=?9, notes_nonce=?10, updated_at=?11, synced_at=NULL, category=?12,
                fields_ct=?13, fields_nonce=?14, totp_ct=?15, totp_nonce=?16 WHERE id=?17",
            params![
                title.ciphertext_b64,
                title.nonce_b64,
                username.ciphertext_b64,
                username.nonce_b64,
                password.ciphertext_b64,
                password.nonce_b64,
                url.ciphertext_b64,
                url.nonce_b64,
                notes.ciphertext_b64,
                notes.nonce_b64,
                now,
                input.category,
                fields_ct,
                fields_nonce,
                totp.0,
                totp.1,
                id
            ],
        )
        .map_err(|e| e.to_string())?;

    if affected == 0 {
        return Err("entry not found".to_string());
    }
    Ok(())
}

/// Moves an entry to Trash (soft delete) rather than removing it.
/// Also bumps updated_at and clears synced_at so the deletion itself
/// is treated as a change that needs to be pushed to the cloud —
/// otherwise a delete on one device would never reach other devices.
pub fn soft_delete_entry(app: &AppHandle, id: &str) -> Result<(), String> {
    let conn = open_db(app)?;
    let now = now_unix();
    conn.execute(
        "UPDATE entries SET deleted_at = ?1, updated_at = ?1, synced_at = NULL WHERE id = ?2",
        params![now, id],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

/// Brings a trashed entry back to the active list.
pub fn restore_entry(app: &AppHandle, id: &str) -> Result<(), String> {
    let conn = open_db(app)?;
    let now = now_unix();
    conn.execute(
        "UPDATE entries SET deleted_at = NULL, updated_at = ?1, synced_at = NULL WHERE id = ?2",
        params![now, id],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

/// Permanently removes an entry — only meant to be called from Trash.
/// The id is FIRST queued in `pending_deletes` so the cloud document is
/// retried on every sync until the delete is confirmed; a failed remote
/// delete used to be silently ignored and the entry came back on the
/// next pull (the resurrection bug). Every local entry is deleted (used
/// when this device adopts a different account/device's vault key —
/// entries encrypted under the old key are permanently undecryptable
/// under the new one, so they're cleared to make room for a fresh pull
/// from the cloud).
pub fn wipe_all_entries(app: &AppHandle) -> Result<(), String> {
    let conn = open_db(app)?;
    conn.execute("DELETE FROM entries", []).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn permanently_delete_entry(app: &AppHandle, id: &str) -> Result<(), String> {
    let conn = open_db(app)?;
    conn.execute("DELETE FROM entries WHERE id = ?1", params![id])
        .map_err(|e| e.to_string())?;
    enqueue_pending_delete(app, id)
}

// --- Pending remote-deletes (tombstone retry queue) ---

/// Records that the cloud document `id` still needs to be deleted.
/// Harmless when the delete already succeeded — the sync loop clears
/// the queue entry right after a confirmed remote delete.
pub fn enqueue_pending_delete(app: &AppHandle, id: &str) -> Result<(), String> {
    let conn = open_db(app)?;
    conn.execute(
        "INSERT OR REPLACE INTO pending_deletes (id, deleted_at) VALUES (?1, ?2)",
        params![id, now_unix()],
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

pub fn list_pending_deletes(app: &AppHandle) -> Result<Vec<String>, String> {
    let conn = open_db(app)?;
    let mut stmt = conn
        .prepare("SELECT id FROM pending_deletes ORDER BY deleted_at ASC")
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| e.to_string())?);
    }
    Ok(out)
}

pub fn clear_pending_delete(app: &AppHandle, id: &str) -> Result<(), String> {
    let conn = open_db(app)?;
    conn.execute("DELETE FROM pending_deletes WHERE id = ?1", params![id])
        .map(|_| ())
        .map_err(|e| e.to_string())
}

// --- Conflict backups (no data ever silently lost) ---

/// Archives the local (still-encrypted) version of an entry that is
/// about to be overwritten by a newer remote version while the local
/// copy itself had unsynced edits. The UI lists these as "conflicts".
fn save_conflict_backup(app: &AppHandle, entry: &RawEntry, reason: &str) -> Result<(), String> {
    let conn = open_db(app)?;
    let payload = serde_json::to_string(entry).map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT INTO conflict_backups (id, reason, payload, saved_at) VALUES (?1, ?2, ?3, ?4)",
        params![entry.id, reason, payload, now_unix()],
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

#[derive(Serialize)]
pub struct ConflictBackup {
    pub seq: i64,
    pub id: String,
    pub reason: String,
    pub saved_at: i64,
    /// The archived entry, decrypted for review (frontend-only display).
    pub entry: EntryFull,
}

pub fn list_conflict_backups(app: &AppHandle, key: &VaultKey) -> Result<Vec<ConflictBackup>, String> {
    let conn = open_db(app)?;
    let mut stmt = conn
        .prepare("SELECT seq, id, reason, payload, saved_at FROM conflict_backups ORDER BY saved_at DESC")
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })
        .map_err(|e| e.to_string())?;

    let mut out = Vec::new();
    for row in rows {
        let (seq, id, reason, payload, saved_at) = row.map_err(|e| e.to_string())?;
        let raw: RawEntry = serde_json::from_str(&payload).map_err(|e| e.to_string())?;
        out.push(ConflictBackup {
            seq,
            id: id.clone(),
            reason,
            saved_at,
            entry: EntryFull {
                id,
                title: dec(&raw.title_ct, &raw.title_nonce, key)?,
                username: dec_opt(raw.username_ct, raw.username_nonce, key)?,
                password: dec(&raw.password_ct, &raw.password_nonce, key)?,
                url: dec_opt(raw.url_ct, raw.url_nonce, key)?,
                notes: dec_opt(raw.notes_ct, raw.notes_nonce, key)?,
                updated_at: raw.updated_at,
                favorite: raw.favorite,
                category: raw.category.clone(),
                fields_json: dec_opt_none(raw.fields_ct, raw.fields_nonce, key)?,
                totp_secret: dec_opt_none(raw.totp_ct, raw.totp_nonce, key)?,
            },
        });
    }
    Ok(out)
}

pub fn clear_conflict_backup(app: &AppHandle, seq: i64) -> Result<(), String> {
    let conn = open_db(app)?;
    conn.execute("DELETE FROM conflict_backups WHERE seq = ?1", params![seq])
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[allow(dead_code)]
pub fn count_conflict_backups(app: &AppHandle) -> Result<i64, String> {
    let conn = open_db(app)?;
    conn.query_row("SELECT COUNT(*) FROM conflict_backups", [], |row| row.get(0))
        .map_err(|e| e.to_string())
}

// (kept public for diagnostics; the UI reads the full list instead)

pub fn toggle_favorite(app: &AppHandle, id: &str) -> Result<bool, String> {
    let conn = open_db(app)?;
    conn.execute(
        "UPDATE entries SET favorite = 1 - favorite, updated_at = ?1, synced_at = NULL WHERE id = ?2",
        params![now_unix(), id],
    )
    .map_err(|e| e.to_string())?;
    let new_val: i64 = conn
        .query_row(
            "SELECT favorite FROM entries WHERE id = ?1",
            params![id],
            |row| row.get(0),
        )
        .map_err(|e| e.to_string())?;
    Ok(new_val != 0)
}

// --- Raw (still-encrypted) access, used only by the sync module ---
// Sync never sees plaintext or the vault key — it just moves the
// already-encrypted ciphertext + nonce pairs to/from Firestore.

#[derive(Serialize, Deserialize, Clone)]
pub struct RawEntry {
    pub id: String,
    pub title_ct: String,
    pub title_nonce: String,
    pub username_ct: Option<String>,
    pub username_nonce: Option<String>,
    pub password_ct: String,
    pub password_nonce: String,
    pub url_ct: Option<String>,
    pub url_nonce: Option<String>,
    pub notes_ct: Option<String>,
    pub notes_nonce: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub favorite: bool,
    pub deleted_at: Option<i64>,
    #[serde(default)]
    pub synced_at: Option<i64>,
    #[serde(default = "default_category")]
    pub category: String,
    #[serde(default)]
    pub fields_ct: Option<String>,
    #[serde(default)]
    pub fields_nonce: Option<String>,
    #[serde(default)]
    pub totp_ct: Option<String>,
    #[serde(default)]
    pub totp_nonce: Option<String>,
}

pub fn export_all(app: &AppHandle, key: &VaultKey) -> Result<Vec<EntryFull>, String> {
    let raw = list_entries_raw(app)?;
    let mut out = Vec::new();
    for r in raw {
        if r.deleted_at.is_some() {
            continue;
        }
        out.push(EntryFull {
            id: r.id,
            title: dec(&r.title_ct, &r.title_nonce, key)?,
            username: dec_opt(r.username_ct, r.username_nonce, key)?,
            password: dec(&r.password_ct, &r.password_nonce, key)?,
            url: dec_opt(r.url_ct, r.url_nonce, key)?,
            notes: dec_opt(r.notes_ct, r.notes_nonce, key)?,
            updated_at: r.updated_at,
            favorite: r.favorite,
            category: r.category.clone(),
            fields_json: dec_opt_none(r.fields_ct, r.fields_nonce, key)?,
            totp_secret: dec_opt_none(r.totp_ct, r.totp_nonce, key)?,
        });
    }
    Ok(out)
}

pub fn list_entries_raw(app: &AppHandle) -> Result<Vec<RawEntry>, String> {
    list_entries_raw_where(app, "1=1")
}

/// Entries that either have never been synced, or were changed locally
/// after their last successful push (updated_at > synced_at). This is
/// what "smart sync" pushes instead of blindly re-pushing everything.
pub fn list_dirty_entries_raw(app: &AppHandle) -> Result<Vec<RawEntry>, String> {
    list_entries_raw_where(app, "synced_at IS NULL OR synced_at < updated_at")
}

/// Cheap count of dirty entries, used for status checks without
/// pulling all the (encrypted) field data into memory.
pub fn count_dirty_entries(app: &AppHandle) -> Result<i64, String> {
    let conn = open_db(app)?;
    conn.query_row(
        "SELECT COUNT(*) FROM entries WHERE synced_at IS NULL OR synced_at < updated_at",
        [],
        |row| row.get(0),
    )
    .map_err(|e| e.to_string())
}

fn list_entries_raw_where(app: &AppHandle, where_clause: &str) -> Result<Vec<RawEntry>, String> {
    let conn = open_db(app)?;
    let sql = format!(
        "SELECT id, title_ct, title_nonce, username_ct, username_nonce, password_ct,
                password_nonce, url_ct, url_nonce, notes_ct, notes_nonce, created_at, updated_at,
                favorite, deleted_at, synced_at, category, fields_ct, fields_nonce,
                totp_ct, totp_nonce
         FROM entries WHERE {where_clause}"
    );
    let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;

    let rows = stmt
        .query_map([], |row| {
            Ok(RawEntry {
                id: row.get(0)?,
                title_ct: row.get(1)?,
                title_nonce: row.get(2)?,
                username_ct: row.get(3)?,
                username_nonce: row.get(4)?,
                password_ct: row.get(5)?,
                password_nonce: row.get(6)?,
                url_ct: row.get(7)?,
                url_nonce: row.get(8)?,
                notes_ct: row.get(9)?,
                notes_nonce: row.get(10)?,
                created_at: row.get(11)?,
                updated_at: row.get(12)?,
                favorite: row.get::<_, i64>(13)? != 0,
                deleted_at: row.get(14)?,
                synced_at: row.get(15)?,
                category: row.get(16)?,
                fields_ct: row.get(17)?,
                fields_nonce: row.get(18)?,
                totp_ct: row.get(19)?,
                totp_nonce: row.get(20)?,
            })
        })
        .map_err(|e| e.to_string())?;

    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| e.to_string())?);
    }
    Ok(out)
}

/// Marks the given entries as synced as-of `ts` (the updated_at value
/// they had at push time). Run in a single transaction so a large
/// batch doesn't hammer SQLite with individual commits.
pub fn mark_synced(app: &AppHandle, ids_and_ts: &[(String, i64)]) -> Result<(), String> {
    let mut conn = open_db(app)?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    {
        let mut stmt = tx
            .prepare("UPDATE entries SET synced_at = ?1 WHERE id = ?2")
            .map_err(|e| e.to_string())?;
        for (id, ts) in ids_and_ts {
            stmt.execute(params![ts, id]).map_err(|e| e.to_string())?;
        }
    }
    tx.commit().map_err(|e| e.to_string())
}

/// Clears synced_at on every entry so the next sync re-pushes the whole
/// vault — used when this device's key becomes the account's canonical
/// key (publish_local_vault_key): everything must be re-uploaded under
/// the new key.
pub fn mark_all_entries_dirty(app: &AppHandle) -> Result<(), String> {
    let conn = open_db(app)?;
    conn.execute("UPDATE entries SET synced_at = NULL", [])
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Writes a remote entry into the local DB only if it's newer than
/// what's already there (or not present at all) — last-write-wins
/// conflict resolution with a safety net: if the local row it's about
/// to clobber had UNSYNCED edits of its own (both devices changed the
/// same entry since the last sync), the local version is archived to
/// `conflict_backups` first, so the losing side is never silently
/// destroyed. Returns true if it actually applied.
pub fn upsert_raw_entry_if_newer(app: &AppHandle, entry: &RawEntry) -> Result<bool, String> {
    let conn = open_db(app)?;

    let existing: Option<(i64, Option<i64>)> = conn
        .query_row(
            "SELECT updated_at, synced_at FROM entries WHERE id = ?1",
            params![entry.id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .ok();

    if let Some((local_ts, local_synced)) = existing {
        if local_ts >= entry.updated_at {
            return Ok(false);
        }
        // The local row is "dirty" when it was edited after its last
        // successful push. Overwriting a dirty row with the remote
        // version means real local work would vanish — archive first.
        let dirty = local_synced.is_none() || local_synced.unwrap() < local_ts;
        if dirty {
            if let Ok(Some(local_raw)) = get_raw_entry(app, &entry.id) {
                let _ = save_conflict_backup(
                    app,
                    &local_raw,
                    &format!("local edit ({local_ts}) vs remote edit ({})", entry.updated_at),
                );
            }
        }
    }

    // synced_at = updated_at here because this entry just came straight
    // from the cloud — local now matches remote exactly, so it's not
    // "dirty" and won't be redundantly pushed back on the next sync.
    conn.execute(
        "INSERT INTO entries (id, title_ct, title_nonce, username_ct, username_nonce,
            password_ct, password_nonce, url_ct, url_nonce, notes_ct, notes_nonce,
            created_at, updated_at, favorite, deleted_at, synced_at, category, fields_ct, fields_nonce,
            totp_ct, totp_nonce)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?13,?16,?17,?18,?19,?20)
         ON CONFLICT(id) DO UPDATE SET
            title_ct=excluded.title_ct, title_nonce=excluded.title_nonce,
            username_ct=excluded.username_ct, username_nonce=excluded.username_nonce,
            password_ct=excluded.password_ct, password_nonce=excluded.password_nonce,
            url_ct=excluded.url_ct, url_nonce=excluded.url_nonce,
            notes_ct=excluded.notes_ct, notes_nonce=excluded.notes_nonce,
            updated_at=excluded.updated_at, favorite=excluded.favorite,
            deleted_at=excluded.deleted_at, synced_at=excluded.updated_at, category=excluded.category,
            fields_ct=excluded.fields_ct, fields_nonce=excluded.fields_nonce,
            totp_ct=excluded.totp_ct, totp_nonce=excluded.totp_nonce",
        params![
            entry.id,
            entry.title_ct,
            entry.title_nonce,
            entry.username_ct,
            entry.username_nonce,
            entry.password_ct,
            entry.password_nonce,
            entry.url_ct,
            entry.url_nonce,
            entry.notes_ct,
            entry.notes_nonce,
            entry.created_at,
            entry.updated_at,
            entry.favorite as i64,
            entry.deleted_at,
            entry.category,
            entry.fields_ct,
            entry.fields_nonce,
            entry.totp_ct,
            entry.totp_nonce
        ],
    )
    .map_err(|e| e.to_string())?;

    Ok(true)
}

/// Fetches one raw entry by id (None if absent) — used by the conflict
/// backup path above.
fn get_raw_entry(app: &AppHandle, id: &str) -> Result<Option<RawEntry>, String> {
    let conn = open_db(app)?;
    let sql = "SELECT id, title_ct, title_nonce, username_ct, username_nonce, password_ct,
            password_nonce, url_ct, url_nonce, notes_ct, notes_nonce, created_at, updated_at,
            favorite, deleted_at, synced_at, category, fields_ct, fields_nonce, totp_ct, totp_nonce
         FROM entries WHERE id = ?1";
    let mut stmt = conn.prepare(sql).map_err(|e| e.to_string())?;
    let row = stmt
        .query_row(params![id], |r| {
            Ok(RawEntry {
                id: r.get(0)?,
                title_ct: r.get(1)?,
                title_nonce: r.get(2)?,
                username_ct: r.get(3)?,
                username_nonce: r.get(4)?,
                password_ct: r.get(5)?,
                password_nonce: r.get(6)?,
                url_ct: r.get(7)?,
                url_nonce: r.get(8)?,
                notes_ct: r.get(9)?,
                notes_nonce: r.get(10)?,
                created_at: r.get(11)?,
                updated_at: r.get(12)?,
                favorite: r.get::<_, i64>(13)? != 0,
                deleted_at: r.get(14)?,
                synced_at: r.get(15)?,
                category: r.get(16)?,
                fields_ct: r.get(17)?,
                fields_nonce: r.get(18)?,
                totp_ct: r.get(19)?,
                totp_nonce: r.get(20)?,
            })
        })
        .ok();
    Ok(row)
}

/// Applies one pulled entry, honoring "trash is per-device, not
/// synced": if the entry is a tombstone (deleted_at set) that comes
/// from ANOTHER device, this device removes it outright instead of
/// adding it to its own Trash — Trash should only ever contain items
/// *this* device deleted. If this device already has it in its own
/// trash, the incoming tombstone is just its own echo and is ignored.
/// Non-deleted (active) entries go through the normal upsert path
/// exactly as before.
pub fn apply_remote_entry(app: &AppHandle, entry: &RawEntry) -> Result<bool, String> {
    if entry.deleted_at.is_none() {
        return upsert_raw_entry_if_newer(app, entry);
    }

    let conn = open_db(app)?;
    let existing: Option<(i64, Option<i64>)> = conn
        .query_row(
            "SELECT updated_at, deleted_at FROM entries WHERE id = ?1",
            params![entry.id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .ok();

    match existing {
        None => Ok(false), // never had it locally — nothing to remove
        Some((_, Some(_))) => Ok(false), // already in OUR OWN trash — this is our own echo, leave it
        Some((local_updated_at, None)) => {
            if local_updated_at >= entry.updated_at {
                return Ok(false); // a local edit is newer — local wins, keep it active
            }
            // Another device deleted this after our last local change —
            // remove it entirely rather than reviving it into our trash.
            conn.execute("DELETE FROM entries WHERE id = ?1", params![entry.id])
                .map_err(|e| e.to_string())?;
            Ok(true)
        }
    }
}
