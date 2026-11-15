package com.nexapp.nexpass.autofill

import android.util.Base64
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import org.json.JSONObject
import java.io.File
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Replicates the Rust backend's crypto in Kotlin so OS-side components
 * (AutofillService, home-screen widget) can decrypt vault entries on
 * demand — they run outside the Tauri runtime and can't call its commands.
 *
 * Everything here reads the exact same app-private files the Rust side
 * writes:
 *   - vault_meta.json   → {"master":{"salt": "<argon2 PHC salt b64>", "verification_hash": "argon2id$…"}}
 *   - vault.sqlite3     → entries table with per-field ciphertext + nonce columns (base64, standard alphabet)
 *   - biometric.json    → {"pin": "<digits>"} (same trust model as biometric_store.rs — app sandbox, not hardware keystore)
 *
 * The derived key material exists only inside the requesting process's
 * memory for the duration of one fill/render and is zeroed afterwards.
 */
object VaultCrypto {

    private const val KEY_BITS = 256
    private const val TAG_BITS = 128

    private fun filesDir(context: android.content.Context): File = context.filesDir

    private fun b64(value: String): ByteArray =
        Base64.decode(value, Base64.DEFAULT)

    /**
     * Derives the 32-byte AES key exactly like crypto.rs::derive_key_bytes.
     *
     * CRITICAL subtlety: the Rust side passes the salt's BASE64 STRING
     * bytes (UTF-8 of the PHC salt text) into hash_password_into — NOT
     * the decoded salt bytes. The two agree on the default Argon2
     * parameters (m=19456 KiB, t=2, p=1, v19). Any deviation silently
     * produces a key that decrypts nothing.
     */
    fun deriveKey(pin: String, saltB64: String): ByteArray {
        val salt = saltB64.toByteArray(Charsets.UTF_8)
        // NOTE: BouncyCastle's variant constants are lowercase (ARGON2_id),
        // and the salt goes through withSalt() — the Builder ctor only
        // takes the variant int.
        val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withSalt(salt)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withMemoryAsKB(19456)
            .withIterations(2)
            .withParallelism(1)
            .build()
        val generator = Argon2BytesGenerator()
        generator.init(params)
        val out = ByteArray(KEY_BITS / 8)
        generator.generateBytes(pin.toByteArray(Charsets.UTF_8), out, 0, out.size)
        return out
    }

    /**
     * The Rust salt is a PHC SaltString: standard-alphabet base64 WITHOUT
     * padding. android.util.Base64.NO_PADDING + NO_WRAP reproduces that.
     */
    private fun decodeSalt(saltB64: String): ByteArray =
        Base64.decode(saltB64.trim().removeSuffix("="), Base64.NO_PADDING or Base64.NO_WRAP)

    fun decryptField(ciphertextB64: String?, nonceB64: String?, key: ByteArray): String? {
        if (ciphertextB64.isNullOrBlank() || nonceB64.isNullOrBlank()) return null
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(key, "AES"),
                GCMParameterSpec(TAG_BITS, b64(nonceB64))
            )
            val plain = cipher.doFinal(b64(ciphertextB64))
            String(plain, Charsets.UTF_8)
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Verifies the PIN against the stored PHC verification hash. This
     * path mirrors Rust's `hash_password` — which DOES use the decoded
     * raw salt bytes (unlike derive_key_bytes above, which re-encodes).
     * The PHC string carries the params (m/t/p/v) explicitly.
     */
    fun verifyPin(pin: String, metaJson: JSONObject): Boolean {
        val master = metaJson.optJSONObject("master") ?: return false
        val phc = master.optString("verification_hash")
        if (phc.isBlank()) return false

        // PHC string: argon2id$v=19$m=19456,t=2,p=1$<saltB64>$<hashB64>
        val parts = phc.split("$")
        if (parts.size < 5 || parts[0] != "argon2id") return false
        val paramsPart = parts[2]
        val saltB64 = parts[parts.size - 2]
        val hashB64 = parts[parts.size - 1]

        var m = 19456; var t = 2; var p = 1; var v = 19
        paramsPart.split(",").forEach { kv ->
            val ps = kv.split("=")
            if (ps.size == 2) when (ps[0]) {
                "m" -> m = ps[1].toIntOrNull() ?: m
                "t" -> t = ps[1].toIntOrNull() ?: t
                "p" -> p = ps[1].toIntOrNull() ?: p
            }
        }
        val versionMatch = Regex("v=(\\d+)").find(parts[1])
        v = versionMatch?.groupValues?.get(1)?.toIntOrNull() ?: v

        val salt = decodeSalt(saltB64)
        // NOTE: BouncyCastle's variant constants are lowercase (ARGON2_i / ARGON2_id).
        val mode = if (phc.startsWith("argon2i$")) Argon2Parameters.ARGON2_i else Argon2Parameters.ARGON2_id
        val params = Argon2Parameters.Builder(mode)
            .withSalt(salt)
            .withVersion(v)
            .withMemoryAsKB(m)
            .withIterations(t)
            .withParallelism(p)
            .build()
        val generator = Argon2BytesGenerator()
        generator.init(params)
        val derived = ByteArray(KEY_BITS / 8)
        generator.generateBytes(pin.toByteArray(Charsets.UTF_8), derived, 0, derived.size)

        // PHC hash part is base64 (unpadded) of the 32-byte hash.
        val stored = try { Base64.decode(hashB64, Base64.NO_PADDING or Base64.NO_WRAP) } catch (_: Exception) { return false }
        val ok = stored.size == derived.size && stored.indices.all { stored[it] == derived[it] }
        java.util.Arrays.fill(derived, 0)
        return ok
    }

    /** Reads the PIN saved by biometric_store.rs ({"pin": "..."}). */
    fun readStoredPin(context: android.content.Context): String? = try {
        val file = File(filesDir(context), "biometric.json")
        if (!file.exists()) null
        else JSONObject(file.readText()).optString("pin").takeIf { it.isNotEmpty() }
    } catch (_: Exception) { null }

    data class VaultEntry(
        val id: String,
        val title: String,
        val username: String?,
        val password: String?,
        val url: String?,
        val category: String
    )

    /** Reads + decrypts all ACTIVE (non-trashed) entries. Key is zeroed after. */
    fun loadEntries(context: android.content.Context, pin: String): List<VaultEntry>? {
        val metaFile = File(filesDir(context), "vault_meta.json")
        val dbFile = File(filesDir(context), "vault.sqlite3")
        if (!metaFile.exists() || !dbFile.exists()) return null

        val meta = try { JSONObject(metaFile.readText()) } catch (_: Exception) { return null }
        val salt = meta.optJSONObject("master")?.optString("salt") ?: return null
        if (!verifyPin(pin, meta)) return null

        val key = deriveKey(pin, salt)
        try {
            val db = android.database.sqlite.SQLiteDatabase.openDatabase(
                dbFile.absolutePath, null, android.database.sqlite.SQLiteDatabase.OPEN_READONLY
            )
            val out = mutableListOf<VaultEntry>()
            db.rawQuery(
                "SELECT id, title_ct, title_nonce, username_ct, username_nonce, password_ct, password_nonce, url_ct, url_nonce, category FROM entries WHERE deleted_at IS NULL",
                null
            ).use { c ->
                while (c.moveToNext()) {
                    val title = decryptField(c.getString(1), c.getString(2), key) ?: continue
                    out.add(
                        VaultEntry(
                            id = c.getString(0),
                            title = title,
                            username = decryptField(c.getString(3), c.getString(4), key),
                            password = decryptField(c.getString(5), c.getString(6), key),
                            url = decryptField(c.getString(7), c.getString(8), key),
                            category = c.getString(9)
                        )
                    )
                }
            }
            db.close()
            return out
        } catch (_: Exception) {
            return null
        } finally {
            java.util.Arrays.fill(key, 0)
        }
    }
}
