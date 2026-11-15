package com.nexapp.nexpass.autofill

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import android.view.autofill.AutofillManager
import app.tauri.annotation.Command
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import app.tauri.plugin.Invoke

// Exposes autofill enablement to the NexPass frontend:
//   - autofillStatus()      → { enabled, ready }
//   - openAutofillSettings() → jumps to the OS screen where NexPass can
//     be picked as the autofill provider (pre-targeted at this app).
@TauriPlugin
class AutofillPlugin(private val activity: Activity) : Plugin(activity) {

    @Command
    fun autofillStatus(invoke: Invoke) {
        try {
            val manager = activity.getSystemService(AutofillManager::class.java)
            val enabled = manager?.hasEnabledAutofillServices() == true
            val ready = VaultCrypto.readStoredPin(activity) != null
            val result = JSObject()
            result.put("enabled", enabled)
            result.put("ready", ready)
            invoke.resolve(result)
        } catch (e: Exception) {
            val result = JSObject()
            result.put("enabled", false)
            result.put("ready", false)
            invoke.resolve(result)
        }
    }

    @Command
    fun openAutofillSettings(invoke: Invoke) {
        try {
            // Pre-targeted dialog ("Set NexPass as your autofill app?"),
            // falling back to the generic autofill settings screen.
            val targeted = Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE)
                .setData(Uri.parse("package:${activity.packageName}"))
            try {
                activity.startActivity(targeted)
            } catch (_: Exception) {
                activity.startActivity(Intent(Settings.ACTION_SETTINGS))
            }
            invoke.resolve(JSObject())
        } catch (e: Exception) {
            invoke.reject("${e.javaClass.simpleName}: ${e.message}")
        }
    }
}
