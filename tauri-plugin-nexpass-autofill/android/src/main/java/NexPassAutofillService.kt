package com.nexapp.nexpass.autofill

import android.app.assist.AssistStructure
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillContext
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import android.text.SpannableString
import android.text.style.RelativeSizeSpan
import android.view.ViewStructure
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import com.nexapp.nexpass.autofill.R

/**
 * NexPass as a system Autofill provider.
 *
 * Flow: Android asks us to fill login fields in some other app → we
 * decrypt the vault ON DEMAND with the PIN saved behind the biometric
 * gate (biometric.json — see VaultCrypto + biometric_store.rs for the
 * trust model), build a Dataset per matching entry, and hand the
 * credentials to the OS. The decrypted values exist only for the
 * duration of the fill and go straight to the target app's fields.
 *
 * If no stored PIN exists (biometric unlock not enabled), we return no
 * response — autofill stays silent and the user unlocks NexPass itself.
 * No PIN is ever transmitted, logged, or cached beyond this call.
 */
class NexPassAutofillService : AutofillService() {

    override fun onFillRequest(request: FillRequest, cancellationSignal: CancellationSignal, callback: FillCallback) {
        try {
            val structure: AssistStructure? = request.fillContexts.lastOrNull()?.structure
            if (structure == null) {
                callback.onSuccess(null)
                return
            }

            val fields = mutableListOf<ViewStructure>()
            walkStructure(structure.windowNodeList) { node ->
                val hints = node.autofillHints ?: return@walkStructure
                if (hints.any { it == ViewStructure.AUTOFILL_HINT_USER_NAME || it == ViewStructure.AUTOFILL_HINT_PASSWORD || it == ViewStructure.AUTOFILL_HINT_EMAIL_ADDRESS }) {
                    node.autofillId?.let { fields.add(node) }
                }
            }
            if (fields.isEmpty()) {
                callback.onSuccess(null) // nothing we recognize — stay out of the way
                return
            }

            val pin = VaultCrypto.readStoredPin(this)
            if (pin == null) {
                callback.onSuccess(manualUnlockResponse(request))
                return
            }

            val entries = VaultCrypto.loadEntries(this, pin)
            if (entries.isNullOrEmpty()) {
                callback.onSuccess(null)
                return
            }

            val packageName = structure.windowNodeList.firstOrNull()?.title?.toString() ?: ""
            val relevant = pickEntries(entries, packageName)
                .ifEmpty { entries.take(5) }

            val response = FillResponse.Builder()
            for (entry in relevant) {
                val dataset = buildDataset(request.fillContexts, entry)
                if (dataset != null) response.addDataset(dataset)
            }
            response.setSaveInfo(saveInfo())
            callback.onSuccess(response.build())
        } catch (_: Exception) {
            // Never crash from a background service — degrade to "no fill".
            try { callback.onSuccess(null) } catch (_: Exception) {}
        }
    }

    /** Prefer entries whose saved domain matches the app being filled into. */
    private fun pickEntries(entries: List<VaultCrypto.VaultEntry>, targetPackage: String): List<VaultCrypto.VaultEntry> {
        if (targetPackage.isBlank()) return emptyList()
        val pkg = targetPackage.lowercase()
        return entries.filter { e ->
            val host = e.url?.substringAfter("://")?.substringBefore("/")?.lowercase() ?: ""
            host.isNotEmpty() && (pkg.contains(host.substringBefore(".")) || host.contains(pkg.substringBefore(".")))
        }
    }

    private fun buildDataset(contexts: List<FillContext>, entry: VaultCrypto.VaultEntry): Dataset? {
        val present = mutableMapOf<AutofillId, ViewStructure>()
        for (ctx in contexts) {
            walkStructure(ctx.structure.windowNodeList) { node ->
                node.autofillId?.let { present[it] = node }
            }
        }

        val usernameValue = entry.username ?: ""
        val passwordValue = entry.password ?: ""
        if (usernameValue.isEmpty() && passwordValue.isEmpty()) return null

        val presentation = RemoteViews(packageName, R.layout.autofill_item).apply {
            setTextViewText(R.id.autofill_title, entry.title)
            setTextViewText(R.id.autofill_username, usernameValue.ifEmpty { entry.category })
        }

        val builder = Dataset.Builder()
        var filled = 0
        for ((id, node) in present) {
            val hints = node.autofillHints ?: continue
            val isUser = hints.any { it == ViewStructure.AUTOFILL_HINT_USER_NAME || it == ViewStructure.AUTOFILL_HINT_EMAIL_ADDRESS }
            val isPass = hints.contains(ViewStructure.AUTOFILL_HINT_PASSWORD)
            when {
                isUser && usernameValue.isNotEmpty() -> builder.setValue(id, AutofillValue.forText(usernameValue))
                isPass && passwordValue.isNotEmpty() -> builder.setValue(id, AutofillValue.forText(passwordValue))
                else -> continue
            }
            filled++
        }
        if (filled == 0) return null
        return builder.setPresentation(presentation).build()
    }

    /** A friendly inline chip telling the user how to enable full autofill. */
    private fun manualUnlockResponse(request: FillRequest): FillResponse? {
        val structure = request.fillContexts.lastOrNull()?.structure ?: return null
        val firstId = structure.autofillIds?.firstOrNull() ?: return null
        val presentation = RemoteViews(packageName, R.layout.autofill_item).apply {
            val s = SpannableString("Unlock NexPass once (enable biometric unlock in Settings) to autofill")
            s.setSpan(RelativeSizeSpan(0.85f), 0, s.length, 0)
            setTextViewText(R.id.autofill_title, s)
            setTextViewText(R.id.autofill_username, "")
        }
        return FillResponse.Builder()
            .setSaveInfo(saveInfo())
            .addDataset(Dataset.Builder().setPresentation(presentation).build())
            .build()
    }

    private fun saveInfo(): android.service.autofill.SaveInfo =
        SaveInfo.Builder(
            android.service.autofill.SaveDataType.PASSWORD or android.service.autofill.SaveDataType.USERNAME,
            arrayOf(android.view.autofill.AutofillId())
        ).build()

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        // Saving new credentials from other apps is a later step — the
        // vault write path lives in the Tauri runtime. Silently decline.
        callback.onSuccess()
    }

    private fun walkStructure(nodes: List<AssistStructure.WindowNode>, visit: (ViewStructure) -> Unit) {
        for (window in nodes) walkNode(window.rootViewNode, visit)
    }

    private fun walkNode(node: ViewStructure?, visit: (ViewStructure) -> Unit) {
        if (node == null) return
        visit(node)
        for (i in 0 until node.childCount) walkNode(node.getChildAt(i), visit)
    }
}
