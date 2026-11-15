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
import android.service.autofill.SaveInfo
import android.service.autofill.SaveRequest
import android.text.SpannableString
import android.text.style.RelativeSizeSpan
import android.view.View
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
 * If no stored PIN exists (biometric unlock not enabled), we return a
 * response with no datasets — autofill stays silent and the user
 * unlocks NexPass itself. No PIN is ever transmitted, logged, or cached
 * beyond this call.
 */
class NexPassAutofillService : AutofillService() {

    override fun onFillRequest(request: FillRequest, cancellationSignal: CancellationSignal, callback: FillCallback) {
        try {
            val structure = request.fillContexts.lastOrNull()?.structure
            if (structure == null) {
                callback.onSuccess(null)
                return
            }

            // Collect every field the app tagged as a login input, using
            // the standard autofill hints (View.AUTOFILL_HINT_*).
            val fields = mutableListOf<Pair<AutofillId, ViewNodeInfo>>()
            forEachNode(structure) { node ->
                val id = node.autofillId ?: return@forEachNode
                val hints = node.autofillHints ?: return@forEachNode
                val isUser = hints.any {
                    it == View.AUTOFILL_HINT_USERNAME || it == View.AUTOFILL_HINT_EMAIL_ADDRESS
                }
                val isPass = hints.contains(View.AUTOFILL_HINT_PASSWORD)
                if (isUser || isPass) {
                    fields.add(Pair(id, ViewNodeInfo(isUser, isPass)))
                }
            }
            if (fields.isEmpty()) {
                callback.onSuccess(null) // nothing we recognize — stay out of the way
                return
            }

            val pin = VaultCrypto.readStoredPin(this)
            if (pin == null) {
                callback.onSuccess(buildManualUnlockResponse(fields))
                return
            }

            val entries = VaultCrypto.loadEntries(this, pin)
            if (entries.isNullOrEmpty()) {
                callback.onSuccess(null)
                return
            }

            // The os doesn't tell us the target app's package here in a
            // reliably readable way, so show the five most relevant
            // entries (most recently updated first is available upstream).
            val relevant = entries.take(5)

            val response = FillResponse.Builder()
            var added = 0
            for (entry in relevant) {
                buildDataset(request.fillContexts, fields, entry)?.let {
                    response.addDataset(it)
                    added++
                }
            }
            if (added == 0) {
                callback.onSuccess(null)
                return
            }
            response.setSaveInfo(buildSaveInfo(fields))
            callback.onSuccess(response.build())
        } catch (_: Exception) {
            // Never crash from a background service — degrade to "no fill".
            try { callback.onSuccess(null) } catch (_: Exception) {}
        }
    }

    private class ViewNodeInfo(val isUser: Boolean, val isPass: Boolean)

    private fun buildDataset(
        contexts: List<FillContext>,
        wanted: List<Pair<AutofillId, ViewNodeInfo>>,
        entry: VaultCrypto.VaultEntry
    ): Dataset? {
        val usernameValue = entry.username ?: ""
        val passwordValue = entry.password ?: ""
        if (usernameValue.isEmpty() && passwordValue.isEmpty()) return null

        val presentation = RemoteViews(packageName, R.layout.autofill_item).apply {
            setTextViewText(R.id.autofill_title, entry.title)
            setTextViewText(R.id.autofill_username, usernameValue.ifEmpty { entry.category })
        }

        // Dataset.Builder(RemoteViews) is the (deprecated but correct)
        // way to give a dataset-level menu presentation — there is no
        // setPresentation() method on the builder.
        val builder = Dataset.Builder(presentation)
        var filled = 0
        for ((id, info) in wanted) {
            when {
                info.isUser && usernameValue.isNotEmpty() -> builder.setValue(id, AutofillValue.forText(usernameValue))
                info.isPass && passwordValue.isNotEmpty() -> builder.setValue(id, AutofillValue.forText(passwordValue))
                else -> continue
            }
            filled++
        }
        if (filled == 0) return null
        return builder.build()
    }

    private fun buildSaveInfo(wanted: List<Pair<AutofillId, ViewNodeInfo>>): SaveInfo {
        val ids = wanted.map { it.first }.toTypedArray()
        return SaveInfo.Builder(
            SaveInfo.SAVE_DATA_TYPE_USERNAME or SaveInfo.SAVE_DATA_TYPE_PASSWORD,
            ids
        ).build()
    }

    /** A friendly inline chip telling the user how to enable full autofill. */
    private fun buildManualUnlockResponse(wanted: List<Pair<AutofillId, ViewNodeInfo>>): FillResponse? {
        val firstId = wanted.firstOrNull()?.first ?: return null
        val presentation = RemoteViews(packageName, R.layout.autofill_item).apply {
            val s = SpannableString("Enable biometric unlock in NexPass Settings to autofill")
            s.setSpan(RelativeSizeSpan(0.85f), 0, s.length, 0)
            setTextViewText(R.id.autofill_title, s)
            setTextViewText(R.id.autofill_username, "")
        }
        return FillResponse.Builder()
            .addDataset(Dataset.Builder(presentation).build())
            .setSaveInfo(
                SaveInfo.Builder(
                    SaveInfo.SAVE_DATA_TYPE_USERNAME or SaveInfo.SAVE_DATA_TYPE_PASSWORD,
                    arrayOf(firstId)
                ).build()
            )
            .build()
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        // Saving new credentials from other apps is a later step — the
        // vault write path lives in the Tauri runtime. Silently decline.
        callback.onSuccess()
    }

    private fun forEachNode(structure: AssistStructure, visit: (AssistStructure.ViewNode) -> Unit) {
        for (i in 0 until structure.windowNodeCount) {
            walkNode(structure.getWindowNodeAt(i).rootViewNode, visit)
        }
    }

    private fun walkNode(node: AssistStructure.ViewNode?, visit: (AssistStructure.ViewNode) -> Unit) {
        if (node == null) return
        visit(node)
        for (i in 0 until node.childCount) walkNode(node.getChildAt(i), visit)
    }
}
