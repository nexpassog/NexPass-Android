package com.nexapp.nexpass.autofill

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.widget.RemoteViews
import com.nexapp.nexpass.autofill.R

/**
 * Home-screen widget: shows the vault size and the most recent entry
 * titles, one tap opens NexPass. Tapping a specific entry to copy its
 * password without unlocking the app would weaken the trust model (the
 * widget runs outside any biometric gate), so the whole widget is a
 * launcher — same posture as the app's own lock screen.
 */
class VaultWidgetProvider : AppWidgetProvider() {

    override fun onUpdate(context: Context, appWidgetManager: AppWidgetManager, appWidgetIds: IntArray) {
        val pin = VaultCrypto.readStoredPin(context)
        val entries = pin?.let { VaultCrypto.loadEntries(context, it) }

        for (id in appWidgetIds) {
            val views = RemoteViews(context.packageName, R.layout.widget_vault).apply {
                if (entries == null) {
                    setTextViewText(R.id.widget_count, "locked")
                    setTextViewText(R.id.widget_line1, "Tap to unlock your vault")
                    setTextViewText(R.id.widget_line2, "")
                } else {
                    setTextViewText(R.id.widget_count, "${entries.size} item${if (entries.size == 1) "" else "s"}")
                    val recent = entries.sortedByDescending { it.title }.take(2)
                    setTextViewText(R.id.widget_line1, recent.getOrNull(0)?.title ?: "")
                    setTextViewText(R.id.widget_line2, recent.getOrNull(1)?.title ?: "")
                }
            }

            val launch = context.packageManager.getLaunchIntentForPackage(context.packageName)
            if (launch != null) {
                val pending = PendingIntent.getActivity(
                    context, 0, launch,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
                )
                views.setOnClickPendingIntent(R.id.widget_root, pending)
            }
            appWidgetManager.updateAppWidget(id, views)
        }
    }

    override fun onEnabled(context: Context) { requestRefresh(context) }
    override fun onDeleted(context: Context, appWidgetIds: IntArray) { requestRefresh(context) }

    private fun requestRefresh(context: Context) {
        val ids = AppWidgetManager.getInstance(context)
            .getAppWidgetIds(ComponentName(context, VaultWidgetProvider::class.java))
        onUpdate(context, AppWidgetManager.getInstance(context), ids)
    }
}
