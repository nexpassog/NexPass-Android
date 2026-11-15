use tauri::{command, AppHandle, Runtime};

use crate::models::*;
use crate::NexpassAutofillExt;
use crate::Result;

#[command]
pub(crate) async fn open_autofill_settings<R: Runtime>(
    app: AppHandle<R>,
) -> Result<OpenAutofillSettingsResponse> {
    app.nexpass_autofill().open_autofill_settings()
}

#[command]
pub(crate) async fn autofill_status<R: Runtime>(app: AppHandle<R>) -> Result<AutofillStatusResponse> {
    app.nexpass_autofill().autofill_status()
}
