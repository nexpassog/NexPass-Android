use serde::de::DeserializeOwned;
use tauri::{plugin::PluginApi, AppHandle, Runtime};

use crate::models::*;

pub fn init<R: Runtime, C: DeserializeOwned>(
    _app: &AppHandle<R>,
    _api: PluginApi<R, C>,
) -> crate::Result<NexpassAutofill<R>> {
    Ok(NexpassAutofill(std::marker::PhantomData))
}

/// Desktop is a no-op — autofill is an Android OS feature.
/// `fn() -> R` keeps the marker Send+Sync so the plugin can be managed as state.
pub struct NexpassAutofill<R: Runtime>(std::marker::PhantomData<fn() -> R>);

impl<R: Runtime> NexpassAutofill<R> {
    pub fn open_autofill_settings(&self) -> crate::Result<OpenAutofillSettingsResponse> {
        Err(crate::Error::DesktopUnsupported)
    }

    pub fn autofill_status(&self) -> crate::Result<AutofillStatusResponse> {
        Ok(AutofillStatusResponse::default())
    }
}
