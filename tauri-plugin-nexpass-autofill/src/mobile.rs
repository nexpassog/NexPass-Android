use serde::de::DeserializeOwned;
use tauri::{
    plugin::{PluginApi, PluginHandle},
    AppHandle, Runtime,
};

use crate::models::*;

#[cfg(target_os = "ios")]
tauri::ios_plugin_binding!(init_plugin_nexpass_autofill);

// initializes the Kotlin plugin class
pub fn init<R: Runtime, C: DeserializeOwned>(
    _app: &AppHandle<R>,
    api: PluginApi<R, C>,
) -> crate::Result<NexpassAutofill<R>> {
    #[cfg(target_os = "android")]
    let handle = api.register_android_plugin("com.nexapp.nexpass.autofill", "AutofillPlugin")?;
    #[cfg(target_os = "ios")]
    let handle = api.register_ios_plugin(init_plugin_nexpass_autofill)?;
    Ok(NexpassAutofill(handle))
}

/// Access to the nexpass-autofill APIs.
pub struct NexpassAutofill<R: Runtime>(PluginHandle<R>);

impl<R: Runtime> NexpassAutofill<R> {
    pub fn open_autofill_settings(&self) -> crate::Result<OpenAutofillSettingsResponse> {
        self.0
            .run_mobile_plugin("openAutofillSettings", ())
            .map_err(Into::into)
    }

    pub fn autofill_status(&self) -> crate::Result<AutofillStatusResponse> {
        self.0
            .run_mobile_plugin("autofillStatus", ())
            .map_err(Into::into)
    }
}
