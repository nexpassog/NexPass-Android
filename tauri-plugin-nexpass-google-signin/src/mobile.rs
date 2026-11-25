use serde::de::DeserializeOwned;
use tauri::{
    plugin::{PluginApi, PluginHandle},
    AppHandle, Runtime,
};

use crate::models::*;
use crate::error::{Error, Result};

#[cfg(target_os = "android")]
tauri::android_plugin_binding!(init_plugin_nexpass_google_signin);

pub fn init<R: Runtime, C: DeserializeOwned>(
    _app: &AppHandle<R>,
    api: PluginApi<R, C>,
) -> Result<NexpassGoogleSignin<R>> {
    #[cfg(target_os = "android")]
    let handle = api.register_android_plugin("com.nexapp.nexpass.googlesignin", "GoogleSignInPlugin")?;
    #[cfg(target_os = "ios")]
    let handle = api.register_ios_plugin(init_plugin_nexpass_google_signin)?;
    Ok(NexpassGoogleSignin(handle))
}

/// Access to the nexpass-google-signin APIs.
pub struct NexpassGoogleSignin<R: Runtime>(PluginHandle<R>);

impl<R: Runtime> NexpassGoogleSignin<R> {
    pub async fn sign_in(&self) -> Result<SignInResponse> {
        self.0
            .run_mobile_plugin("signIn", ())
            .await
            .map_err(|e| Error::PluginError(e.to_string()))
    }

    pub async fn sign_out(&self) -> Result<()> {
        self.0
            .run_mobile_plugin("signOut", ())
            .await
            .map_err(|e| Error::PluginError(e.to_string()))
    }

    pub async fn get_current_user(&self) -> Result<CurrentUserResponse> {
        self.0
            .run_mobile_plugin("getCurrentUser", ())
            .await
            .map_err(|e| Error::PluginError(e.to_string()))
    }

    pub async fn is_available(&self) -> Result<AvailabilityResponse> {
        self.0
            .run_mobile_plugin("isAvailable", ())
            .await
            .map_err(|e| Error::PluginError(e.to_string()))
    }
}