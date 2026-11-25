use serde::de::DeserializeOwned;
use tauri::{
    plugin::{PluginApi, PluginHandle},
    AppHandle, Runtime,
};

use crate::models::*;
use crate::error::{Error, Result};

pub fn init<R: Runtime, C: DeserializeOwned>(
    _app: &AppHandle<R>,
    api: PluginApi<R, C>,
) -> Result<NexpassGoogleSignin<R>> {
    #[cfg(target_os = "android")]
    let handle = api.register_android_plugin("com.nexapp.nexpass.googlesignin", "GoogleSignInPlugin")?;
    #[cfg(target_os = "ios")]
    let handle = api.register_ios_plugin("nexpass-google-signin")?; // will need iOS plugin later
    Ok(NexpassGoogleSignin(handle))
}

/// Access to the nexpass-google-signin APIs.
pub struct NexpassGoogleSignin<R: Runtime>(PluginHandle<R>);

impl<R: Runtime> NexpassGoogleSignin<R> {
    pub fn sign_in(&self) -> Result<SignInResponse> {
        self.0
            .run_mobile_plugin("signIn", ())
            .map_err(|e| Error::PluginError(e.to_string()))
    }

    pub fn sign_out(&self) -> Result<()> {
        self.0
            .run_mobile_plugin("signOut", ())
            .map_err(|e| Error::PluginError(e.to_string()))
    }

    pub fn get_current_user(&self) -> Result<CurrentUserResponse> {
        self.0
            .run_mobile_plugin("getCurrentUser", ())
            .map_err(|e| Error::PluginError(e.to_string()))
    }

    pub fn is_available(&self) -> Result<AvailabilityResponse> {
        self.0
            .run_mobile_plugin("isAvailable", ())
            .map_err(|e| Error::PluginError(e.to_string()))
    }
}