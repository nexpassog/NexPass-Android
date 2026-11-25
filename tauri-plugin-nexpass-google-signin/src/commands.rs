use crate::{models::*, Error, Result};
use tauri::{Manager, Runtime};
use anyhow;

/// Sign in with Google using native Android Google Identity Services
#[tauri::command]
pub fn sign_in<R: Runtime>(app: tauri::AppHandle<R>) -> tauri::Result<SignInResponse> {
    let plugin = app
        .try_state::<crate::NexpassGoogleSignin<R>>()
        .ok_or_else(|| tauri::Error::Anyhow(anyhow::anyhow!("Google Sign-In plugin not available")))?;
    
    plugin.sign_in().map_err(|e| tauri::Error::Anyhow(anyhow::anyhow!(e.to_string())))
}

/// Sign out the current Google user
#[tauri::command]
pub fn sign_out<R: Runtime>(app: tauri::AppHandle<R>) -> tauri::Result<()> {
    let plugin = app
        .try_state::<crate::NexpassGoogleSignin<R>>()
        .ok_or_else(|| tauri::Error::Anyhow(anyhow::anyhow!("Google Sign-In plugin not available")))?;
    
    plugin.sign_out().map_err(|e| tauri::Error::Anyhow(anyhow::anyhow!(e.to_string())))
}

/// Get the currently signed-in Google user (if any)
#[tauri::command]
pub fn get_current_user<R: Runtime>(app: tauri::AppHandle<R>) -> tauri::Result<CurrentUserResponse> {
    let plugin = app
        .try_state::<crate::NexpassGoogleSignin<R>>()
        .ok_or_else(|| tauri::Error::Anyhow(anyhow::anyhow!("Google Sign-In plugin not available")))?;
    
    plugin.get_current_user().map_err(|e| tauri::Error::Anyhow(anyhow::anyhow!(e.to_string())))
}

/// Check if Google Sign-In is available on this platform
#[tauri::command]
pub fn is_available<R: Runtime>(app: tauri::AppHandle<R>) -> tauri::Result<AvailabilityResponse> {
    let plugin = app
        .try_state::<crate::NexpassGoogleSignin<R>>()
        .ok_or_else(|| tauri::Error::Anyhow(anyhow::anyhow!("Google Sign-In plugin not available")))?;
    
    plugin.is_available().map_err(|e| tauri::Error::Anyhow(anyhow::anyhow!(e.to_string())))
}