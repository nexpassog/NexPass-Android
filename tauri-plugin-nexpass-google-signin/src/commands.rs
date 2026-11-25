use crate::{models::*, Error, Result};
use tauri::Runtime;

/// Sign in with Google using native Android Google Identity Services
#[tauri::command]
pub async fn sign_in<R: Runtime>(app: tauri::AppHandle<R>) -> Result<SignInResponse> {
    let plugin = app
        .try_state::<crate::NexpassGoogleSignin<R>>()
        .ok_or(Error::NotAvailable)?;
    
    plugin.sign_in().await
}

/// Sign out the current Google user
#[tauri::command]
pub async fn sign_out<R: Runtime>(app: tauri::AppHandle<R>) -> Result<()> {
    let plugin = app
        .try_state::<crate::NexpassGoogleSignin<R>>()
        .ok_or(Error::NotAvailable)?;
    
    plugin.sign_out().await
}

/// Get the currently signed-in Google user (if any)
#[tauri::command]
pub async fn get_current_user<R: Runtime>(app: tauri::AppHandle<R>) -> Result<CurrentUserResponse> {
    let plugin = app
        .try_state::<crate::NexpassGoogleSignin<R>>()
        .ok_or(Error::NotAvailable)?;
    
    plugin.get_current_user().await
}

/// Check if Google Sign-In is available on this platform
#[tauri::command]
pub async fn is_available<R: Runtime>(app: tauri::AppHandle<R>) -> Result<AvailabilityResponse> {
    let plugin = app
        .try_state::<crate::NexpassGoogleSignin<R>>()
        .ok_or(Error::NotAvailable)?;
    
    plugin.is_available().await
}