use tauri::{
    plugin::{Builder, TauriPlugin},
    Manager, Runtime,
};

#[cfg(desktop)]
mod desktop;
#[cfg(mobile)]
mod mobile;

mod commands;
mod error;
mod models;

pub use error::{Error, Result};
pub use models::*;

#[cfg(desktop)]
use desktop::NexpassGoogleSignin;
#[cfg(mobile)]
use mobile::NexpassGoogleSignin;

/// Extensions to [`tauri::App`], [`tauri::AppHandle`] and [`tauri::Window`] to access the nexpass-google-signin APIs.
pub trait NexpassGoogleSigninExt<R: Runtime> {
    fn nexpass_google_signin(&self) -> &NexpassGoogleSignin<R>;
}

impl<R: Runtime, T: Manager<R>> crate::NexpassGoogleSigninExt<R> for T {
    fn nexpass_google_signin(&self) -> &NexpassGoogleSignin<R> {
        self.state::<NexpassGoogleSignin<R>>().inner()
    }
}

/// Initializes the plugin.
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("nexpass-google-signin")
        .invoke_handler(tauri::generate_handler![
            commands::sign_in,
            commands::sign_out,
            commands::get_current_user,
            commands::is_available
        ])
        .setup(|app, api| {
            #[cfg(mobile)]
            let nexpass_google_signin = mobile::init(app, api)?;
            #[cfg(desktop)]
            let nexpass_google_signin = desktop::init(app, api)?;
            app.manage(nexpass_google_signin);
            Ok(())
        })
        .build()
}