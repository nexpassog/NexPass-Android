use tauri::{
    plugin::{Builder, TauriPlugin},
    Manager, Runtime,
};

pub use models::*;

#[cfg(desktop)]
mod desktop;
#[cfg(mobile)]
mod mobile;

mod commands;
mod error;
mod models;

pub use error::{Error, Result};

#[cfg(desktop)]
use desktop::NexpassAutofill;
#[cfg(mobile)]
use mobile::NexpassAutofill;

/// Extensions to [`tauri::App`], [`tauri::AppHandle`] and [`tauri::Window`] to access the nexpass-autofill APIs.
pub trait NexpassAutofillExt<R: Runtime> {
    fn nexpass_autofill(&self) -> &NexpassAutofill<R>;
}

impl<R: Runtime, T: Manager<R>> crate::NexpassAutofillExt<R> for T {
    fn nexpass_autofill(&self) -> &NexpassAutofill<R> {
        self.state::<NexpassAutofill<R>>().inner()
    }
}

/// Initializes the plugin.
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("nexpass-autofill")
        .invoke_handler(tauri::generate_handler![
            commands::open_autofill_settings,
            commands::autofill_status
        ])
        .setup(|app, api| {
            #[cfg(mobile)]
            let nexpass_autofill = mobile::init(app, api)?;
            #[cfg(desktop)]
            let nexpass_autofill = desktop::init(app, api)?;
            app.manage(nexpass_autofill);
            Ok(())
        })
        .build()
}
