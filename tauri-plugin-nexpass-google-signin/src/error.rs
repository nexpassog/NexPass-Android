use serde::{ser::Serializer, Serialize};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Google Sign-In is not available on this platform")]
    NotAvailable,
    
    #[error("Google Sign-In was cancelled by the user")]
    Cancelled,
    
    #[error("Google Sign-In failed: {0}")]
    SignInFailed(String),
    
    #[error("No user is currently signed in")]
    NoUser,
    
    #[error("Plugin communication error: {0}")]
    PluginError(String),
    
    #[error("JSON parsing error: {0}")]
    JsonError(#[from] serde_json::Error),
    
    #[cfg(mobile)]
    #[error(transparent)]
    PluginInvoke(#[from] tauri::plugin::mobile::PluginInvokeError),
}

impl Serialize for Error {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_string().as_ref())
    }
}