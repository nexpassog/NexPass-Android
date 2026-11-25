use std::fmt;
use thiserror::Error;

#[derive(Error, Debug)]
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
}

pub type Result<T> = std::result::Result<T, Error>;