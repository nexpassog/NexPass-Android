use crate::{models::*, error::{Error, Result}};
use tauri::Runtime;

/// Desktop stub — Google Sign-In is only available on mobile
pub struct NexpassGoogleSignin<R: Runtime>(std::marker::PhantomData<R>);

impl<R: Runtime> NexpassGoogleSignin<R> {
    pub fn new() -> Self {
        Self(std::marker::PhantomData)
    }

    pub async fn sign_in(&self) -> Result<SignInResponse> {
        Err(Error::NotAvailable)
    }

    pub async fn sign_out(&self) -> Result<()> {
        Err(Error::NotAvailable)
    }

    pub async fn get_current_user(&self) -> Result<CurrentUserResponse> {
        Ok(CurrentUserResponse { user: None })
    }

    pub async fn is_available(&self) -> Result<AvailabilityResponse> {
        Ok(AvailabilityResponse { available: false })
    }
}