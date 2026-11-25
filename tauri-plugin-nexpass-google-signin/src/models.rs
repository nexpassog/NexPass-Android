use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleUser {
    pub id: String,
    pub email: String,
    pub display_name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub photo_url: Option<String>,
    pub id_token: String,
    pub server_auth_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignInResponse {
    pub user: GoogleUser,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentUserResponse {
    pub user: Option<GoogleUser>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvailabilityResponse {
    pub available: bool,
}