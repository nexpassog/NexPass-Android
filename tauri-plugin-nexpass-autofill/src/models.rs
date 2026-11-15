use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenAutofillSettingsRequest {}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenAutofillSettingsResponse {}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutofillStatusResponse {
    /// NexPass is registered as the system autofill provider.
    pub enabled: bool,
    /// A biometric-gated PIN exists so autofill can decrypt on demand.
    pub ready: bool,
}
