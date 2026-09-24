// holonomy-core/src/manager/license_manager.rs
// @trace TASK-138
// @trace TASK-142
// @trace LCOMP-013
use std::sync::atomic::{AtomicBool, Ordering};
use crate::policy::signer::verify_manifest;
use crate::config::resolver::ResolvedConfiguration;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct LicenseEnvelope {
    pub signature: String,
    pub payload: String,
}

#[derive(Debug)]
pub enum LicenseError {
    Unlicensed,
    VerificationFailed(String),
    S3FetchFailed(String),
    InvalidUtf8(String),
    ParseError(String),
    HardcodedKeyInvalid,
}

pub const HOLONOMY_ROOT_PUBLIC_KEY_HEX: &str = "37e5de163b5391b05ec3d87bb3c908b48f58148bf6de52bf1fabe814bfb2bbd5";

static LICENSE_VALID: AtomicBool = AtomicBool::new(false);

pub fn is_license_valid() -> bool {
    LICENSE_VALID.load(Ordering::Acquire)
}

pub fn set_license_valid(valid: bool) {
    LICENSE_VALID.store(valid, Ordering::Release);
}

pub async fn resolve_and_verify_license(config: &ResolvedConfiguration) -> Result<bool, LicenseError> {
    // 1 & 2: Resolved through unified config engine (Env Var, CLI, TOML, etc.)
    if let Some(key) = &config.license.key {
        return verify_and_set(key).map(|_| true);
    }

    // 3: S3 Fallback
    let policy_bucket = &config.policy.central_bucket;
    if !policy_bucket.is_empty() {
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
        if !config.storage.endpoint.is_empty() {
            loader = loader.endpoint_url(&config.storage.endpoint);
        }
        if !config.storage.region.is_empty() {
            loader = loader.region(aws_config::Region::new(config.storage.region.clone()));
        }
        let sdk_config = loader.load().await;
        let client = aws_sdk_s3::Client::new(&sdk_config);
        
        return try_resolve_s3(&client, policy_bucket).await;
    }

    Err(LicenseError::Unlicensed)
}

async fn try_resolve_s3(client: &aws_sdk_s3::Client, policy_bucket: &str) -> Result<bool, LicenseError> {
    let resp = client.get_object().bucket(policy_bucket).key("holonomy.lic").send().await
        .map_err(|e| LicenseError::S3FetchFailed(e.to_string()))?;

    let body = resp.body.collect().await
        .map_err(|e| LicenseError::S3FetchFailed(e.to_string()))?;

    let content = String::from_utf8(body.into_bytes().to_vec())
        .map_err(|e| LicenseError::InvalidUtf8(e.to_string()))?;

    verify_and_set(&content).map(|_| true)
}

pub fn verify_and_set(content: &str) -> Result<(), LicenseError> {
    let envelope = serde_json::from_str::<LicenseEnvelope>(content)
        .map_err(|e| LicenseError::ParseError(e.to_string()))?;

    let mut pub_key = [0u8; 32];
    let bytes = hex::decode(HOLONOMY_ROOT_PUBLIC_KEY_HEX)
        .map_err(|_| LicenseError::HardcodedKeyInvalid)?;

    if bytes.len() != 32 {
        return Err(LicenseError::HardcodedKeyInvalid);
    }

    pub_key.copy_from_slice(&bytes);
    verify_manifest(&envelope.payload, &envelope.signature, &pub_key)
        .map_err(|e| LicenseError::VerificationFailed(format!("{:?}", e)))?;

    // Parse payload to check expiration
    let payload_value = serde_json::from_str::<serde_json::Value>(&envelope.payload)
        .map_err(|e| LicenseError::ParseError(format!("Payload is not valid JSON: {}", e)))?;
        
    if let Some(expires_at_str) = payload_value.get("expires_at").and_then(|v| v.as_str()) {
        let expiration_date = chrono::NaiveDate::parse_from_str(expires_at_str, "%Y-%m-%d")
            .map_err(|e| LicenseError::ParseError(format!("Invalid expires_at format (expected YYYY-MM-DD): {}", e)))?;
        let today = chrono::Utc::now().naive_utc().date();
        if today > expiration_date {
            return Err(LicenseError::VerificationFailed(format!("License expired on {}", expires_at_str)));
        }
    }

    set_license_valid(true);
    Ok(())
}
