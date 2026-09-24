// @trace TASK-138
// @trace TASK-142
use holonomy_core::manager::license_manager::{is_license_valid, set_license_valid, resolve_and_verify_license, verify_and_set, LicenseEnvelope, LicenseError};
use holonomy_core::config::resolver::{ResolvedConfiguration, ResolvedLicenseConfig};
use serial_test::serial;

#[tokio::test]
#[serial]
async fn test_license_manager_invalid_env() {
    set_license_valid(false);
    
    let mut config = ResolvedConfiguration::default();
    config.license = ResolvedLicenseConfig {
        key: Some("invalid_json".to_string()),
    };
    
    let result = resolve_and_verify_license(&config).await;
    assert!(matches!(result, Err(LicenseError::ParseError(_))));
    assert!(!is_license_valid());
}

#[tokio::test]
#[serial]
async fn test_license_manager_valid_config() {
    set_license_valid(false);
    
    let private_key_hex = "a7666c6e7bfb4ed299d18f1302c2e21007f6cbf59bedb7e53b9aa5686e67684d";
    let priv_bytes = hex::decode(private_key_hex).unwrap();
    let mut priv_array = [0u8; 32];
    priv_array.copy_from_slice(&priv_bytes);
    
    // Future date ensures validity
    let payload = r#"{"customer_id": "test", "expires_at": "2050-01-01"}"#;
    let signature = holonomy_core::policy::signer::sign_manifest(payload, &priv_array).unwrap();
    
    let envelope = LicenseEnvelope {
        signature,
        payload: payload.to_string(),
    };
    let envelope_json = serde_json::to_string(&envelope).unwrap();
    
    let mut config = ResolvedConfiguration::default();
    config.license = ResolvedLicenseConfig {
        key: Some(envelope_json),
    };
    
    let result = resolve_and_verify_license(&config).await;
    assert!(result.is_ok());
    assert!(is_license_valid());
}

#[tokio::test]
#[serial]
async fn test_license_manager_expired_config() {
    set_license_valid(false);
    
    let private_key_hex = "a7666c6e7bfb4ed299d18f1302c2e21007f6cbf59bedb7e53b9aa5686e67684d";
    let priv_bytes = hex::decode(private_key_hex).unwrap();
    let mut priv_array = [0u8; 32];
    priv_array.copy_from_slice(&priv_bytes);
    
    // Past date ensures expiration
    let payload = r#"{"customer_id": "test", "expires_at": "2020-01-01"}"#;
    let signature = holonomy_core::policy::signer::sign_manifest(payload, &priv_array).unwrap();
    
    let envelope = LicenseEnvelope {
        signature,
        payload: payload.to_string(),
    };
    let envelope_json = serde_json::to_string(&envelope).unwrap();
    
    let mut config = ResolvedConfiguration::default();
    config.license = ResolvedLicenseConfig {
        key: Some(envelope_json),
    };
    
    let result = resolve_and_verify_license(&config).await;
    assert!(matches!(result, Err(LicenseError::VerificationFailed(_))));
    assert!(!is_license_valid());
}

#[test]
#[serial]
fn test_verify_and_set_pure_logic_invalid_utf8() {
    // Tests the pure verification logic against garbage data (which could simulate corrupted S3 payload)
    set_license_valid(false);
    
    let result = verify_and_set("garbage data");
    assert!(matches!(result, Err(LicenseError::ParseError(_))));
    assert!(!is_license_valid());
}
