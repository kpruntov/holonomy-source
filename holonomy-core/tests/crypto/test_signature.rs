// @trace TASK-068
// @trace FR-018
use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;
use serde_json::json;
use std::sync::Arc;

use holonomy_core::manager::policy_manager::{PolicyError, PolicyManager, PolicyProvider};
use holonomy_core::policy::manifest::{PolicyEnvelope, PolicyLevel};

pub struct MockPolicyProvider;

impl PolicyProvider for MockPolicyProvider {
    fn discover_policies(&self, _target: &str) -> Result<Vec<(PolicyLevel, String)>, PolicyError> {
        Ok(vec![])
    }
}

#[test]
fn test_verify_signatures_valid() {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    let manifest = json!({
        "version": "1.0",
        "geofencing": null,
        "roles": {}
    });

    let payload = serde_json::to_string(&manifest).unwrap();
    let signature = signing_key.sign(payload.as_bytes());
    let signature_hex = hex::encode(signature.to_bytes());

    let envelope = PolicyEnvelope {
        signature: signature_hex,
        payload,
    };
    let content = serde_json::to_string(&envelope).unwrap();

    let manager =
        PolicyManager::with_public_key(Arc::new(MockPolicyProvider), verifying_key.to_bytes());

    let policies = vec![(PolicyLevel::Local, content)];
    let result = manager.verify_signatures(&policies);

    assert!(result.is_ok());
}

#[test]
fn test_verify_signatures_invalid() {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);

    let another_signing_key = SigningKey::generate(&mut csprng);
    let wrong_verifying_key = another_signing_key.verifying_key();

    let manifest = json!({
        "version": "1.0",
        "geofencing": null,
        "roles": {}
    });

    let payload = serde_json::to_string(&manifest).unwrap();
    let signature = signing_key.sign(payload.as_bytes());
    let signature_hex = hex::encode(signature.to_bytes());

    let envelope = PolicyEnvelope {
        signature: signature_hex,
        payload,
    };
    let content = serde_json::to_string(&envelope).unwrap();

    let manager = PolicyManager::with_public_key(
        Arc::new(MockPolicyProvider),
        wrong_verifying_key.to_bytes(),
    );

    let policies = vec![(PolicyLevel::Local, content)];
    let result = manager.verify_signatures(&policies);

    assert!(matches!(result, Err(PolicyError::InvalidSignature)));
}

#[test]
fn test_verify_signatures_tampered() {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    let manifest = json!({
        "version": "1.0",
        "geofencing": null,
        "roles": {}
    });

    let payload = serde_json::to_string(&manifest).unwrap();
    let signature = signing_key.sign(payload.as_bytes());
    let signature_hex = hex::encode(signature.to_bytes());

    // Tamper with the payload after signing
    let tampered_payload = payload.replace(r#""version":"1.0""#, r#""version":"1.1""#);

    let envelope = PolicyEnvelope {
        signature: signature_hex,
        payload: tampered_payload,
    };
    let content = serde_json::to_string(&envelope).unwrap();

    let manager =
        PolicyManager::with_public_key(Arc::new(MockPolicyProvider), verifying_key.to_bytes());

    let policies = vec![(PolicyLevel::Local, content)];
    let result = manager.verify_signatures(&policies);

    assert!(matches!(result, Err(PolicyError::InvalidSignature)));
}

#[test]
fn test_verify_signatures_pretty_printed() {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    // Use a pretty-printed literal
    let payload = r#"{
        "version": "1.0",
        "geofencing": null,
        "roles": {}
    }"#;

    let signature = signing_key.sign(payload.as_bytes());
    let signature_hex = hex::encode(signature.to_bytes());

    let envelope = PolicyEnvelope {
        signature: signature_hex,
        payload: payload.to_string(), // we package the exact pretty-printed string!
    };
    let content = serde_json::to_string(&envelope).unwrap();

    let manager =
        PolicyManager::with_public_key(Arc::new(MockPolicyProvider), verifying_key.to_bytes());

    let policies = vec![(PolicyLevel::Local, content)];
    let result = manager.verify_signatures(&policies);

    // If serialization destroyed whitespace, this signature would fail!
    assert!(result.is_ok());
}
