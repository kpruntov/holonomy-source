// @trace TASK-131
use holonomy_core::manager::policy_manager::PolicyProvider;
use holonomy_core::policy::local_provider::LocalPolicyProvider;
use std::fs;
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use tempfile::tempdir;

#[test]
fn test_local_policy_provider_discovers_and_signs() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("policy.yaml");
    let raw_manifest = r#"
version: "1.0"
principals: {}
"#;
    fs::write(&file_path, raw_manifest).unwrap();

    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let private_key = signing_key.to_bytes();

    let provider = LocalPolicyProvider::new(dir.path().to_string_lossy().to_string(), private_key);
    
    let policies = provider.discover_policies("test_target").expect("Discovery should succeed");
    
    assert_eq!(policies.len(), 1);
    let (_level, envelope_json) = &policies[0];
    
    // We expect a signed envelope
    let envelope: holonomy_core::policy::manifest::PolicyEnvelope = serde_json::from_str(envelope_json).expect("Should be a valid envelope");
    assert_eq!(envelope.payload, raw_manifest);
    assert!(!envelope.signature.is_empty());
}
