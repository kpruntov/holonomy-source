// @trace TASK-065, TASK-066
use holonomy_core::manager::governance_manager::SchemaRegistryProvider;
use holonomy_core::manager::policy_manager::{PolicyError, PolicyProvider};
use holonomy_core::policy::manifest::PolicyLevel;

#[allow(dead_code)]
pub struct MockPolicyProvider;

impl PolicyProvider for MockPolicyProvider {
    fn discover_policies(&self, _target: &str) -> Result<Vec<(PolicyLevel, String)>, PolicyError> {
        let dummy = r#"{"signature": "dummy", "payload": "{\"version\": \"1.0\", \"roles\": {}, \"encryption\": {\"required_tags\": [\"pii\", \"phi\", \"pci\", \"sensitive\"], \"required_columns\": [\"ssn\", \"password\", \"secret\", \"salary\", \"credit_card\", \"dob\", \"email\", \"phone\"]}}"}"#.to_string();
        Ok(vec![(PolicyLevel::Local, dummy)])
    }
}

#[allow(dead_code)]
pub struct MockSchemaRegistryProvider;

impl SchemaRegistryProvider for MockSchemaRegistryProvider {
    fn resolve_contract(&self, _target: &str) -> Option<String> {
        None
    }
}

#[allow(dead_code)]
pub struct MockKmsProvider;
#[async_trait::async_trait]
impl holonomy_core::manager::crypto_manager::KmsProvider for MockKmsProvider {
    async fn decrypt_dek(
        &self,
        _wrapped_dek_ciphertext: &[u8],
        _context: Option<&std::collections::HashMap<String, String>>,
    ) -> Result<Vec<u8>, holonomy_core::manager::crypto_manager::CryptoError> {
        Ok(b"1234567890123456".to_vec())
    }

    async fn wrap_key(
        &self,
        key: &[u8],
        _context: Option<&std::collections::HashMap<String, String>>,
    ) -> Result<Vec<u8>, holonomy_core::manager::crypto_manager::CryptoError> {
        let mut wrapped = b"kms_wrapped:".to_vec();
        wrapped.extend_from_slice(key);
        Ok(wrapped)
    }
}
