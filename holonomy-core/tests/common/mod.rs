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
        wrapped_dek_ciphertext: &[u8],
        context: Option<&std::collections::BTreeMap<String, String>>,
    ) -> Result<Vec<u8>, holonomy_core::manager::crypto_manager::CryptoError> {
        let mut _key = wrapped_dek_ciphertext;
        if wrapped_dek_ciphertext.starts_with(b"kms_wrapped:") {
            let rest = &wrapped_dek_ciphertext[12..];
            let ctx_len = u32::from_le_bytes(rest[0..4].try_into().unwrap()) as usize;
            let expected_ctx_bytes = &rest[4..4 + ctx_len];
            let expected_ctx: Option<std::collections::BTreeMap<String, String>> = if ctx_len > 0 {
                Some(serde_json::from_slice(expected_ctx_bytes).unwrap())
            } else {
                None
            };
            if context != expected_ctx.as_ref() {
                return Err(
                    holonomy_core::manager::crypto_manager::CryptoError::KmsFailed(format!(
                        "AAD Context mismatch! Expected {:?}, got {:?}",
                        expected_ctx, context
                    )),
                );
            }
            _key = &rest[4 + ctx_len..];
        }
        Ok(b"1234567890123456".to_vec())
    }

    async fn wrap_key(
        &self,
        key: &[u8],
        context: Option<&std::collections::BTreeMap<String, String>>,
    ) -> Result<Vec<u8>, holonomy_core::manager::crypto_manager::CryptoError> {
        let mut wrapped = b"kms_wrapped:".to_vec();
        if let Some(ctx) = context {
            let ctx_bytes = serde_json::to_vec(ctx).unwrap();
            wrapped.extend_from_slice(&(ctx_bytes.len() as u32).to_le_bytes());
            wrapped.extend_from_slice(&ctx_bytes);
        } else {
            wrapped.extend_from_slice(&0u32.to_le_bytes());
        }
        wrapped.extend_from_slice(key);
        Ok(wrapped)
    }
}
