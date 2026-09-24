// @trace TASK-035, TASK-065
// @trace TASK-079
use crate::linter::validator::DataContract;
use crate::policy::manifest::{PolicyEnvelope, PolicyLevel, PolicyManifest};
use std::sync::Arc;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum PolicyError {
    #[error("Policy discovery failed for target: {0}")]
    DiscoveryFailed(String),
    #[error("Invalid signature on manifest")]
    InvalidSignature,
    #[error("Failed to merge policy layers")]
    MergeFailed,
    #[error("Failed to parse policy JSON: {0}")]
    ParseError(String),
}

pub trait PolicyProvider: Send + Sync {
    fn discover_policies(&self, target: &str) -> Result<Vec<(PolicyLevel, String)>, PolicyError>;
}

pub struct PolicyManager {
    provider: Arc<dyn PolicyProvider>,
    public_key: Option<[u8; 32]>,
}

impl PolicyManager {
    pub fn new_dangerously_allow_unsigned(provider: Arc<dyn PolicyProvider>) -> Self {
        eprintln!(
            "WARNING: PolicyManager initialized with new_dangerously_allow_unsigned(). Cryptographic signatures will NOT be verified!"
        );
        Self {
            provider,
            public_key: None,
        }
    }

    pub fn with_public_key(provider: Arc<dyn PolicyProvider>, public_key: [u8; 32]) -> Self {
        Self {
            provider,
            public_key: Some(public_key),
        }
    }

    pub fn discover_policies(
        &self,
        target: &str,
    ) -> Result<Vec<(PolicyLevel, String)>, PolicyError> {
        self.provider.discover_policies(target)
    }

    pub fn verify_signatures(
        &self,
        policies: &[(PolicyLevel, String)],
    ) -> Result<Vec<(PolicyLevel, PolicyManifest)>, PolicyError> {
        // LF-030: Verify Signatures
        // "The system fails safe if any manifest in the composition stack fails signature verification."
        // @trace TASK-068
        let mut parsed_policies = Vec::new();

        for (level, content) in policies {
            let envelope: PolicyEnvelope = serde_json::from_str(content)
                .map_err(|e| PolicyError::ParseError(e.to_string()))?;

            if let Some(pub_key_bytes) = &self.public_key {
                use ed25519_dalek::{Signature, Verifier, VerifyingKey};
                let verifying_key = VerifyingKey::from_bytes(pub_key_bytes)
                    .map_err(|_| PolicyError::InvalidSignature)?;

                let sig_bytes =
                    hex::decode(&envelope.signature).map_err(|_| PolicyError::InvalidSignature)?;
                let signature =
                    Signature::from_slice(&sig_bytes).map_err(|_| PolicyError::InvalidSignature)?;

                verifying_key
                    .verify(envelope.payload.as_bytes(), &signature)
                    .map_err(|_| PolicyError::InvalidSignature)?;
            } else {
                // Fails open ONLY if initialized via new_dangerously_allow_unsigned
            }

            let manifest: PolicyManifest = serde_json::from_str(&envelope.payload)
                .map_err(|e| PolicyError::ParseError(e.to_string()))?;

            parsed_policies.push((level.clone(), manifest));
        }
        Ok(parsed_policies)
    }

    pub fn merge_layers(
        &self,
        policies: &[(PolicyLevel, String)],
    ) -> Result<PolicyManifest, PolicyError> {
        // LF-028 & LF-029: Merge Layers and Conflict Resolution
        let mut parsed_policies = self.verify_signatures(policies)?;

        // Sort policies by level (Local = 0, Domain = 1, Global = 2)
        // We fold starting from Local, so Domain overwrites Local, and Global overwrites Domain.
        parsed_policies.sort_by(|a, b| a.0.cmp(&b.0));

        let mut iter = parsed_policies.into_iter();

        let first = match iter.next() {
            Some((_, m)) => m,
            None => {
                // Return an empty policy if no manifests discovered
                PolicyManifest {
                    version: "1.0".to_string(),
                    principals: std::collections::HashMap::new(),
                    encryption: None,
                    purpose_bindings: None,
                }
            }
        };

        let merged = iter.fold(first, |acc, (_, m)| acc.merge(m));

        Ok(merged)
    }

    // @trace TASK-071
    pub fn resolve_columns_to_encrypt(
        &self,
        contract: &DataContract,
        policy: &PolicyManifest,
    ) -> Vec<String> {
        let mut columns_to_encrypt = Vec::new();

        let (req_tags, req_cols) = if let Some(enc) = &policy.encryption {
            (enc.required_tags.clone(), enc.required_columns.clone())
        } else {
            (Vec::new(), Vec::new())
        };

        for col in &contract.columns {
            let mut is_sensitive = false;

            // 1. Explicit Semantic Tags matching policy.encryption.required_tags
            if let Some(tags) = &col.tags {
                for tag in tags {
                    if req_tags.contains(&tag.to_lowercase()) {
                        is_sensitive = true;
                        break;
                    }
                }
            }

            // 2. Column Name matching policy.encryption.required_columns
            if !is_sensitive
                && req_cols
                    .iter()
                    .any(|c| col.name.to_lowercase().contains(&c.to_lowercase()))
            {
                is_sensitive = true;
            }

            if is_sensitive {
                columns_to_encrypt.push(col.name.clone());
            }
        }

        columns_to_encrypt
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub struct MockPolicyProvider;

    impl PolicyProvider for MockPolicyProvider {
        fn discover_policies(
            &self,
            _target: &str,
        ) -> Result<Vec<(PolicyLevel, String)>, PolicyError> {
            let dummy = r#"{"signature": "dummy", "payload": "{\"version\": \"1.0\", \"geofencing\": null, \"principals\": {}, \"encryption\": {\"required_tags\": [\"pii\", \"phi\", \"pci\", \"sensitive\"], \"required_columns\": [\"ssn\", \"password\", \"secret\", \"salary\", \"credit_card\", \"dob\", \"email\", \"phone\"]}}"}"#.to_string();
            Ok(vec![(PolicyLevel::Local, dummy)])
        }
    }
}
