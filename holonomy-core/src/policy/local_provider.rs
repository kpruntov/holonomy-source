// @trace TASK-131
use crate::manager::policy_manager::{PolicyError, PolicyProvider};
use crate::policy::manifest::{PolicyEnvelope, PolicyLevel};
use crate::policy::signer;
use std::fs;
use std::path::Path;

pub struct LocalPolicyProvider {
    directory: String,
    private_key: [u8; 32],
}

impl LocalPolicyProvider {
    pub fn new(directory: String, private_key: [u8; 32]) -> Self {
        Self {
            directory,
            private_key,
        }
    }
}

impl PolicyProvider for LocalPolicyProvider {
    fn discover_policies(&self, _target: &str) -> Result<Vec<(PolicyLevel, String)>, PolicyError> {
        let mut policies = Vec::new();
        let path = Path::new(&self.directory);

        if !path.exists() || !path.is_dir() {
            // No local policies found, return empty
            return Ok(policies);
        }

        let entries = fs::read_dir(path).map_err(|e| PolicyError::DiscoveryFailed(e.to_string()))?;

        for entry in entries {
            let entry = entry.map_err(|e| PolicyError::DiscoveryFailed(e.to_string()))?;
            let file_path = entry.path();
            if file_path.is_file()
                && let Some(ext) = file_path.extension().map(|e| e.to_string_lossy().to_lowercase())
                    && (ext == "yaml" || ext == "yml" || ext == "json") {
                        let content = fs::read_to_string(&file_path)
                            .map_err(|e| PolicyError::DiscoveryFailed(e.to_string()))?;

                        // Try parsing it as a PolicyEnvelope first. If it already is an envelope, just pass it through.
                        let is_envelope = serde_json::from_str::<PolicyEnvelope>(&content).is_ok();

                        let envelope_json = if is_envelope {
                            content
                        } else {
                            // If it's a raw manifest, sign it in-memory
                            let signature = signer::sign_manifest(&content, &self.private_key)
                                .map_err(|_| PolicyError::InvalidSignature)?;

                            let envelope = PolicyEnvelope {
                                signature,
                                payload: content,
                            };

                            serde_json::to_string(&envelope)
                                .map_err(|e| PolicyError::ParseError(e.to_string()))?
                        };

                        policies.push((PolicyLevel::Local, envelope_json));
                    }
        }

        Ok(policies)
    }
}
