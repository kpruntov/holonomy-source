// @trace TASK-020
use crate::audit::ring_buffer::{Action, AuditEvent, AuditRingBuffer};
use crate::crypto::dek_cache::DekCache;
use chrono::Utc;
use reqwest::Client;
use std::sync::Arc;

pub struct KmsAdmin {
    endpoint: String,
    client: Client,
    dek_cache: Arc<DekCache>,
    audit_buffer: Arc<AuditRingBuffer>,
}

impl KmsAdmin {
    pub fn new(
        endpoint: String,
        dek_cache: Arc<DekCache>,
        audit_buffer: Arc<AuditRingBuffer>,
    ) -> Self {
        Self {
            endpoint,
            client: Client::new(),
            dek_cache,
            audit_buffer,
        }
    }

    /// Triggers the permanent deletion of a specific micro-partition Data Encryption Key (DEK)
    /// within the remote KMS.
    pub async fn shred_partition(
        &self,
        dek_id: &str,
        user_hash: &str,
        purpose: &str,
    ) -> Result<(), String> {
        // Record Action::Shred in the audit logs BEFORE the irreversible action
        let event = AuditEvent {
            timestamp: Utc::now(),
            user_hash: user_hash.to_string(),
            file_signature: dek_id.to_string(),
            accessed_columns: None,
            business_purpose: purpose.to_string(),
            action: Action::Shred,
        };

        self.audit_buffer.push(event);

        let url = format!("{}/keys/{}", self.endpoint, dek_id);

        let res = self
            .client
            .delete(&url)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if !res.status().is_success() {
            return Err(format!("KMS API error: {}", res.status()));
        }

        // Drop key from local cache to ensure subsequent reads fail.
        self.dek_cache.remove(dek_id);

        Ok(())
    }
}
