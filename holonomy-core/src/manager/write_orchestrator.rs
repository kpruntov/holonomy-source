// @trace TASK-017
// @trace TASK-040
// @trace TASK-041
// @trace TASK-042
// @trace TASK-079
// @trace TASK-115
// @trace TASK-122

use crate::audit::ring_buffer::{Action, AuditEvent, AuditRingBuffer};
use crate::crypto::pme_encrypt::StreamItem;
use crate::crypto::pme_encrypt::{PmeEncryptor, StorageUploader};
use crate::linter::validator::{LinterError, Validator};
use crate::manager::crypto_manager::CryptoManager;
use crate::manager::governance_manager::GovernanceManager;
use crate::manager::policy_manager::PolicyManager;
use arrow::record_batch::RecordBatch;
use chrono::Utc;
use parquet::arrow::ArrowWriter;
use std::sync::Arc;
use thiserror::Error;

// @trace TASK-039
struct ChannelWriter {
    buffer: Vec<u8>,
    chunk_size: usize,
    tx: tokio::sync::mpsc::Sender<StreamItem>,
    has_failed: bool,
}

impl std::io::Write for ChannelWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buffer.extend_from_slice(buf);
        while self.buffer.len() >= self.chunk_size {
            let remaining = self.buffer.split_off(self.chunk_size);
            let chunk = std::mem::replace(&mut self.buffer, remaining);
            if self.tx.blocking_send(StreamItem::Data(chunk)).is_err() {
                self.has_failed = true;
                return Err(std::io::Error::other("Channel closed"));
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if !self.buffer.is_empty() && !self.has_failed {
            let chunk = std::mem::take(&mut self.buffer);
            if self.tx.blocking_send(StreamItem::Data(chunk)).is_err() {
                self.has_failed = true;
                return Err(std::io::Error::other("Channel closed"));
            }
        }
        Ok(())
    }
}

impl Drop for ChannelWriter {
    fn drop(&mut self) {
        let _ = std::io::Write::flush(self);
    }
}

#[derive(Error, Debug)]
pub enum WriteError {
    #[error(
        "Missing purpose metadata. A valid purpose string is required for all read/write operations."
    )]
    MissingPurpose,
    #[error(
        "Missing data contract. A valid contract must be provided via GovernanceManager, a local .holonomy_contract.json file, or explicitly passed."
    )]
    MissingContract,
    #[error("Invalid data contract format: {0}")]
    InvalidContract(String),
    #[error("Linting failed: {0:?}")]
    LintFailed(Vec<LinterError>),
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Upload failed: {0}")]
    UploadFailed(String),
    #[error("Audit error: failed to record critical security audit event")]
    AuditFailed,
    #[error("Parquet serialization error: {0}")]
    SerializationError(String),
}

pub struct WriteOrchestrator {
    audit_buffer: Arc<AuditRingBuffer>,
    crypto_manager: Arc<CryptoManager>,
    uploader: Arc<dyn StorageUploader>,
    governance_manager: Arc<GovernanceManager>,
    policy_manager: Arc<PolicyManager>,
    pub sidecar_deks: Arc<dashmap::DashMap<String, crate::manager::sidecar::SidecarMetadata>>,
}

impl WriteOrchestrator {
    pub fn new(
        audit_buffer: Arc<AuditRingBuffer>,
        crypto_manager: Arc<CryptoManager>,
        uploader: Arc<dyn StorageUploader>,
        governance_manager: Arc<GovernanceManager>,
        policy_manager: Arc<PolicyManager>,
    ) -> Self {
        Self {
            audit_buffer,
            crypto_manager,
            uploader,
            governance_manager,
            policy_manager,
            sidecar_deks: Arc::new(dashmap::DashMap::new()),
        }
    }

    // @trace TASK-057
    pub async fn write(
        &self,
        batch: &RecordBatch,
        target: &str,
        purpose: Option<&str>,
        user_hash: &str,
        explicit_contract_json: Option<&str>,
    ) -> Result<(), WriteError> {
        let valid_purpose = match purpose {
            Some(p) if !p.trim().is_empty() => p.trim(),
            _ => return Err(WriteError::MissingPurpose),
        };

        // Step 2 & 3: Validate (Hierarchical Contract Resolution)
        let contract_str = if let Some(canonical) = self.governance_manager.resolve_contract(target)
        {
            canonical
        } else if let Ok(local_file) = std::fs::read_to_string(".holonomy_contract.json") {
            local_file
        } else if let Some(explicit) = explicit_contract_json {
            explicit.to_string()
        } else {
            return Err(WriteError::MissingContract);
        };

        let validator = Validator::from_json(&contract_str)
            .map_err(|e| WriteError::InvalidContract(format!("Invalid contract: {}", e)))?;

        let lint_errors = validator.validate(batch);
        if !lint_errors.is_empty() {
            return Err(WriteError::LintFailed(lint_errors));
        }

        // Fetch the effective policy
        let discovered_policies = self
            .policy_manager
            .discover_policies(target)
            .map_err(|e| WriteError::EncryptionFailed(format!("Policy discovery failed: {}", e)))?;
        let merged_policy = self
            .policy_manager
            .merge_layers(&discovered_policies)
            .map_err(|e| WriteError::EncryptionFailed(format!("Policy merge failed: {}", e)))?;

        // @trace TASK-071
        let columns_to_encrypt = self
            .policy_manager
            .resolve_columns_to_encrypt(&validator.contract, &merged_policy);

        let _partition_root = if let Some(idx) = target.rfind('/') {
            &target[..idx]
        } else {
            target
        };
        // @trace TASK-070
        let footer_dek = PmeEncryptor::generate_or_get_dek(
            &self.crypto_manager,
            _partition_root,
            valid_purpose,
            "__footer__",
            user_hash,
        )
        .await
        .map_err(|e| WriteError::EncryptionFailed(e.to_string()))?;

        let mut column_deks = std::collections::HashMap::new();
        let mut wrapped_column_deks = std::collections::HashMap::new();
        for col in columns_to_encrypt {
            let col_dek = PmeEncryptor::generate_or_get_dek(
                &self.crypto_manager,
                _partition_root,
                valid_purpose,
                &col,
                user_hash,
            )
            .await
            .map_err(|e| WriteError::EncryptionFailed(e.to_string()))?;
            column_deks.insert(col.clone(), col_dek.plaintext);
            wrapped_column_deks.insert(col, col_dek.wrapped);
        }

        use crate::manager::sidecar::SidecarKeyEntry;
        use base64::Engine;
        
        let mut keys_to_append = vec![
            SidecarKeyEntry {
                purpose: valid_purpose.to_string(),
                column: "__footer__".to_string(),
                wrapped_dek: base64::engine::general_purpose::STANDARD.encode(&footer_dek.wrapped),
            }
        ];
        
        for (col, dek) in &wrapped_column_deks {
            keys_to_append.push(SidecarKeyEntry {
                purpose: valid_purpose.to_string(),
                column: col.clone(),
                wrapped_dek: base64::engine::general_purpose::STANDARD.encode(dek),
            });
        }
        
        {
            let mut sidecar = self.sidecar_deks.entry(_partition_root.to_string()).or_default();
            for key in keys_to_append {
                if !sidecar.keys.contains(&key) {
                    sidecar.keys.push(key);
                }
            }
        }

        let encryptor = PmeEncryptor::new(
            footer_dek.plaintext,
            footer_dek.wrapped,
            column_deks,
            wrapped_column_deks,
        );
        let mut props_builder = encryptor.get_writer_properties_builder();

        // Extract semantic tags from DataContract and inject into KeyValue metadata
        let mut kv_metadata = Vec::new();
        for col in &validator.contract.columns {
            if let Some(tags) = &col.tags
                && !tags.is_empty()
            {
                let tags_str = tags.join(",");
                kv_metadata.push(parquet::file::metadata::KeyValue::new(
                    format!("holonomy.tags.{}", col.name),
                    tags_str,
                ));
            }
        }

        if !kv_metadata.is_empty() {
            props_builder = props_builder.set_key_value_metadata(Some(kv_metadata));
        }

        let props = props_builder.build();

        // Step 5 & 7: Serialize DataFrame to Arrow Buffer and stream to S3 (Zero-Copy)
        // @trace TASK-039
        let (tx, rx) = tokio::sync::mpsc::channel(10);
        let chunk_size = 5 * 1024 * 1024; // 5MB minimum for S3 multipart

        let batch_clone = batch.clone();
        let schema_clone = batch.schema();

        let tx_clone = tx.clone();
        let write_task = tokio::task::spawn_blocking(move || {
            let writer_sink = ChannelWriter {
                buffer: Vec::with_capacity(chunk_size),
                chunk_size,
                tx: tx_clone.clone(),
                has_failed: false,
            };

            let mut writer = ArrowWriter::try_new(writer_sink, schema_clone, Some(props))
                .map_err(|e| WriteError::SerializationError(e.to_string()))?;
            writer
                .write(&batch_clone)
                .map_err(|e| WriteError::SerializationError(e.to_string()))?;
            writer
                .close()
                .map_err(|e| WriteError::SerializationError(e.to_string()))?;

            // Explicitly signal success to the upload task
            let _ = tx_clone.blocking_send(StreamItem::Success);

            Ok::<(), WriteError>(())
        });

        // Step 8: Record write audit event *before* remote side effect
        let event = AuditEvent {
            timestamp: Utc::now(),
            user_hash: user_hash.to_string(),
            file_signature: target.to_string(),
            accessed_columns: None,
            business_purpose: valid_purpose.to_string(),
            action: Action::Write,
        };

        self.audit_buffer.push(event);

        // Step 7: Upload encrypted payload to S3
        let target_copy = target.to_string();

        // We must drop our end of `tx` so the channel closes if the write_task panics
        drop(tx);

        let upload_future = self.uploader.upload_stream(&target_copy, rx);

        let (upload_res, write_res) = tokio::join!(upload_future, write_task);

        write_res.map_err(|_| WriteError::SerializationError("Task panicked".to_string()))??;
        upload_res.map_err(|e| WriteError::UploadFailed(format!("{:#?}", e)))?;

        Ok(())
    }

    pub async fn flush_partition(&self, partition_root: &str) -> Result<(), WriteError> {
        if let Some((_, sidecar)) = self.sidecar_deks.remove(partition_root) {
            let json = serde_json::to_string(&sidecar)
                .map_err(|e| WriteError::SerializationError(e.to_string()))?;
            
            let target_key = format!("{}/_holonomy_keys.json", partition_root.trim_end_matches('/'));
            
            let (tx, rx) = tokio::sync::mpsc::channel(2);
            let _ = tx.send(StreamItem::Data(json.into_bytes())).await;
            let _ = tx.send(StreamItem::Success).await;
            
            self.uploader.upload_stream(&target_key, rx).await
                .map_err(|e| WriteError::UploadFailed(format!("{:?}", e)))?;
        }
        Ok(())
    }
}
