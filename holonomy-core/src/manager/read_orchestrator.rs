// @trace TASK-078
// @trace TASK-013
// @trace TASK-040
// @trace TASK-041
// @trace TASK-042
// @trace TASK-101

use crate::audit::ring_buffer::{Action, AuditEvent, AuditRingBuffer};
use crate::ingestion::s3_client::{IngestionError, IngestionProvider};
use crate::manager::crypto_manager::CryptoManager;
use crate::manager::governance_manager::{GovernanceError, GovernanceManager};
use crate::manager::policy_manager::{PolicyError, PolicyManager};
use arrow::array::Array;
use arrow::record_batch::RecordBatch;
use chrono::Utc;
use std::sync::Arc;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ReadError {
    #[error(
        "Missing purpose metadata. A valid purpose string is required for all read/write operations."
    )]
    MissingPurpose,
    #[error("Policy error: {0}")]
    PolicyFailed(#[from] PolicyError),
    #[error("Governance error: {0}")]
    GovernanceFailed(#[from] GovernanceError),
    #[error("Ingestion error: {0:?}")]
    IngestionFailed(IngestionError),
    #[error("Crypto error: {0}")]
    CryptoFailed(#[from] crate::manager::crypto_manager::CryptoError),
    #[error("Audit error: failed to record critical security audit event")]
    AuditFailed,
}

impl From<IngestionError> for ReadError {
    fn from(e: IngestionError) -> Self {
        ReadError::IngestionFailed(e)
    }
}

pub struct ReadOrchestrator {
    audit_buffer: Arc<AuditRingBuffer>,
    s3_client: Arc<dyn IngestionProvider>,
    crypto_manager: Arc<CryptoManager>,
    policy_manager: Arc<PolicyManager>,
    governance_manager: Arc<GovernanceManager>,
}

impl ReadOrchestrator {
    pub fn new(
        audit_buffer: Arc<AuditRingBuffer>,
        s3_client: Arc<dyn IngestionProvider>,
        crypto_manager: Arc<CryptoManager>,
        policy_manager: Arc<PolicyManager>,
        governance_manager: Arc<GovernanceManager>,
    ) -> Self {
        Self {
            audit_buffer,
            s3_client,
            crypto_manager,
            policy_manager,
            governance_manager,
        }
    }

    /// Warning: This function allocates contiguous memory by concatenating all chunks.
    /// Massive data retrieval should strictly prefer `scan()`.
    #[allow(clippy::too_many_arguments)]
    pub async fn read(
        &self,
        target: &str,
        purpose: Option<&str>,
        user_ctx: &crate::auth::jwt_validator::UserContext,
        column_to_read: &str,
        contract_json: Option<&str>,
        assumed_role: Option<&str>,
        fail_closed_mode: Option<crate::manager::governance_manager::FailClosedMode>,
    ) -> Result<Arc<dyn Array>, ReadError> {
        let user_hash = user_ctx.identity();
        // LF-013: Guard Purpose
        let valid_purpose = match purpose {
            Some(p) if !p.trim().is_empty() => p.trim(),
            _ => return Err(ReadError::MissingPurpose),
        };

        // Governance / Policy Checks
        let policies = self.policy_manager.discover_policies(target)?;
        self.policy_manager.verify_signatures(&policies)?;
        let merged_policy = self.policy_manager.merge_layers(&policies)?;

        // @trace TASK-059, TASK-061: Fetch FileDecryptionProperties
        let decryption_props = match self
            .crypto_manager
            .get_decryption_properties(None, Some(user_hash.to_string()))
        {
            Ok(props) => props,
            Err(e) => {
                let event = AuditEvent {
                    timestamp: Utc::now(),
                    user_hash: user_hash.to_string(),
                    file_signature: target.to_string(),
                    accessed_columns: None,
                    business_purpose: valid_purpose.to_string(),
                    action: Action::Read,
                };
                self.audit_buffer.push(event);
                return Err(ReadError::CryptoFailed(e));
            }
        };

        // @trace TASK-059: Native Parquet PME Decoding
        let async_reader = crate::ingestion::s3_client::S3AsyncFileReader::new(
            self.s3_client.clone(),
            target.to_string(),
            Some(decryption_props.clone()),
        );
        let options = parquet::arrow::arrow_reader::ArrowReaderOptions::new()
            .with_file_decryption_properties(decryption_props);
        let mut builder =
            match parquet::arrow::async_reader::ParquetRecordBatchStreamBuilder::new_with_options(
                async_reader,
                options,
            )
            .await
            {
                Ok(b) => b,
                Err(e) => {
                    if e.to_string().contains("KMS Failed") {
                        let event = AuditEvent {
                            timestamp: Utc::now(),
                            user_hash: user_hash.to_string(),
                            file_signature: target.to_string(),
                            accessed_columns: None,
                            business_purpose: valid_purpose.to_string(),
                            action: Action::Read,
                        };
                        self.audit_buffer.push(event);
                        return Err(ReadError::CryptoFailed(
                            crate::manager::crypto_manager::CryptoError::KmsFailed(e.to_string()),
                        ));
                    } else {
                        return Err(ReadError::IngestionFailed(IngestionError::Parquet(e)));
                    }
                }
            };

        // Parse Parquet Footer from the decrypted builder
        let metadata = builder.metadata().clone();
        let num_rows = metadata.file_metadata().num_rows() as usize;

        // Resolve target unified schema to allow reading missing columns if defined in contract
        let unified_schema = if let Some(json) = contract_json {
            let validator = crate::linter::validator::Validator::from_json(json)
                .map_err(|e| ReadError::IngestionFailed(IngestionError::ParseFailed(e)))?;
            Some(
                validator
                    .to_arrow_schema()
                    .map_err(|e| ReadError::IngestionFailed(IngestionError::ParseFailed(e)))?,
            )
        } else {
            None
        };

        let file_cols: Vec<String> = metadata
            .file_metadata()
            .schema_descr()
            .columns()
            .iter()
            .map(|c| c.name().to_string())
            .collect();

        let mut policy_predicates = Vec::new();
        let mut hidden_cols = Vec::new();
        if let Ok(active_role) =
            crate::manager::governance_manager::GovernanceManager::resolve_active_role(
                user_ctx,
                &merged_policy,
                assumed_role,
                Some(valid_purpose),
            )
            && let Some(role_policy) = merged_policy.principals.get(active_role)
        {
            for filter_str in &role_policy.global_row_filters {
                if let Some(pred) = crate::ingestion::s3_client::Predicate::parse_filter(filter_str)
                {
                    let col = pred.column().to_string();
                    if !file_cols.contains(&col) {
                        return Err(ReadError::GovernanceFailed(
                            crate::manager::governance_manager::GovernanceError::AccessDenied(
                                format!("Global row filter references missing column '{}'", col),
                            ),
                        ));
                    }
                    policy_predicates.push(pred);
                    hidden_cols.push(col);
                }
            }
            for filter_str in &role_policy.selective_row_filters {
                if let Some(pred) = crate::ingestion::s3_client::Predicate::parse_filter(filter_str)
                {
                    let col = pred.column().to_string();
                    if file_cols.contains(&col) {
                        policy_predicates.push(pred);
                        hidden_cols.push(col);
                    }
                }
            }
        }

        if !file_cols.contains(&column_to_read.to_string())
            && let Some(us) = &unified_schema
            && let Ok(field) = us.field_with_name(column_to_read)
        {
            let null_array = arrow::array::new_null_array(field.data_type(), num_rows);
            return Ok(Arc::new(null_array) as Arc<dyn Array>);
        }

        let file_schema = builder.schema().clone();
        let column_idx = file_schema
            .fields()
            .iter()
            .position(|f| f.name() == column_to_read)
            .ok_or_else(|| {
                ReadError::IngestionFailed(IngestionError::ParseFailed(
                    "Column not found".to_string(),
                ))
            })?;

        let mut projected_indices = vec![column_idx];
        for col in &hidden_cols {
            if let Some(idx) = file_schema.fields().iter().position(|f| f.name() == col)
                && !projected_indices.contains(&idx)
            {
                projected_indices.push(idx);
            }
        }

        let mask =
            parquet::arrow::ProjectionMask::leaves(builder.parquet_schema(), projected_indices);
        let valid_row_groups = crate::ingestion::s3_client::S3Client::get_pruned_row_groups(
            &metadata,
            column_to_read,
            &policy_predicates,
        );
        builder = builder
            .with_projection(mask)
            .with_row_groups(valid_row_groups);

        let mut stream = builder
            .build()
            .map_err(|e| ReadError::IngestionFailed(IngestionError::Parquet(e)))?;

        use futures::stream::StreamExt;
        let mut arrays = Vec::new();
        while let Some(batch_result) = stream.next().await {
            let record_batch =
                batch_result.map_err(|e| ReadError::IngestionFailed(IngestionError::Parquet(e)))?;

            let mut current_batch = record_batch;
            for pred in &policy_predicates {
                if let Some(col_array) = current_batch.column_by_name(pred.column()) {
                    let mask = crate::governance::simd_ops::GovernanceEngine::evaluate_filter(
                        col_array, pred,
                    )
                    .map_err(|e| {
                        ReadError::GovernanceFailed(
                            crate::manager::governance_manager::GovernanceError::AccessDenied(
                                e.to_string(),
                            ),
                        )
                    })?;
                    let filtered_arrays = current_batch
                        .columns()
                        .iter()
                        .map(|arr| arrow::compute::filter(arr.as_ref(), &mask))
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|e| {
                            ReadError::IngestionFailed(IngestionError::ParseFailed(e.to_string()))
                        })?;
                    current_batch = RecordBatch::try_new(current_batch.schema(), filtered_arrays)
                        .map_err(|e| {
                        ReadError::IngestionFailed(IngestionError::ParseFailed(e.to_string()))
                    })?;
                } else {
                    return Err(ReadError::GovernanceFailed(
                        crate::manager::governance_manager::GovernanceError::AccessDenied(format!(
                            "Access Denied: Row filter references missing column '{}'",
                            pred.column()
                        )),
                    ));
                }
            }

            if let Some(idx) = current_batch
                .schema()
                .fields()
                .iter()
                .position(|f| f.name() == column_to_read)
                && current_batch.num_rows() > 0
            {
                arrays.push(current_batch.column(idx).clone());
            }
        }

        if arrays.is_empty() {
            return Err(ReadError::IngestionFailed(IngestionError::ParseFailed(
                "No batches found".to_string(),
            )));
        }

        let mut refs = Vec::new();
        for arr in &arrays {
            refs.push(arr.as_ref());
        }

        let decrypted_array = arrow::compute::concat(&refs)
            .map_err(|e| ReadError::IngestionFailed(IngestionError::ParseFailed(e.to_string())))?;

        // Extract physical encryption status from parquet footer
        let is_physically_encrypted = metadata
            .row_groups()
            .first()
            .is_some_and(|rg| rg.column(column_idx).crypto_metadata().is_some());

        // Extract semantic tags
        let mut column_tags = Vec::new();
        if let Some(kv_meta) = metadata.file_metadata().key_value_metadata() {
            let tag_key = format!("holonomy.tags.{}", column_to_read);
            for kv in kv_meta {
                if kv.key == tag_key
                    && let Some(val) = &kv.value
                {
                    column_tags = val.split(',').map(|s| s.trim().to_string()).collect();
                }
            }
        }

        // LF-007: SIMD RLS & Masking
        let output_array = self.governance_manager.apply_rls(
            decrypted_array,
            user_ctx,
            &merged_policy,
            column_to_read,
            assumed_role,
            Some(valid_purpose),
            fail_closed_mode,
            is_physically_encrypted,
            &column_tags,
        )?;

        // LF-019: Async Fire Audit Event
        let event = AuditEvent {
            timestamp: Utc::now(),
            user_hash: user_hash.to_string(),
            file_signature: target.to_string(),
            accessed_columns: None,
            business_purpose: valid_purpose.to_string(),
            action: Action::Read,
        };

        self.audit_buffer.push(event);

        // LF-015: Export Arrow Pointers (Zero-Copy)
        Ok(output_array)
    }
}
