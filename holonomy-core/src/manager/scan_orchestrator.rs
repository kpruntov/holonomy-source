// @trace TASK-078
// @trace TASK-052
// @trace TASK-101
// @trace TASK-123
// @trace TASK-124
use crate::audit::ring_buffer::AuditRingBuffer;
use crate::ingestion::s3_client::IngestionProvider;
use crate::manager::crypto_manager::CryptoManager;
use crate::manager::governance_manager::GovernanceManager;
use crate::manager::policy_manager::PolicyManager;
use arrow::array::RecordBatchReader;
use arrow::datatypes::SchemaRef;
use arrow::error::ArrowError;
use arrow::record_batch::RecordBatch;
use std::sync::Arc;

pub struct ScanOrchestrator {
    _audit_buffer: Arc<AuditRingBuffer>,
    _s3_client: Arc<dyn IngestionProvider>,
    _crypto_manager: Arc<CryptoManager>,
    _policy_manager: Arc<PolicyManager>,
    _governance_manager: Arc<GovernanceManager>,
}

pub struct ScanIterator {
    receiver: tokio::sync::mpsc::Receiver<Result<RecordBatch, ArrowError>>,
    schema: SchemaRef,
}

impl Iterator for ScanIterator {
    type Item = Result<RecordBatch, ArrowError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.receiver.blocking_recv()
    }
}

impl RecordBatchReader for ScanIterator {
    fn schema(&self) -> SchemaRef {
        self.schema.clone()
    }
}

impl ScanOrchestrator {
    pub fn new(
        _audit_buffer: Arc<AuditRingBuffer>,
        _s3_client: Arc<dyn IngestionProvider>,
        _crypto_manager: Arc<CryptoManager>,
        _policy_manager: Arc<PolicyManager>,
        _governance_manager: Arc<GovernanceManager>,
    ) -> Self {
        Self {
            _audit_buffer,
            _s3_client,
            _crypto_manager,
            _policy_manager,
            _governance_manager,
        }
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::type_complexity)]
    pub async fn scan(
        &self,
        targets: Vec<String>,
        purpose: Option<&str>,
        user_ctx: &crate::auth::jwt_validator::UserContext,
        columns: Option<Vec<String>>,
        predicates: &[crate::ingestion::s3_client::Predicate],
        contract_json: Option<&str>,
        target_schema: Option<SchemaRef>,
        assumed_role: Option<&str>,
        fail_closed_mode: Option<crate::manager::governance_manager::FailClosedMode>,
    ) -> Result<Box<dyn RecordBatchReader + Send>, String> {
        let user_hash = user_ctx.identity();
        let valid_purpose = match purpose {
            Some(p) if !p.trim().is_empty() => p.trim(),
            _ => return Err("Missing purpose".to_string()),
        };

        let first_target = targets.first().ok_or("No targets provided")?;

        // Governance / Policy Checks
        let policies = self
            ._policy_manager
            .discover_policies(first_target)
            .map_err(|e| e.to_string())?;
        self._policy_manager
            .verify_signatures(&policies)
            .map_err(|e| e.to_string())?;
        let merged_policy = self
            ._policy_manager
            .merge_layers(&policies)
            .map_err(|e| e.to_string())?;

        // 0. Fetch and apply DEK sidecar cache warming (LF-057)
        let partition_root = if let Some(idx) = first_target.rfind('/') {
            &first_target[..idx]
        } else {
            first_target
        };
        let sidecar_target = format!("{}/_holonomy_keys.json", partition_root);
        if let Ok(bytes) = self._s3_client.fetch_entire_file(&sidecar_target).await
            && let Ok(keys) = serde_json::from_slice::<Vec<crate::manager::sidecar::SidecarKeyEntry>>(&bytes)
        {
            self._crypto_manager.warm_dek_cache(keys, Some(&user_hash), None).await;
        }

        // 1. Initialize Decryption Properties and Builder (Fetches and decrypts metadata automatically)
        let decryption_props = self
            ._crypto_manager
            .get_decryption_properties(None, Some(user_hash.to_string()))
            .map_err(|e| e.to_string())?;

        let async_reader = crate::ingestion::s3_client::S3AsyncFileReader::new(
            self._s3_client.clone(),
            first_target.to_string(),
            Some(decryption_props.clone()),
        );
        let options = parquet::arrow::arrow_reader::ArrowReaderOptions::new()
            .with_file_decryption_properties(decryption_props.clone());
        let builder =
            parquet::arrow::async_reader::ParquetRecordBatchStreamBuilder::new_with_options(
                async_reader,
                options,
            )
            .await
            .map_err(|e| e.to_string())?;

        let metadata = builder.metadata().clone();
        let file_metadata = metadata.file_metadata();
        let schema_desc = file_metadata.schema_descr();

        let all_columns: Vec<String> = schema_desc
            .columns()
            .iter()
            .map(|c| c.name().to_string())
            .collect();

        // Resolve target unified schema
        let unified_schema = if let Some(ts) = target_schema {
            Some(ts)
        } else if let Some(json) = contract_json {
            let validator =
                crate::linter::validator::Validator::from_json(json).map_err(|e| e.to_string())?;
            Some(Arc::new(
                validator.to_arrow_schema().map_err(|e| e.to_string())?,
            ))
        } else {
            None
        };

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
                    if !all_columns.contains(&col) {
                        return Err(format!(
                            "Access Denied: Global row filter references missing column '{}'",
                            col
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
                    if all_columns.contains(&col) {
                        policy_predicates.push(pred);
                        hidden_cols.push(col);
                    }
                }
            }
        }

        let mut combined_predicates = predicates.to_vec();
        combined_predicates.extend(policy_predicates.clone());

        let requested_cols = if let Some(cols) = columns {
            cols
        } else if let Some(us) = &unified_schema {
            us.fields().iter().map(|f| f.name().clone()).collect()
        } else {
            all_columns.clone()
        };

        let mut projected_cols = requested_cols.clone();
        for col in &hidden_cols {
            if !projected_cols.contains(col) {
                projected_cols.push(col.clone());
            }
        }

        let _num_rows = file_metadata.num_rows() as usize;

        // 3. Apply projection and pruned row groups
        let file_schema = builder.schema().clone();

        let schema = if let Some(us) = &unified_schema {
            let mut final_fields = Vec::new();
            for col_name in &requested_cols {
                if let Ok(field) = us.field_with_name(col_name) {
                    final_fields.push(field.clone());
                } else {
                    if let Some(idx) = file_schema
                        .fields()
                        .iter()
                        .position(|f| f.name() == col_name)
                    {
                        final_fields.push(file_schema.field(idx).clone());
                    } else {
                        final_fields.push(arrow::datatypes::Field::new(
                            col_name.clone(),
                            arrow::datatypes::DataType::Null,
                            true,
                        ));
                    }
                }
            }
            Arc::new(arrow::datatypes::Schema::new(final_fields))
        } else {
            let mut final_fields = Vec::new();
            for col_name in &requested_cols {
                if let Some(idx) = file_schema
                    .fields()
                    .iter()
                    .position(|f| f.name() == col_name)
                {
                    final_fields.push(file_schema.field(idx).clone());
                } else {
                    final_fields.push(arrow::datatypes::Field::new(
                        col_name.clone(),
                        arrow::datatypes::DataType::Null,
                        true,
                    ));
                }
            }
            Arc::new(arrow::datatypes::Schema::new(final_fields))
        };

        let (tx, rx) = tokio::sync::mpsc::channel::<Result<RecordBatch, ArrowError>>(10);

        let unified_schema_clone = unified_schema.clone();
        let projected_cols_clone = projected_cols.clone();
        let requested_cols_clone = requested_cols.clone();
        let policy_predicates_clone = policy_predicates.clone();
        let gov_clone = self._governance_manager.clone();
        let user_ctx_clone = user_ctx.clone();
        let merged_policy_clone = merged_policy.clone();
        let assumed_role_clone = assumed_role.map(|s| s.to_string());
        let purpose_clone = Some(valid_purpose.to_string());
        let task_schema = schema.clone();

        // Audit Event
        use crate::audit::ring_buffer::{Action, AuditEvent};
        use chrono::Utc;
        let event = AuditEvent {
            timestamp: Utc::now(),
            user_hash: user_hash.to_string(),
            file_signature: targets.join(","),
            accessed_columns: Some(projected_cols.clone()),
            business_purpose: valid_purpose.to_string(),
            action: Action::Read,
        };
        self._audit_buffer.push(event);

        let targets_clone = targets.clone();
        let s3_client_clone = self._s3_client.clone();
        let mut first_builder = Some(builder);
        
        tokio::spawn(async move {
            use futures::stream::StreamExt;
            
            // We create a stream of streams to fetch footers concurrently with processing
            let mut file_streams = futures::stream::iter(targets_clone)
                .map(move |target_file| {
                    let s3_client = s3_client_clone.clone();
                    let decryption_props = decryption_props.clone();
                    let combined_predicates = combined_predicates.clone();
                    let projected_cols = projected_cols.clone();
                    let builder_opt = first_builder.take();
                    
                    async move {
                        let mut builder = match builder_opt {
                            Some(b) => b,
                            None => {
                                let async_reader = crate::ingestion::s3_client::S3AsyncFileReader::new(
                                    s3_client,
                                    target_file.clone(),
                                    Some(decryption_props.clone()),
                                );
                                let options = parquet::arrow::arrow_reader::ArrowReaderOptions::new()
                                    .with_file_decryption_properties(decryption_props);
                                
                                match parquet::arrow::async_reader::ParquetRecordBatchStreamBuilder::new_with_options(
                                    async_reader,
                                    options,
                                ).await {
                                    Ok(b) => b,
                                    Err(e) => return Err(arrow::error::ArrowError::ExternalError(e.to_string().into())),
                                }
                            }
                        };
                        
                        let metadata = builder.metadata().clone();
                        let file_metadata = metadata.file_metadata();
                        let schema_desc = file_metadata.schema_descr();
                        let all_columns: Vec<String> = schema_desc
                            .columns()
                            .iter()
                            .map(|c| c.name().to_string())
                            .collect();
                            
                        let existing_cols: Vec<&str> = projected_cols
                            .iter()
                            .filter(|c| all_columns.contains(*c))
                            .map(|s| s.as_str())
                            .collect();
                        let valid_row_groups = crate::ingestion::s3_client::S3Client::get_pruned_row_groups(
                            &metadata,
                            existing_cols.first().unwrap_or(&""),
                            &combined_predicates,
                        );
                        
                        let file_schema = builder.schema().clone();
                        let mut projected_indices = Vec::new();
                        for col_name in &projected_cols {
                            if let Some(idx) = file_schema.fields().iter().position(|f| f.name() == col_name) {
                                projected_indices.push(idx);
                            }
                        }
                        
                        let mask = parquet::arrow::ProjectionMask::leaves(builder.parquet_schema(), projected_indices);
                        builder = builder.with_projection(mask).with_row_groups(valid_row_groups);
                        
                        let stream = match builder.build() {
                            Ok(s) => s,
                            Err(e) => return Err(arrow::error::ArrowError::ExternalError(e.to_string().into())),
                        };
                        
                        let mut physical_encryption_map = std::collections::HashMap::new();
                        let mut column_tags_map = std::collections::HashMap::new();
                        for col_name in &projected_cols {
                            let mut is_encrypted = false;
                            if let Some(idx) = file_schema.fields().iter().position(|f| f.name() == col_name) {
                                is_encrypted = metadata.row_groups().first().is_some_and(|rg| rg.column(idx).crypto_metadata().is_some());
                            }
                            physical_encryption_map.insert(col_name.clone(), is_encrypted);

                            let mut tags = Vec::new();
                            if let Some(kv_meta) = metadata.file_metadata().key_value_metadata() {
                                let tag_key = format!("holonomy.tags.{}", col_name);
                                for kv in kv_meta {
                                    if kv.key == tag_key && let Some(val) = &kv.value {
                                        tags = val.split(',').map(|s| s.trim().to_string()).collect();
                                    }
                                }
                            }
                            column_tags_map.insert(col_name.clone(), tags);
                        }
                        
                        Ok((stream, physical_encryption_map, column_tags_map))
                    }
                })
                .buffered(2);

            let (stream_tx, mut stream_rx) = tokio::sync::mpsc::channel(2);
            
            tokio::spawn(async move {
                while let Some(res) = futures::StreamExt::next(&mut file_streams).await {
                    if stream_tx.send(res).await.is_err() {
                        break;
                    }
                }
            });

            while let Some(result) = stream_rx.recv().await {
                match result {
                    Ok((mut stream, physical_encryption_map, column_tags_map)) => {
                        while let Some(result) = stream.next().await {
                            match result {
                                Ok(batch) => {
                                    let mut current_batch = batch;

                                    // Apply RLS row filters
                                    let mut filter_failed = false;
                                    for pred in &policy_predicates_clone {
                                        if let Some(col_array) = current_batch.column_by_name(pred.column()) {
                                            match crate::governance::simd_ops::GovernanceEngine::evaluate_filter(
                                                col_array, pred,
                                            ) {
                                                Ok(mask) => {
                                                    match current_batch
                                                        .columns()
                                                        .iter()
                                                        .map(|arr| arrow::compute::filter(arr.as_ref(), &mask))
                                                        .collect::<Result<Vec<_>, _>>()
                                                    {
                                                        Ok(filtered_arrays) => {
                                                            match RecordBatch::try_new(
                                                                current_batch.schema(),
                                                                filtered_arrays,
                                                            ) {
                                                                Ok(new_batch) => current_batch = new_batch,
                                                                Err(e) => {
                                                                    let _ = tx.send(Err(arrow::error::ArrowError::ComputeError(e.to_string()))).await;
                                                                    filter_failed = true;
                                                                    break;
                                                                }
                                                            }
                                                        }
                                                        Err(e) => {
                                                            let _ = tx
                                                                .send(Err(
                                                                    arrow::error::ArrowError::ComputeError(
                                                                        e.to_string(),
                                                                    ),
                                                                ))
                                                                .await;
                                                            filter_failed = true;
                                                            break;
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    let _ = tx
                                                        .send(Err(arrow::error::ArrowError::ComputeError(
                                                            e.to_string(),
                                                        )))
                                                        .await;
                                                    filter_failed = true;
                                                    break;
                                                }
                                            }
                                        } else {
                                            let _ = tx.send(Err(arrow::error::ArrowError::InvalidArgumentError(format!("Access Denied: Row filter references missing column '{}'", pred.column())))).await;
                                            filter_failed = true;
                                            break;
                                        }
                                    }

                                    if filter_failed {
                                        break;
                                    }

                                    // Drop hidden projections
                                    if projected_cols_clone != requested_cols_clone {
                                        let mut final_arrays = Vec::new();
                                        let mut final_fields = Vec::new();
                                        for (i, field) in current_batch.schema().fields().iter().enumerate() {
                                            if requested_cols_clone.contains(field.name()) {
                                                final_arrays.push(current_batch.column(i).clone());
                                                final_fields.push(field.clone());
                                            }
                                        }
                                        match RecordBatch::try_new(
                                            Arc::new(arrow::datatypes::Schema::new(final_fields)),
                                            final_arrays,
                                        ) {
                                            Ok(new_batch) => current_batch = new_batch,
                                            Err(e) => {
                                                let _ = tx
                                                    .send(Err(arrow::error::ArrowError::ComputeError(
                                                        e.to_string(),
                                                    )))
                                                    .await;
                                                break;
                                            }
                                        }
                                    }

                                    let batch = current_batch;

                                    let mut final_arrays: Vec<Arc<dyn arrow::array::Array>> = Vec::new();
                                    let mut final_fields = Vec::new();
                                    let batch_len = batch.num_rows();

                                    let mut error = None;
                                    for col_name in &requested_cols_clone {
                                        if let Some(idx) = batch
                                            .schema()
                                            .fields()
                                            .iter()
                                            .position(|f| f.name() == col_name)
                                        {
                                            let array = batch.column(idx).clone();
                                            let is_physically_encrypted = physical_encryption_map
                                                .get(col_name)
                                                .copied()
                                                .unwrap_or(false);
                                            let empty_tags = Vec::new();
                                            let tags = column_tags_map.get(col_name).unwrap_or(&empty_tags);
                                            match gov_clone.apply_rls(
                                                array,
                                                &user_ctx_clone,
                                                &merged_policy_clone,
                                                col_name,
                                                assumed_role_clone.as_deref(),
                                                purpose_clone.as_deref(),
                                                fail_closed_mode,
                                                is_physically_encrypted,
                                                tags,
                                            ) {
                                                Ok(rls_array) => {
                                                    final_arrays.push(rls_array);
                                                    final_fields.push(batch.schema().field(idx).clone());
                                                }
                                                Err(e) => {
                                                    error = Some(e.to_string());
                                                    break;
                                                }
                                            }
                                        } else {
                                            // Schema Evolution: Pad missing column with Nulls
                                            let dt = if let Some(us) = &unified_schema_clone {
                                                if let Ok(field) = us.field_with_name(col_name) {
                                                    field.data_type().clone()
                                                } else {
                                                    arrow::datatypes::DataType::Null
                                                }
                                            } else {
                                                arrow::datatypes::DataType::Null
                                            };
                                            let null_array = arrow::array::new_null_array(&dt, batch_len);
                                            final_arrays.push(Arc::new(null_array));
                                            final_fields.push(arrow::datatypes::Field::new(
                                                col_name.clone(),
                                                dt,
                                                true,
                                            ));
                                        }
                                    }

                                    if let Some(e) = error {
                                        let _ = tx.send(Err(arrow::error::ArrowError::ExternalError(e.into()))).await;
                                        break;
                                    }

                                    let schema_to_use = task_schema.clone();
                                    match RecordBatch::try_new(schema_to_use, final_arrays) {
                                        Ok(batch) => {
                                            if tx.send(Ok(batch)).await.is_err() {
                                                break;
                                            }
                                        }
                                        Err(e) => {
                                            let _ = tx.send(Err(e)).await;
                                            break;
                                        }
                                    }
                                }
                                Err(e) => {
                                    let _ = tx.send(Err(e.into())).await;
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(e)).await;
                        break;
                    }
                }
            }
        });

        Ok(Box::new(ScanIterator {
            receiver: rx,
            schema,
        }))
    }
}
