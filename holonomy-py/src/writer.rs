// @trace TASK-119
use arrow::pyarrow::PyArrowType;
use arrow::record_batch::RecordBatch;
use holonomy_core::crypto::pme_encrypt::{PmeEncryptor, S3MultipartUploader, StorageUploader, StreamItem};
use holonomy_core::linter::validator::Validator;
use holonomy_core::manager::channel_writer::ChannelWriter;
use pyo3::prelude::*;
use std::sync::Arc;
use tokio::sync::oneshot;

use crate::{get_engine_state, get_runtime};

struct WriterState {
    channel_writer: ChannelWriter,
    result_rx: oneshot::Receiver<Result<Vec<u8>, parquet::errors::ParquetError>>,
    target_key: String,
    uploader: Arc<dyn StorageUploader>,
    user_hash: String,
    purpose: String,
}

#[pyclass]
pub struct Writer {
    target: String,
    user_context: String,
    purpose: Option<String>,
    contract_json: Option<String>,
    state: Option<WriterState>,
}

#[pymethods]
impl Writer {
    #[new]
    #[pyo3(signature = (target, user_context=None, purpose=None, contract_json=None))]
    fn new(
        target: String,
        user_context: Option<String>,
        purpose: Option<String>,
        contract_json: Option<String>,
    ) -> PyResult<Self> {
        let user_ctx = user_context.ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err("MissingIdentityError: user_context is required")
        })?;

        Ok(Self {
            target,
            user_context: user_ctx,
            purpose,
            contract_json,
            state: None,
        })
    }

    fn __enter__(slf: Py<Self>, _py: Python<'_>) -> PyResult<Py<Self>> {
        Ok(slf)
    }

    fn write_batch(&mut self, py: Python<'_>, batch: PyArrowType<RecordBatch>) -> PyResult<()> {
        let batch = batch.0;

        if self.state.is_none() {
            let engine_state = get_engine_state()
                .map_err(pyo3::exceptions::PyRuntimeError::new_err)?;
            let rt = get_runtime();
            let state_result = rt.block_on(async {

                let valid_purpose = self.purpose.as_deref().ok_or_else(|| {
                    pyo3::exceptions::PyValueError::new_err("MissingPurpose")
                })?;


                let config = holonomy_core::config::resolver::get_config();
                let storage_endpoint = if config.storage.endpoint.is_empty() { None } else { Some(config.storage.endpoint.clone()) };
                let storage_region = if config.storage.region.is_empty() { None } else { Some(config.storage.region.clone()) };
                let (bucket, key, endpoint) = crate::parse_target(&self.target, storage_endpoint);
                
                let uploader: Arc<dyn holonomy_core::crypto::pme_encrypt::StorageUploader> = if self.target.starts_with("file://") {
                    Arc::new(MockStorageUploader {
                        target_path: self.target.replace("file://", ""),
                    })
                } else {
                    Arc::new(S3MultipartUploader::new(bucket, endpoint, storage_region, None, None).await)
                };

                let contract_str = if let Some(canonical) = engine_state
                    .governance_manager
                    .resolve_contract(&self.target)
                {
                    canonical
                } else if let Ok(local_file) = std::fs::read_to_string(".holonomy_contract.json") {
                    local_file
                } else if let Some(explicit) = &self.contract_json {
                    explicit.clone()
                } else {
                    return Err(pyo3::exceptions::PyValueError::new_err("MissingContract"));
                };

                let validator = Validator::from_json(&contract_str).map_err(|e| {
                    pyo3::exceptions::PyValueError::new_err(format!("InvalidContract: {}", e))
                })?;

                let lint_errors = validator.validate(&batch);
                if !lint_errors.is_empty() {
                    return Err(pyo3::exceptions::PyValueError::new_err(format!(
                        "LintFailed: {:?}",
                        lint_errors
                    )));
                }

                let discovered_policies = engine_state
                    .policy_manager
                    .discover_policies(&self.target)
                    .map_err(|e| {
                        pyo3::exceptions::PyRuntimeError::new_err(format!(
                            "Policy discovery failed: {}",
                            e
                        ))
                    })?;
                let merged_policy = engine_state
                    .policy_manager
                    .merge_layers(&discovered_policies)
                    .map_err(|e| {
                        pyo3::exceptions::PyRuntimeError::new_err(format!(
                            "Policy merge failed: {}",
                            e
                        ))
                    })?;

                let columns_to_encrypt = engine_state
                    .policy_manager
                    .resolve_columns_to_encrypt(&validator.contract, &merged_policy);

                let footer_dek = PmeEncryptor::generate_or_get_dek(
                    &engine_state.crypto_manager,
                    &self.target,
                    valid_purpose,
                    "__footer__",
                    &self.user_context,
                )
                .await
                .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;

                let mut column_deks = std::collections::HashMap::new();
                let mut wrapped_column_deks = std::collections::HashMap::new();
                for col in columns_to_encrypt {
                    let col_dek = PmeEncryptor::generate_or_get_dek(
                        &engine_state.crypto_manager,
                        &self.target,
                        valid_purpose,
                        &col,
                        &self.user_context,
                    )
                    .await
                    .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
                    column_deks.insert(col.clone(), col_dek.plaintext);
                    wrapped_column_deks.insert(col, col_dek.wrapped);
                }

                let encryptor = PmeEncryptor::new(
                    footer_dek.plaintext,
                    footer_dek.wrapped,
                    column_deks,
                    wrapped_column_deks,
                );
                let mut props_builder = encryptor.get_writer_properties_builder();

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

                let (channel_writer, result_rx) =
                    ChannelWriter::spawn(batch.schema(), Some(props));

                Ok::<WriterState, PyErr>(WriterState {
                    channel_writer,
                    result_rx,
                    target_key: key,
                    uploader,
                    user_hash: self.user_context.clone(),
                    purpose: valid_purpose.to_string(),
                })
            });

            self.state = Some(state_result?);
        }

        let state = self.state.as_mut().unwrap();
        let channel_writer = &mut state.channel_writer;

        let res = py.detach(move || {
            let rt = get_runtime();
            rt.block_on(async {
                channel_writer
                    .send(batch)
                    .await
                    .map_err(|e| e.to_string())
            })
        });

        res.map_err(pyo3::exceptions::PyRuntimeError::new_err)?;

        Ok(())
    }

    fn __exit__(
        &mut self,
        py: Python<'_>,
        exc_type: Option<&Bound<'_, PyAny>>,
        _exc_value: Option<&Bound<'_, PyAny>>,
        _traceback: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        if exc_type.is_some() {
            // Drop state to prevent finalizing corrupt dataset and don't audit
            self.state = None;
            return Ok(());
        }

        if let Some(state) = self.state.take() {
            let engine_state = get_engine_state().map_err(pyo3::exceptions::PyRuntimeError::new_err)?;
            py.detach(move || {
                let rt = get_runtime();
                rt.block_on(async move {
                    state.channel_writer.close().await.map_err(|_| {
                        pyo3::exceptions::PyRuntimeError::new_err("Failed to close channel writer")
                    })?;

                    let buffer = state.result_rx.await.map_err(|_| {
                        pyo3::exceptions::PyRuntimeError::new_err("Failed to receive serialized data")
                    })?.map_err(|e| {
                        pyo3::exceptions::PyRuntimeError::new_err(format!("Serialization failed: {}", e))
                    })?;

                    let (tx, rx) = tokio::sync::mpsc::channel(2);
                    let _ = tx.send(StreamItem::Data(buffer)).await;
                    let _ = tx.send(StreamItem::Success).await;

                    state
                        .uploader
                        .upload_stream(&state.target_key, rx)
                        .await
                        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("Upload failed: {:?}", e)))?;

                    use holonomy_core::audit::ring_buffer::{Action, AuditEvent};
                    let event = AuditEvent {
                        timestamp: chrono::Utc::now(),
                        user_hash: state.user_hash.clone(),
                        file_signature: state.target_key.clone(),
                        accessed_columns: None,
                        business_purpose: state.purpose.clone(),
                        action: Action::Write,
                    };
                    engine_state.audit_buffer.push(event);

                    Ok::<(), PyErr>(())
                })
            })?;
        }
        Ok(())
    }
}

pub(crate) struct MockStorageUploader {
    pub(crate) target_path: String,
}

#[async_trait::async_trait]
impl StorageUploader for MockStorageUploader {
    async fn upload_stream(
        &self,
        _key: &str,
        mut rx: tokio::sync::mpsc::Receiver<StreamItem>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use tokio::io::AsyncWriteExt;
        let mut file = tokio::fs::File::create(&self.target_path).await?;
        
        while let Some(item) = rx.recv().await {
            match item {
                StreamItem::Data(chunk) => {
                    file.write_all(&chunk).await?;
                }
                StreamItem::Success => {
                    break;
                }
            }
        }
        Ok(())
    }
}
