// @trace TASK-115
mod common;

use arrow::array::{Int32Array, StringArray};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use bytes::Bytes;
use holonomy_core::audit::ring_buffer::AuditRingBuffer;
use holonomy_core::crypto::dek_cache::DekCache;
use holonomy_core::crypto::pme_encrypt::{StorageUploader, StreamItem};
use holonomy_core::manager::crypto_manager::CryptoManager;
use holonomy_core::manager::governance_manager::GovernanceManager;
use holonomy_core::manager::write_orchestrator::WriteOrchestrator;
use parquet::file::reader::{FileReader, SerializedFileReader};
use std::sync::Arc;
use tokio::sync::Mutex;

struct CapturingUploader {
    data: Arc<Mutex<Vec<u8>>>,
}

#[async_trait::async_trait]
impl StorageUploader for CapturingUploader {
    async fn upload_stream(
        &self,
        _key: &str,
        mut rx: tokio::sync::mpsc::Receiver<StreamItem>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        while let Some(item) = rx.recv().await {
            match item {
                StreamItem::Data(d) => {
                    let mut buf = self.data.lock().await;
                    buf.extend_from_slice(&d);
                }
                StreamItem::Success => break,
            }
        }
        Ok(())
    }
}

#[tokio::test]
async fn test_tags_are_embedded_in_parquet() {
    let schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int32, false),
        Field::new("name", DataType::Utf8, false),
    ]));
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(Int32Array::from(vec![1])),
            Arc::new(StringArray::from(vec!["Alice"])),
        ],
    )
    .unwrap();

    let contract_json = r#"{
        "name": "test_contract",
        "version": "1.0",
        "columns": [
            { "name": "id", "type": "int32", "required": true },
            { "name": "name", "type": "string", "required": true, "tags": ["pii", "phi"] }
        ]
    }"#;

    let data = Arc::new(Mutex::new(Vec::new()));
    let uploader = Arc::new(CapturingUploader { data: data.clone() });
    let crypto_manager = Arc::new(CryptoManager::new(
        Arc::new(DekCache::new(std::time::Duration::from_secs(10))),
        Arc::new(common::MockKmsProvider),
    ));
    let audit_buffer = Arc::new(AuditRingBuffer::new(10));

    let governance_manager = Arc::new(GovernanceManager::new(std::sync::Arc::new(
        common::MockSchemaRegistryProvider,
    )));
    let orchestrator = WriteOrchestrator::new(
        audit_buffer.clone(),
        crypto_manager,
        uploader,
        governance_manager,
        std::sync::Arc::new(
            holonomy_core::manager::policy_manager::PolicyManager::new_dangerously_allow_unsigned(
                std::sync::Arc::new(common::MockPolicyProvider),
            ),
        ),
    );

    orchestrator
        .write(
            &batch,
            "test_tags.parquet",
            Some("Testing write flow"),
            "mock_user_hash",
            Some(contract_json),
        )
        .await
        .unwrap();

    let bytes = data.lock().await.clone();
    let reader = SerializedFileReader::new(Bytes::from(bytes)).unwrap();
    let metadata = reader.metadata().file_metadata();

    let kv_option = metadata.key_value_metadata();
    let kv_meta = kv_option.as_ref().expect("Should have key value metadata");
    let mut found = false;
    for kv in kv_meta.iter() {
        if kv.key == "holonomy.tags.name" {
            assert_eq!(kv.value.as_ref().unwrap(), "pii,phi");
            found = true;
        }
    }
    assert!(found, "The tag metadata was not found");
}
