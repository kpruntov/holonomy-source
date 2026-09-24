// @trace TASK-122
mod common;

use arrow::array::{Int32Array, StringArray};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use holonomy_core::audit::ring_buffer::AuditRingBuffer;
use holonomy_core::crypto::dek_cache::DekCache;
use holonomy_core::crypto::pme_encrypt::{StorageUploader, StreamItem};
use holonomy_core::manager::crypto_manager::CryptoManager;
use holonomy_core::manager::governance_manager::GovernanceManager;
use holonomy_core::manager::write_orchestrator::WriteOrchestrator;
use std::sync::Arc;
use tokio::sync::Mutex;

struct TrackingMockUploader {
    pub uploaded_keys: Arc<Mutex<Vec<String>>>,
}

#[async_trait::async_trait]
impl StorageUploader for TrackingMockUploader {
    async fn upload_stream(
        &self,
        key: &str,
        mut rx: tokio::sync::mpsc::Receiver<StreamItem>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.uploaded_keys.lock().await.push(key.to_string());
        let mut success = false;
        while let Some(item) = rx.recv().await {
            match item {
                StreamItem::Data(_) => {}
                StreamItem::Success => {
                    success = true;
                    break;
                }
            }
        }
        if success {
            Ok(())
        } else {
            Err("Upload aborted".into())
        }
    }
}

#[tokio::test]
async fn test_sidecar_generation_and_flush() {
    let schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int32, false),
        Field::new("name", DataType::Utf8, false),
    ]));
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(Int32Array::from(vec![1, 2])),
            Arc::new(StringArray::from(vec!["Alice", "Bob"])),
        ],
    )
    .unwrap();

    let contract_json = r#"{
        "name": "test_contract",
        "version": "1.0",
        "columns": [
            { "name": "id", "type": "int32", "required": true },
            { "name": "name", "type": "string", "required": true }
        ]
    }"#;
    let uploaded_keys = Arc::new(Mutex::new(Vec::new()));
    let uploader = Arc::new(TrackingMockUploader {
        uploaded_keys: uploaded_keys.clone(),
    });

    let dek_cache = DekCache::new(std::time::Duration::from_secs(10));
    // Pre-seed the cache to mock the KMS response
    let dek_id = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"s3://bucket/path/to/partition");
        hex::encode(hasher.finalize())
    };
    dek_cache.insert(dek_id, b"1234567890123456".to_vec());
    
    let crypto_manager = Arc::new(CryptoManager::new(
        Arc::new(dek_cache),
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

    let partition_root = "s3://bucket/path/to/partition";
    
    // Write two files to the same partition
    let result1 = orchestrator
        .write(
            &batch,
            &format!("{}/file1.parquet", partition_root),
            Some("Testing sidecar"),
            "mock_user_hash",
            Some(contract_json),
        )
        .await;
    assert!(result1.is_ok());

    let result2 = orchestrator
        .write(
            &batch,
            &format!("{}/file2.parquet", partition_root),
            Some("Testing sidecar"),
            "mock_user_hash",
            Some(contract_json),
        )
        .await;
    assert!(result2.is_ok());

    // Verify accumulation
    {
        let sidecar = orchestrator.sidecar_deks.get(partition_root).unwrap();
        // 2 files * (footer + any encrypted columns). Assuming 0 columns encrypted by default policy -> 1 key per file.
        // Wait, default policy doesn't encrypt columns, only footer.
        assert_eq!(sidecar.keys.len(), 1, "Should deduplicate identical keys for multiple files in same partition");
    }

    // Flush partition
    let flush_result = orchestrator.flush_partition(partition_root).await;
    assert!(flush_result.is_ok());

    // Verify sidecar was uploaded
    let keys = uploaded_keys.lock().await;
    assert!(keys.contains(&"s3://bucket/path/to/partition/_holonomy_keys.json".to_string()));
}
