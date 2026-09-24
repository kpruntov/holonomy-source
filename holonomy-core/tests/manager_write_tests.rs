// @trace TASK-017, TASK-066
// @trace TASK-042
mod common;

use arrow::array::{Int32Array, StringArray};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use holonomy_core::audit::ring_buffer::{Action, AuditRingBuffer};
use holonomy_core::crypto::dek_cache::DekCache;
use holonomy_core::crypto::pme_encrypt::{StorageUploader, StreamItem};
use holonomy_core::manager::crypto_manager::CryptoManager;
use holonomy_core::manager::governance_manager::GovernanceManager;
use holonomy_core::manager::write_orchestrator::{WriteError, WriteOrchestrator};
use std::sync::Arc;

struct MockStorageUploader;

#[async_trait::async_trait]
impl StorageUploader for MockStorageUploader {
    async fn upload_stream(
        &self,
        _key: &str,
        mut rx: tokio::sync::mpsc::Receiver<StreamItem>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
async fn test_write_orchestrator_success() {
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
    let uploader = Arc::new(MockStorageUploader);

    let dek_cache = DekCache::new(std::time::Duration::from_secs(10));
    // Pre-seed the cache to mock the KMS response
    let dek_id = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"test.parquet");
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

    let result = orchestrator
        .write(
            &batch,
            "test.parquet",
            Some("Testing write flow"),
            "mock_user_hash",
            Some(contract_json),
        )
        .await;

    assert!(result.is_ok());

    let audit_event = audit_buffer.pop().expect("Should receive audit event");
    assert_eq!(audit_event.action, Action::Write);
    assert_eq!(audit_event.business_purpose, "Testing write flow");
}

#[tokio::test]
async fn test_write_orchestrator_lint_failure() {
    let schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int32, false),
        Field::new("name", DataType::Utf8, false),
    ]));
    // Invalid data according to a strict contract
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(Int32Array::from(vec![1, 2])),
            Arc::new(StringArray::from(vec!["Alice", "Bob"])),
        ],
    )
    .unwrap();

    // Contract expects a third column "extra" which is required
    let contract_json = r#"{
        "name": "test_contract",
        "version": "1.0",
        "columns": [
            { "name": "id", "type": "int32", "required": true },
            { "name": "name", "type": "string", "required": true },
            { "name": "extra", "type": "string", "required": true }
        ]
    }"#;

    let uploader = Arc::new(MockStorageUploader);
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

    let result = orchestrator
        .write(
            &batch,
            "test.parquet",
            Some("Testing lint failure"),
            "mock_user_hash",
            Some(contract_json),
        )
        .await;

    match result {
        Err(WriteError::LintFailed(errs)) => {
            assert!(!errs.is_empty(), "Expected lint errors");
        }
        _ => panic!("Expected LintFailed error"),
    }
}

#[tokio::test]
async fn test_write_orchestrator_missing_purpose() {
    let schema = Arc::new(Schema::new(vec![Field::new("id", DataType::Int32, false)]));
    let batch =
        RecordBatch::try_new(schema.clone(), vec![Arc::new(Int32Array::from(vec![1]))]).unwrap();

    let contract_json = r#"{
        "name": "test_contract",
        "version": "1.0",
        "columns": [
            { "name": "id", "type": "int32", "required": true }
        ]
    }"#;
    let uploader = Arc::new(MockStorageUploader);
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

    // Test with None
    let result1 = orchestrator
        .write(
            &batch,
            "test.parquet",
            None,
            "mock_user_hash",
            Some(contract_json),
        )
        .await;
    assert!(matches!(result1, Err(WriteError::MissingPurpose)));

    // Test with empty string
    let result2 = orchestrator
        .write(
            &batch,
            "test.parquet",
            Some("   "),
            "mock_user_hash",
            Some(contract_json),
        )
        .await;
    assert!(matches!(result2, Err(WriteError::MissingPurpose)));
}
