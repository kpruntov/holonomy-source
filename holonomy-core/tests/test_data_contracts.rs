// @trace TASK-057, TASK-066
mod common;
use arrow::array::{Int64Array, StringArray};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use holonomy_core::audit::ring_buffer::AuditRingBuffer;
use holonomy_core::crypto::pme_encrypt::{StorageUploader, StreamItem};
use holonomy_core::manager::crypto_manager::CryptoManager;
use holonomy_core::manager::governance_manager::GovernanceManager;
use holonomy_core::manager::write_orchestrator::{WriteError, WriteOrchestrator};
use std::sync::Arc;

struct MockUploader;

#[async_trait::async_trait]
impl StorageUploader for MockUploader {
    async fn upload_stream(
        &self,
        _target: &str,
        mut _rx: tokio::sync::mpsc::Receiver<StreamItem>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
}

fn create_valid_batch() -> RecordBatch {
    let schema = Arc::new(Schema::new(vec![
        Field::new("user_id", DataType::Int64, false),
        Field::new("email", DataType::Utf8, false),
    ]));

    let user_id = Int64Array::from(vec![1, 2]);
    let email = StringArray::from(vec!["alice@example.com", "bob@example.com"]);

    RecordBatch::try_new(schema, vec![Arc::new(user_id), Arc::new(email)]).unwrap()
}

fn create_invalid_batch() -> RecordBatch {
    // Missing 'user_id' column
    let schema = Arc::new(Schema::new(vec![Field::new(
        "email",
        DataType::Utf8,
        false,
    )]));

    let email = StringArray::from(vec!["alice@example.com", "bob@example.com"]);

    RecordBatch::try_new(schema, vec![Arc::new(email)]).unwrap()
}

#[tokio::test]
async fn test_contract_resolution_hierarchy() {
    let audit_buffer = Arc::new(AuditRingBuffer::new(100));
    let crypto_manager = Arc::new(CryptoManager::new(
        Arc::new(holonomy_core::crypto::dek_cache::DekCache::new(
            std::time::Duration::from_secs(10),
        )),
        Arc::new(common::MockKmsProvider),
    ));
    let uploader = Arc::new(MockUploader);
    let governance_manager = Arc::new(GovernanceManager::new(std::sync::Arc::new(
        common::MockSchemaRegistryProvider,
    )));

    let orchestrator = WriteOrchestrator::new(
        audit_buffer,
        crypto_manager,
        uploader,
        governance_manager,
        std::sync::Arc::new(
            holonomy_core::manager::policy_manager::PolicyManager::new_dangerously_allow_unsigned(
                std::sync::Arc::new(common::MockPolicyProvider),
            ),
        ),
    );

    let batch = create_valid_batch();

    // 1. No contract available anywhere
    let result = orchestrator
        .write(
            &batch,
            "s3://bucket/data",
            Some("analytics"),
            "user_hash",
            None,
        )
        .await;

    assert!(
        matches!(result, Err(WriteError::MissingContract)),
        "Expected MissingContract, got {:?}",
        result
    );

    // 2. Explicit argument contract
    let valid_contract = r#"{
        "name": "TestContract",
        "version": "1.0",
        "columns": [
            {"name": "user_id", "type": "int64", "required": true},
            {"name": "email", "type": "string", "required": true}
        ]
    }"#;

    let result = orchestrator
        .write(
            &batch,
            "s3://bucket/data",
            Some("analytics"),
            "user_hash",
            Some(valid_contract),
        )
        .await;

    // We expect an encryption error or success, because it passes validation
    assert!(!matches!(result, Err(WriteError::MissingContract)));
    assert!(!matches!(result, Err(WriteError::LintFailed(_))));

    // 3. Local file contract
    // We simulate creating a local file
    std::fs::write(".holonomy_contract.json", valid_contract).unwrap();
    let result = orchestrator
        .write(
            &batch,
            "s3://bucket/data",
            Some("analytics"),
            "user_hash",
            None,
        )
        .await;

    assert!(!matches!(result, Err(WriteError::MissingContract)));
    assert!(!matches!(result, Err(WriteError::LintFailed(_))));

    // Clean up
    std::fs::remove_file(".holonomy_contract.json").unwrap();

    // 4. Invalid batch against valid contract
    let invalid_batch = create_invalid_batch();
    let result = orchestrator
        .write(
            &invalid_batch,
            "s3://bucket/data",
            Some("analytics"),
            "user_hash",
            Some(valid_contract),
        )
        .await;

    assert!(matches!(result, Err(WriteError::LintFailed(_))));
}
