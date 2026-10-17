// @trace TASK-022, TASK-066
mod common;
use mockito::Server;
use std::io::Write;
use std::process::Command;
use std::sync::Arc;
use tempfile::NamedTempFile;
use tokio::time::Duration;

use holonomy_core::audit::broadcaster::{AuditBroadcaster, SinkConfig};
use holonomy_core::audit::ring_buffer::{Action, AuditRingBuffer};
use holonomy_core::crypto::dek_cache::DekCache;
use holonomy_core::crypto::kms_admin::KmsAdmin;
use holonomy_core::crypto::pme_encrypt::S3MultipartUploader;
use holonomy_core::manager::crypto_manager::CryptoManager;
use holonomy_core::manager::write_orchestrator::WriteOrchestrator;

use arrow::array::Int32Array;
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use sha2::{Digest, Sha256};

#[tokio::test]
async fn verify_integration_gate_022_admin_telemetry() {
    // 1. Sign a policy manifest using the CLI
    let secret = [1u8; 32];
    let priv_hex = hex::encode(secret);

    let mut manifest_file = NamedTempFile::new().expect("Failed to create temp file");
    write!(manifest_file, r#"{{"policy": "allow"}}"#).unwrap();
    let manifest_path = manifest_file.path().to_str().unwrap();

    let target_dir = std::env::var("CARGO_TARGET_DIR")
        .unwrap_or_else(|_| format!("{}/../target", env!("CARGO_MANIFEST_DIR")));
    let cli_path = format!("{}/debug/holonomy-cli", target_dir);
    let sign_output = Command::new(&cli_path)
        .args(["sign", manifest_path, "--key", &priv_hex])
        .output()
        .expect("Failed to run sign CLI");

    assert!(
        sign_output.status.success(),
        "Sign failed: {:?}",
        String::from_utf8_lossy(&sign_output.stderr)
    );
    let stdout_str = String::from_utf8_lossy(&sign_output.stdout);
    let signature = stdout_str
        .lines()
        .find(|l| l.starts_with("Signature: "))
        .map(|l| l.replace("Signature: ", "").trim().to_string())
        .expect("Could not find signature in output");
    assert!(!signature.is_empty(), "Signature should not be empty");

    // 2. Perform read/write data to verify audit events arrive at webhook sink
    let mut server = Server::new_async().await;

    // Webhook receiver for audit broadcast
    let mock_webhook = server
        .mock("POST", "/")
        .match_header("authorization", "Bearer mock_admin_token")
        .with_status(200)
        .expect(1)
        .create_async()
        .await;

    // S3 endpoints for write flow
    let mock_create = server.mock("POST", mockito::Matcher::Regex(r".*\?uploads$".to_string()))
        .with_status(200)
        .with_body(r#"<?xml version="1.0" encoding="UTF-8"?><InitiateMultipartUploadResult><UploadId>mock-id</UploadId></InitiateMultipartUploadResult>"#)
        .create_async().await;
    let mock_upload_part = server
        .mock(
            "PUT",
            mockito::Matcher::Regex(r".*partNumber=.*".to_string()),
        )
        .with_status(200)
        .with_header("ETag", "\"mock_etag\"")
        .create_async()
        .await;
    let mock_complete = server.mock("POST", mockito::Matcher::Regex(r".*uploadId=mock-id$".to_string()))
        .with_status(200)
        .with_body(r#"<?xml version="1.0" encoding="UTF-8"?><CompleteMultipartUploadResult></CompleteMultipartUploadResult>"#)
        .create_async().await;

    let audit_buffer = Arc::new(AuditRingBuffer::new(10));

    // Start broadcaster pointing to the mock server root "/"
    let broadcaster = AuditBroadcaster::new(
        audit_buffer.clone(),
        SinkConfig::SaaS(server.url(), Some("mock_admin_token".to_string())),
        100,                       // batch_size
        Duration::from_millis(50), // flush_interval
        3,                         // max_retries
    );
    let broadcaster_handle = broadcaster.start();

    // Setup WriteOrchestrator
    // Setup WriteOrchestrator
    let uploader = Arc::new(
        S3MultipartUploader::new(
            "test-bucket".to_string(),
            Some(server.url()),
            Some("us-east-1".to_string()),
            None,
            Some(("mock".to_string(), "mock".to_string())),
        )
        .await,
    );

    let partition_id = "integration_test.parquet";
    let dek_cache = Arc::new(DekCache::new(Duration::from_secs(10)));

    let dek_id = {
        let mut hasher = Sha256::new();
        hasher.update(partition_id.as_bytes());
        hex::encode(hasher.finalize())
    };
    dek_cache.insert(dek_id.clone(), b"1234567890123456".to_vec());

    let crypto_manager = Arc::new(CryptoManager::new(
        dek_cache.clone(),
        Arc::new(common::MockKmsProvider),
    ));
    let governance_manager = Arc::new(
        holonomy_core::manager::governance_manager::GovernanceManager::new(std::sync::Arc::new(
            common::MockSchemaRegistryProvider,
        )),
    );
    let orchestrator = WriteOrchestrator::new(
        audit_buffer.clone(),
        crypto_manager.clone(),
        uploader,
        governance_manager,
        std::sync::Arc::new(
            holonomy_core::manager::policy_manager::PolicyManager::new_dangerously_allow_unsigned(
                std::sync::Arc::new(common::MockPolicyProvider),
            ),
        ),
    );

    let schema = Arc::new(Schema::new(vec![Field::new("id", DataType::Int32, false)]));
    let batch =
        RecordBatch::try_new(schema.clone(), vec![Arc::new(Int32Array::from(vec![1]))]).unwrap();

    let write_result = orchestrator
        .write(
            &batch,
            partition_id,
            Some("Gate 022 Integration Write"),
            "mock_user_hash",
            Some(
                r#"{
                "name": "IntegrationTest",
                "version": "1.0",
                "columns": [
                    {"name": "id", "type": "int32", "required": true}
                ]
            }"#,
            ),
        )
        .await;

    assert!(
        write_result.is_ok(),
        "Write orchestrator failed: {:?}",
        write_result.err().unwrap()
    );

    // Wait briefly for the broadcaster to pick up and dispatch the event
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify webhook received the audit event
    mock_webhook.assert_async().await;

    // Verify S3 write events
    mock_create.assert_async().await;
    mock_upload_part.assert_async().await;
    mock_complete.assert_async().await;

    // Abort the broadcaster so it doesn't race and drain our shred event
    broadcaster_handle.abort();

    // 3. Perform a crypto-shredding operation
    // Using KmsAdmin to shred the partition
    let mock_kms_delete = server
        .mock("DELETE", format!("/keys/{}", dek_id).as_str())
        .with_status(200)
        .expect(1)
        .create_async()
        .await;

    let kms_admin = KmsAdmin::new(server.url(), dek_cache.clone(), audit_buffer.clone());

    let shred_result = kms_admin
        .shred_partition(&dek_id, "admin-user-hash", "shred for integration test")
        .await;

    assert!(shred_result.is_ok(), "Shred partition failed");

    // Verify KMS delete endpoint was called
    mock_kms_delete.assert_async().await;

    // Verify data is unreadable (DEK removed from cache)
    assert!(
        dek_cache.get(&dek_id).is_none(),
        "DEK should be removed from cache, rendering data unreadable"
    );

    // Verify end-to-end admin flows by checking the audit buffer
    let audit_event = audit_buffer.pop().expect("Should have shred audit event");
    assert_eq!(audit_event.action, Action::Shred);
    assert_eq!(audit_event.business_purpose, "shred for integration test");
}
