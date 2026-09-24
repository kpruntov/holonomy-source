// @trace TASK-139
use std::sync::Arc;
use std::time::Duration;
use chrono::Utc;
use holonomy_core::audit::broadcaster::{AuditBroadcaster, SinkConfig};
use holonomy_core::audit::ring_buffer::{Action, AuditEvent, AuditRingBuffer};
use holonomy_core::manager::license_manager::set_license_valid;

use serial_test::serial;

#[tokio::test]
#[serial]
async fn test_telemetry_injects_license_status_unlicensed() {
    set_license_valid(false);

    let buffer = Arc::new(AuditRingBuffer::new(10));
    let temp_dir = tempfile::tempdir().unwrap();
    let file_path = temp_dir.path().join("audit.log");
    
    let sink = SinkConfig::LocalFile(file_path.to_string_lossy().to_string());
    
    let broadcaster = AuditBroadcaster::new(buffer.clone(), sink, 1, Duration::from_millis(100), 3);
    broadcaster.start();
    
    buffer.push(AuditEvent {
        timestamp: Utc::now(),
        user_hash: "test_hash".to_string(),
        file_signature: "test_sig".to_string(),
        accessed_columns: None,
        business_purpose: "test".to_string(),
        action: Action::Read,
    });
    
    // Allow the broadcaster task to run
    tokio::time::sleep(Duration::from_millis(200)).await;
    
    let content = tokio::fs::read_to_string(&file_path).await.unwrap();
    assert!(content.contains(r#""license_status":"UNLICENSED""#), "Payload should be UNLICENSED");
}

#[tokio::test]
#[serial]
async fn test_telemetry_injects_license_status_valid() {
    set_license_valid(true);

    let buffer = Arc::new(AuditRingBuffer::new(10));
    let temp_dir = tempfile::tempdir().unwrap();
    let file_path = temp_dir.path().join("audit2.log");
    
    let sink = SinkConfig::LocalFile(file_path.to_string_lossy().to_string());
    
    let broadcaster = AuditBroadcaster::new(buffer.clone(), sink, 1, Duration::from_millis(100), 3);
    broadcaster.start();
    
    buffer.push(AuditEvent {
        timestamp: Utc::now(),
        user_hash: "test_hash2".to_string(),
        file_signature: "test_sig2".to_string(),
        accessed_columns: None,
        business_purpose: "test2".to_string(),
        action: Action::Write,
    });
    
    // Allow the broadcaster task to run
    tokio::time::sleep(Duration::from_millis(200)).await;
    
    let content = tokio::fs::read_to_string(&file_path).await.unwrap();
    assert!(content.contains(r#""license_status":"VALID""#), "Payload should be VALID");
    
    // Reset back to false so we don't pollute other tests, although tests are parallel so ideally use #[serial]
    set_license_valid(false);
}
