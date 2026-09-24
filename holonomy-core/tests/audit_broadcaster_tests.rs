// @trace TASK-019
use chrono::Utc;
use mockito::Server;
use std::sync::Arc;
use tokio::time::{Duration, sleep};

use holonomy_core::audit::broadcaster::{AuditBroadcaster, SinkConfig};
use holonomy_core::audit::ring_buffer::{Action, AuditEvent, AuditRingBuffer};

#[tokio::test]
async fn test_broadcaster_batch_send() {
    let mut server = Server::new_async().await;

    // We expect a POST to /audit
    let mock = server
        .mock("POST", "/audit")
        .match_header("content-type", "application/json")
        .match_header("authorization", "Bearer test_auth_token")
        .with_status(200)
        .with_body(r#"{"status": "ok"}"#)
        .expect(1)
        .create_async()
        .await;

    let buffer = Arc::new(AuditRingBuffer::new(100));
    let endpoint = format!("{}/audit", server.url());

    let broadcaster = AuditBroadcaster::new(
        buffer.clone(),
        SinkConfig::SaaS(endpoint, Some("test_auth_token".to_string())),
        2,                         // batch_size
        Duration::from_millis(50), // flush_interval
        3,                         // max_retries
    );

    let handle = broadcaster.start();

    // Push 2 events
    buffer.push(AuditEvent {
        timestamp: Utc::now(),
        user_hash: "user1".to_string(),
        file_signature: "file1".to_string(),
        accessed_columns: None,
        business_purpose: "test".to_string(),
        action: Action::Read,
    });

    buffer.push(AuditEvent {
        timestamp: Utc::now(),
        user_hash: "user2".to_string(),
        file_signature: "file2".to_string(),
        accessed_columns: None,
        business_purpose: "test".to_string(),
        action: Action::Write,
    });

    // Wait for the broadcaster to pick it up
    sleep(Duration::from_millis(200)).await;

    mock.assert_async().await;

    handle.abort();
}

#[tokio::test]
async fn test_broadcaster_retry_backoff() {
    let mut server = Server::new_async().await;

    // First 2 times fail, 3rd time succeeds
    let mock_fail = server
        .mock("POST", "/audit")
        .with_status(500)
        .expect(2)
        .create_async()
        .await;

    let mock_success = server
        .mock("POST", "/audit")
        .with_status(200)
        .expect(1)
        .create_async()
        .await;

    let buffer = Arc::new(AuditRingBuffer::new(100));
    let endpoint = format!("{}/audit", server.url());

    let broadcaster = AuditBroadcaster::new(
        buffer.clone(),
        SinkConfig::SaaS(endpoint, None),
        1,                         // batch_size
        Duration::from_millis(10), // flush_interval
        3,                         // max_retries
    );

    let handle = broadcaster.start();

    buffer.push(AuditEvent {
        timestamp: Utc::now(),
        user_hash: "user3".to_string(),
        file_signature: "file3".to_string(),
        accessed_columns: None,
        business_purpose: "retry_test".to_string(),
        action: Action::Read,
    });

    sleep(Duration::from_millis(1500)).await;

    mock_fail.assert_async().await;
    mock_success.assert_async().await;

    handle.abort();
}
