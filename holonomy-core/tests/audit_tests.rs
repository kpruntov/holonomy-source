// @trace TASK-007
use chrono::Utc;
use std::sync::Arc;

// We will import these from our module once implemented
use holonomy_core::audit::ring_buffer::{Action, AuditEvent, AuditRingBuffer};

#[tokio::test]
async fn test_high_concurrency_ingestion() {
    let capacity = 100_000;
    let ring_buffer = Arc::new(AuditRingBuffer::new(capacity));
    let mut handles = vec![];

    // Spawn 100 concurrent tasks
    for i in 0..100 {
        let rb = ring_buffer.clone();
        handles.push(tokio::spawn(async move {
            // Each task pushes 1000 events
            for j in 0..1000 {
                let event = AuditEvent {
                    timestamp: Utc::now(),
                    user_hash: format!("user_{}", i),
                    file_signature: format!("sig_{}", j),
                    accessed_columns: Some(vec!["col1".to_string()]),
                    business_purpose: "Test Purpose".to_string(),
                    action: Action::Read,
                };
                rb.push(event);
            }
        }));
    }

    // Wait for all tasks to finish
    for handle in handles {
        handle.await.unwrap();
    }

    // The buffer should have exactly 100_000 elements since we didn't drop any
    // because capacity == total pushed elements.
    assert_eq!(ring_buffer.len(), 100_000);
}

#[test]
fn test_overflow_drop_policy() {
    let capacity = 10;
    let ring_buffer = AuditRingBuffer::new(capacity);

    // Push 15 events
    for i in 0..15 {
        let event = AuditEvent {
            timestamp: Utc::now(),
            user_hash: format!("user_{}", i),
            file_signature: "sig".to_string(),
            accessed_columns: None,
            business_purpose: "Test Purpose".to_string(),
            action: Action::Write,
        };
        ring_buffer.push(event);
    }

    // The buffer should be at its maximum capacity
    assert_eq!(ring_buffer.len(), 10);
}
