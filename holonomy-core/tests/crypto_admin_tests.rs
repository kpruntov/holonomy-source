// @trace TASK-020
use holonomy_core::audit::ring_buffer::{Action, AuditRingBuffer};
use holonomy_core::crypto::dek_cache::DekCache;
use holonomy_core::crypto::kms_admin::KmsAdmin;
use mockito::Server;
use std::sync::Arc;

#[tokio::test]
async fn test_shred_partition() {
    let mut server = Server::new_async().await;

    let dek_id = "test-dek-id-12345";

    let mock = server
        .mock("DELETE", format!("/keys/{}", dek_id).as_str())
        .with_status(200)
        .create_async()
        .await;

    let dek_cache = Arc::new(DekCache::default());
    let audit_buffer = Arc::new(AuditRingBuffer::new(10));

    // Populate the cache to verify it gets removed
    dek_cache.insert(dek_id.to_string(), vec![1, 2, 3, 4]);

    // Ensure it's there
    assert!(dek_cache.get(dek_id).is_some());

    let kms_admin = KmsAdmin::new(server.url(), dek_cache.clone(), audit_buffer.clone());

    let result = kms_admin
        .shred_partition(dek_id, "admin-user-hash", "compliance")
        .await;

    assert!(result.is_ok(), "Shred partition failed");

    // 1. Verify KMS DELETE API was called
    mock.assert_async().await;

    // 2. Verify subsequent reads would fail (key is removed from cache)
    assert!(
        dek_cache.get(dek_id).is_none(),
        "DEK should be removed from cache"
    );

    // 3. Verify audit log
    let audit_event = audit_buffer.pop().expect("Audit event not found");
    assert_eq!(audit_event.action, Action::Shred);
    assert_eq!(audit_event.user_hash, "admin-user-hash");
    assert_eq!(audit_event.file_signature, dek_id);
    assert_eq!(audit_event.business_purpose, "compliance");
}

#[tokio::test]
async fn test_shred_partition_kms_failure() {
    let mut server = Server::new_async().await;
    let dek_id = "test-dek-id-failure";

    let mock = server
        .mock("DELETE", format!("/keys/{}", dek_id).as_str())
        .with_status(500)
        .create_async()
        .await;

    let dek_cache = Arc::new(DekCache::default());
    let audit_buffer = Arc::new(AuditRingBuffer::new(10));

    dek_cache.insert(dek_id.to_string(), vec![1, 2, 3, 4]);

    let kms_admin = KmsAdmin::new(server.url(), dek_cache.clone(), audit_buffer.clone());

    let result = kms_admin
        .shred_partition(dek_id, "admin-user-hash", "compliance")
        .await;

    assert!(result.is_err(), "Shred partition should fail");

    mock.assert_async().await;

    // Verify key was NOT removed and audit WAS logged
    assert!(dek_cache.get(dek_id).is_some());
    let audit_event = audit_buffer
        .pop()
        .expect("Audit event should be recorded before failure");
    assert_eq!(audit_event.action, Action::Shred);
}
