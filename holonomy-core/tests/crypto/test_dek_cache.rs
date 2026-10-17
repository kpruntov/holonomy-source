// @trace TASK-070
// @trace FR-007

use holonomy_core::crypto::pme_encrypt::PmeEncryptor;
#[path = "../common/mod.rs"]
mod common;
use holonomy_core::crypto::dek_cache::DekCache;
use holonomy_core::manager::crypto_manager::CryptoManager;
use std::sync::Arc;

#[tokio::test]
async fn test_time_based_dek_caching() {
    let dek_cache = Arc::new(DekCache::default());
    let crypto_manager = Arc::new(CryptoManager::new(
        dek_cache,
        Arc::new(common::MockKmsProvider),
    ));

    // First generation (cache miss)
    let dek1 = PmeEncryptor::generate_or_get_dek(
        &crypto_manager,
        "s3://bucket/data",
        "test",
        "__footer__",
        "user_123",
    )
    .await
    .unwrap();

    // Second generation (cache hit)
    let dek2 = PmeEncryptor::generate_or_get_dek(
        &crypto_manager,
        "s3://bucket/data",
        "test",
        "__footer__",
        "user_123",
    )
    .await
    .unwrap();

    // They should be exactly the same
    assert_eq!(dek1.plaintext.as_slice(), dek2.plaintext.as_slice());
    assert_eq!(dek1.wrapped, dek2.wrapped);

    // Different column name should generate a different key
    let dek3 = PmeEncryptor::generate_or_get_dek(
        &crypto_manager,
        "s3://bucket/data",
        "test",
        "other_column",
        "user_123",
    )
    .await
    .unwrap();
    assert_ne!(dek1.plaintext.as_slice(), dek3.plaintext.as_slice());

    // Different target should generate different key
    let dek4 = PmeEncryptor::generate_or_get_dek(
        &crypto_manager,
        "s3://bucket/other",
        "test",
        "__footer__",
        "user_123",
    )
    .await
    .unwrap();
    assert_ne!(dek1.plaintext.as_slice(), dek4.plaintext.as_slice());

    // Different user_ctx should generate different key
    let dek5 = PmeEncryptor::generate_or_get_dek(
        &crypto_manager,
        "s3://bucket/data",
        "test",
        "__footer__",
        "user_456",
    )
    .await
    .unwrap();
    assert_ne!(dek1.plaintext.as_slice(), dek5.plaintext.as_slice());
}
