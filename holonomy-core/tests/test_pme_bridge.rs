// @trace TASK-061
use holonomy_core::crypto::dek_cache::DekCache;
use holonomy_core::manager::crypto_manager::{
    CryptoError, CryptoManager, KmsProvider, ParquetKmsBridge,
};
use parquet::encryption::decrypt::KeyRetriever;
use std::sync::Arc;

struct MockAsyncKmsProvider;

#[async_trait::async_trait]
impl KmsProvider for MockAsyncKmsProvider {
    async fn decrypt_dek(
        &self,
        wrapped_dek_ciphertext: &[u8],
        _context: Option<&std::collections::HashMap<String, String>>,
    ) -> Result<Vec<u8>, CryptoError> {
        if wrapped_dek_ciphertext == b"valid_ciphertext" {
            Ok(b"secret_key_12345".to_vec())
        } else {
            Err(CryptoError::KmsFailed("mock fail".to_string()))
        }
    }

    async fn wrap_key(
        &self,
        _key: &[u8],
        _context: Option<&std::collections::HashMap<String, String>>,
    ) -> Result<Vec<u8>, CryptoError> {
        Ok(b"wrapped".to_vec())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_parquet_kms_bridge_success() {
    let dek_cache = Arc::new(DekCache::default());
    let crypto_manager = Arc::new(CryptoManager::new(
        dek_cache,
        Arc::new(MockAsyncKmsProvider),
    ));
    let bridge = ParquetKmsBridge::new(crypto_manager, None, None);

    use base64::Engine;
    let valid_b64 = base64::engine::general_purpose::STANDARD.encode(b"valid_ciphertext");

    // Call synchronously, which is what Parquet does.
    // This will use block_in_place and block_on safely.
    let retrieved = bridge
        .retrieve_key(valid_b64.as_bytes())
        .expect("Should retrieve successfully");
    assert_eq!(retrieved, b"secret_key_12345".to_vec());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_parquet_kms_bridge_failure() {
    let dek_cache = Arc::new(DekCache::default());
    let crypto_manager = Arc::new(CryptoManager::new(
        dek_cache,
        Arc::new(MockAsyncKmsProvider),
    ));
    let bridge = ParquetKmsBridge::new(crypto_manager, None, None);

    use base64::Engine;
    let invalid_b64 = base64::engine::general_purpose::STANDARD.encode(b"invalid_ciphertext");

    // Should return a ParquetError if KMS fails
    let result = bridge.retrieve_key(invalid_b64.as_bytes());
    assert!(result.is_err(), "Expected error for invalid dek");
}
