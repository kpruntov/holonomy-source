use base64::Engine;
use holonomy_core::manager::crypto_manager::{CryptoError, CryptoManager, KmsProvider};
use sha2::{Digest, Sha256};
use std::sync::Arc;

struct MockEnvelopeKms;

#[async_trait::async_trait]
impl KmsProvider for MockEnvelopeKms {
    async fn decrypt_dek(
        &self,
        wrapped_dek_ciphertext: &[u8],
        _context: Option<&std::collections::HashMap<String, String>>,
    ) -> Result<Vec<u8>, CryptoError> {
        if wrapped_dek_ciphertext == b"mock_encrypted_payload" {
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
        Ok(b"mock_encrypted_payload".to_vec())
    }
}

#[tokio::test]
async fn test_envelope_encryption_flow() {
    let dek_cache = Arc::new(holonomy_core::crypto::dek_cache::DekCache::default());
    let crypto_manager = CryptoManager::new(dek_cache, Arc::new(MockEnvelopeKms));

    let ciphertext = b"mock_encrypted_payload";
    let ciphertext_b64 = base64::engine::general_purpose::STANDARD.encode(ciphertext);

    let mut hasher = Sha256::new();
    hasher.update(ciphertext_b64.as_bytes());
    let _expected_hash = hex::encode(hasher.finalize());

    let plaintext = crypto_manager
        .unwrap_key(&ciphertext_b64, None, None)
        .await
        .unwrap();
    assert_eq!(plaintext.as_slice(), b"secret_key_12345");
}
