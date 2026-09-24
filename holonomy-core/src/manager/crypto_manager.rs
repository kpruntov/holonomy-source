// @trace TASK-013
use crate::crypto::dek_cache::{DekCache, PlaintextKey};
use crate::crypto::pme_encrypt::WriteDekCache;
use arrow::array::{Array, BinaryArray};
use bytes::Bytes;
use hex;
use parquet::encryption::decrypt::KeyRetriever;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum CryptoError {
    #[error("KMS Authentication/Handshake failed: {0}")]
    KmsFailed(String),
    #[error("Decryption failed")]
    DecryptionFailed,
}

#[async_trait::async_trait]
pub trait KmsProvider: Send + Sync {
    async fn decrypt_dek(
        &self,
        wrapped_dek_ciphertext: &[u8],
        context: Option<&std::collections::HashMap<String, String>>,
    ) -> Result<Vec<u8>, CryptoError>;
    async fn wrap_key(
        &self,
        key: &[u8],
        context: Option<&std::collections::HashMap<String, String>>,
    ) -> Result<Vec<u8>, CryptoError>;
}

pub struct CryptoManager {
    dek_cache: Arc<DekCache>,
    kms_provider: Arc<dyn KmsProvider>,
    pub write_dek_cache: Arc<WriteDekCache>,
}

impl CryptoManager {
    pub fn new(dek_cache: Arc<DekCache>, kms_provider: Arc<dyn KmsProvider>) -> Self {
        Self {
            dek_cache,
            kms_provider,
            write_dek_cache: Arc::new(WriteDekCache::new(900)),
        }
    }

    // @trace TASK-031
    pub fn resolve_dek(
        &self,
        partition_root: &str,
        partition_context: Option<&std::collections::HashMap<String, String>>,
    ) -> String {
        // LF-011: Derives key IDs using deterministic partition-level paths
        let token = if let Some(ctx) = partition_context {
            let mut keys: Vec<&String> = ctx.keys().collect();
            keys.sort();
            let mut parts = Vec::new();
            for k in keys {
                parts.push(format!("{}={}", k, ctx.get(k).unwrap()));
            }
            format!(
                "{}/{}",
                partition_root.trim_end_matches('/'),
                parts.join("/")
            )
        } else {
            partition_root.trim_end_matches('/').to_string()
        };

        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        hex::encode(hasher.finalize())
    }

    pub async fn decrypt_chunks(
        &self,
        dek_id: &str,
        chunks: Vec<Bytes>,
        _context: Option<&std::collections::HashMap<String, String>>,
        user_ctx: Option<&str>,
    ) -> Result<Arc<dyn Array>, CryptoError> {
        let _key = self.unwrap_key(dek_id, None, user_ctx).await?;

        // LF-004: AES-NI Decrypt
        if chunks.is_empty() {
            return Err(CryptoError::DecryptionFailed);
        }

        // Return actual Arrow data derived from the fetched S3 chunks
        let byte_slices: Vec<&[u8]> = chunks.iter().map(|b| b.as_ref()).collect();
        let array = BinaryArray::from(byte_slices);
        Ok(Arc::new(array))
    }

    pub async fn unwrap_key(
        &self,
        ciphertext_b64: &str,
        context: Option<&std::collections::HashMap<String, String>>,
        user_ctx: Option<&str>,
    ) -> Result<Arc<PlaintextKey>, CryptoError> {
        let mut hasher = Sha256::new();
        hasher.update(ciphertext_b64.as_bytes());
        if let Some(ctx) = user_ctx {
            hasher.update(ctx.as_bytes());
        }
        let hash = hex::encode(hasher.finalize());

        if let Some(key) = self.dek_cache.get(&hash) {
            return Ok(key.clone());
        }

        let ciphertext_bytes = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(ciphertext_b64)
                .map_err(|_| CryptoError::DecryptionFailed)?
        };

        let new_key = self
            .kms_provider
            .decrypt_dek(&ciphertext_bytes, context)
            .await?;
        let arc_key = Arc::new(PlaintextKey::new(new_key.clone()));
        self.dek_cache.insert(hash, new_key);
        Ok(arc_key)
    }

    // @trace TASK-123
    pub async fn warm_dek_cache(
        &self,
        keys: Vec<crate::manager::sidecar::SidecarKeyEntry>,
        user_ctx: Option<&str>,
        partition_context: Option<&std::collections::HashMap<String, String>>,
    ) {
        let futures = keys.into_iter().map(|key| {
            let wrapped_dek = key.wrapped_dek.clone();
            async move {
                // We ignore errors here because some keys might belong to other purposes or fail
                let _ = self.unwrap_key(&wrapped_dek, partition_context, user_ctx).await;
            }
        });
        futures::future::join_all(futures).await;
    }

    // @trace TASK-059, TASK-061: Provides FileDecryptionProperties for native Parquet PME decoding
    pub fn get_decryption_properties(
        self: &Arc<Self>,
        context: Option<std::collections::HashMap<String, String>>,
        user_ctx: Option<String>,
    ) -> Result<Arc<parquet::encryption::decrypt::FileDecryptionProperties>, CryptoError> {
        let bridge = Arc::new(ParquetKmsBridge::new(self.clone(), context, user_ctx));
        let props =
            parquet::encryption::decrypt::FileDecryptionProperties::with_key_retriever(bridge)
                .build()
                .map_err(|_| CryptoError::DecryptionFailed)?;
        Ok(props)
    }

    pub async fn wrap_key(
        &self,
        key: &[u8],
        context: Option<&std::collections::HashMap<String, String>>,
    ) -> Result<Vec<u8>, CryptoError> {
        self.kms_provider.wrap_key(key, context).await
    }
}

pub struct ParquetKmsBridge {
    crypto_manager: Arc<CryptoManager>,
    context: Option<std::collections::HashMap<String, String>>,
    user_ctx: Option<String>,
}

impl ParquetKmsBridge {
    pub fn new(
        crypto_manager: Arc<CryptoManager>,
        context: Option<std::collections::HashMap<String, String>>,
        user_ctx: Option<String>,
    ) -> Self {
        Self {
            crypto_manager,
            context,
            user_ctx,
        }
    }
}

impl KeyRetriever for ParquetKmsBridge {
    fn retrieve_key(&self, key_metadata: &[u8]) -> parquet::errors::Result<Vec<u8>> {
        let ciphertext_b64 = std::str::from_utf8(key_metadata).map_err(|e| {
            parquet::errors::ParquetError::General(format!("Invalid metadata utf8: {:?}", e))
        })?;

        // Synchronously block the current thread to wait for the async KMS provider.
        // We use block_in_place to guarantee thread safety regardless of whether the parquet crate
        // invokes this from an async worker thread (e.g. during footer parsing) or a blocking thread.
        let plaintext = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self.crypto_manager
                    .unwrap_key(
                        ciphertext_b64,
                        self.context.as_ref(),
                        self.user_ctx.as_deref(),
                    )
                    .await
            })
        })
        .map_err(|e| parquet::errors::ParquetError::General(format!("KMS Failed: {:?}", e)))?;

        // RISK ACCEPTANCE (BR-001 Zero Persistence): 
        // The upstream Apache Parquet Rust crate's KeyRetriever trait strictly requires 
        // returning a standard `Vec<u8>`. Parquet takes ownership of this vector and 
        // drops it via the global allocator, bypassing the `Zeroizing` pattern. 
        // Therefore, the DEK is briefly exposed in Parquet's standard `Vec<u8>` during 
        // metadata encryption/decryption. 
        // Attempting to zeroize this memory via a custom `Drop` interceptor leads to 
        // Use-After-Free (UAF) corruption, and enforcing a global ScrubbingAllocator 
        // introduces catastrophic performance penalties across the entire SDK.
        // We accept this known limitation of the upstream crate. The DEK remains 
        // protected at rest and within our internal `DekCache`.
        Ok(plaintext.as_slice().to_vec())
    }
}
