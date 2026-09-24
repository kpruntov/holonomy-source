// @trace TASK-023
use aws_config::SdkConfig;
use aws_sdk_kms::Client as KmsClient;
use aws_sdk_s3::Client as S3Client;
use aws_sdk_s3::primitives::ByteStream;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AwsError {
    #[error("KMS error: {0}")]
    KmsError(String),
    #[error("S3 error: {0}")]
    S3Error(String),
}

pub struct AwsAdapter {
    kms_client: KmsClient,
    s3_client: S3Client,
    key_id: String,
}

impl AwsAdapter {
    pub fn new(config: &SdkConfig, key_id: String) -> Self {
        Self {
            kms_client: KmsClient::new(config),
            s3_client: S3Client::new(config),
            key_id,
        }
    }

    pub async fn decrypt(
        &self,
        ciphertext: &[u8],
        encryption_context: Option<&std::collections::HashMap<String, String>>,
    ) -> Result<Vec<u8>, AwsError> {
        let mut builder = self
            .kms_client
            .decrypt()
            .ciphertext_blob(aws_smithy_types::Blob::new(ciphertext));

        if let Some(ctx) = encryption_context {
            for (k, v) in ctx {
                builder = builder.encryption_context(k.clone(), v.clone());
            }
        }

        let response = builder
            .send()
            .await
            .map_err(|e| AwsError::KmsError(e.to_string()))?;

        response
            .plaintext()
            .map(|blob| blob.clone().into_inner())
            .ok_or_else(|| AwsError::KmsError("No plaintext returned".to_string()))
    }

    pub async fn encrypt(
        &self,
        key_id: &str,
        plaintext: &[u8],
        encryption_context: Option<&std::collections::HashMap<String, String>>,
    ) -> Result<Vec<u8>, AwsError> {
        let mut builder = self
            .kms_client
            .encrypt()
            .key_id(key_id)
            .plaintext(aws_smithy_types::Blob::new(plaintext));

        if let Some(ctx) = encryption_context {
            for (k, v) in ctx {
                builder = builder.encryption_context(k.clone(), v.clone());
            }
        }

        let response = builder
            .send()
            .await
            .map_err(|e| AwsError::KmsError(e.to_string()))?;

        response
            .ciphertext_blob()
            .map(|blob| blob.clone().into_inner())
            .ok_or_else(|| AwsError::KmsError("No ciphertext returned".to_string()))
    }

    pub async fn upload(&self, bucket: &str, key: &str, data: Vec<u8>) -> Result<(), AwsError> {
        self.s3_client
            .put_object()
            .bucket(bucket)
            .key(key)
            .body(ByteStream::from(data))
            .send()
            .await
            .map_err(|e| AwsError::S3Error(e.to_string()))?;
        Ok(())
    }

    pub async fn download(&self, bucket: &str, key: &str) -> Result<Vec<u8>, AwsError> {
        let resp = self
            .s3_client
            .get_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| AwsError::S3Error(e.to_string()))?;

        let data = resp
            .body
            .collect()
            .await
            .map_err(|e| AwsError::S3Error(e.to_string()))?;
        Ok(data.into_bytes().to_vec())
    }
}

// @trace TASK-063
// @trace FR-002
#[async_trait::async_trait]
impl crate::manager::crypto_manager::KmsProvider for AwsAdapter {
    async fn decrypt_dek(
        &self,
        wrapped_dek_ciphertext: &[u8],
        context: Option<&std::collections::HashMap<String, String>>,
    ) -> Result<Vec<u8>, crate::manager::crypto_manager::CryptoError> {
        let decrypted = self
            .decrypt(wrapped_dek_ciphertext, context)
            .await
            .map_err(|e| crate::manager::crypto_manager::CryptoError::KmsFailed(format!("AWS KMS decrypt failed. Are you logged in? Try 'aws sso login'. Underlying error: {}", e)))?;
        Ok(decrypted)
    }

    async fn wrap_key(
        &self,
        key: &[u8],
        context: Option<&std::collections::HashMap<String, String>>,
    ) -> Result<Vec<u8>, crate::manager::crypto_manager::CryptoError> {
        let encrypted = self
            .encrypt(&self.key_id, key, context)
            .await
            .map_err(|e| crate::manager::crypto_manager::CryptoError::KmsFailed(format!("AWS KMS encrypt failed. Are you logged in? Try 'aws sso login'. Underlying error: {}", e)))?;
        Ok(encrypted)
    }
}
