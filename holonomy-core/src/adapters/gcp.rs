// @trace TASK-064
// @trace FR-002
use base64::{Engine as _, engine::general_purpose::STANDARD as base64_standard};
use gcp_auth::{Token, TokenProvider, provider};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::sync::Arc;

pub struct GcpAdapter {
    client: Client,
    auth_provider: Arc<dyn TokenProvider>,
    key_id: String, // e.g., projects/*/locations/*/keyRings/*/cryptoKeys/*
    endpoint_url: String,
}

#[derive(Serialize)]
struct EncryptRequest {
    plaintext: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    additional_authenticated_data: Option<String>,
}

#[derive(Deserialize)]
struct EncryptResponse {
    ciphertext: Option<String>,
}

#[derive(Serialize)]
struct DecryptRequest {
    ciphertext: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    additional_authenticated_data: Option<String>,
}

#[derive(Deserialize)]
struct DecryptResponse {
    plaintext: Option<String>,
}

impl GcpAdapter {
    pub async fn new(
        key_id: String,
        endpoint_url: Option<String>,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let auth_provider = provider().await?;
        let endpoint =
            endpoint_url.unwrap_or_else(|| "https://cloudkms.googleapis.com".to_string());
        Ok(Self {
            client: Client::new(),
            auth_provider,
            key_id,
            endpoint_url: endpoint,
        })
    }

    pub fn new_with_provider(
        key_id: String,
        endpoint_url: String,
        auth_provider: Arc<dyn TokenProvider>,
    ) -> Self {
        Self {
            client: Client::new(),
            auth_provider,
            key_id,
            endpoint_url,
        }
    }

    pub fn set_client(&mut self, client: Client) {
        self.client = client;
    }

    async fn get_token(&self) -> Result<Arc<Token>, Box<dyn Error + Send + Sync>> {
        let scopes = &["https://www.googleapis.com/auth/cloud-platform"];
        let token = self.auth_provider.token(scopes).await?;
        Ok(token)
    }

    pub async fn encrypt(
        &self,
        key_name: &str,
        plaintext: &[u8],
        encryption_context: Option<&std::collections::HashMap<String, String>>,
    ) -> Result<String, Box<dyn Error + Send + Sync>> {
        let b64_plaintext = base64_standard.encode(plaintext);

        let url = format!("{}/v1/{}:encrypt", self.endpoint_url, key_name);

        let context_str = encryption_context.map(|ctx| {
            let json = serde_json::to_string(ctx).unwrap_or_default();
            base64_standard.encode(json.as_bytes())
        });

        let req_body = EncryptRequest {
            plaintext: b64_plaintext,
            additional_authenticated_data: context_str,
        };

        let token = self.get_token().await?;

        let res = self
            .client
            .post(&url)
            .bearer_auth(token.as_str())
            .json(&req_body)
            .send()
            .await?;

        if !res.status().is_success() {
            let status = res.status();
            let body = res.text().await.unwrap_or_default();
            return Err(format!("GCP KMS encrypt error: {} - {}", status, body).into());
        }

        let resp_json: EncryptResponse = res.json().await?;
        let ciphertext = resp_json
            .ciphertext
            .ok_or("Missing ciphertext in GCP response")?;

        Ok(ciphertext)
    }

    pub async fn decrypt(
        &self,
        key_name: &str,
        ciphertext: &str,
        encryption_context: Option<&std::collections::HashMap<String, String>>,
    ) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        let url = format!("{}/v1/{}:decrypt", self.endpoint_url, key_name);

        let context_str = encryption_context.map(|ctx| {
            let json = serde_json::to_string(ctx).unwrap_or_default();
            base64_standard.encode(json.as_bytes())
        });

        let req_body = DecryptRequest {
            ciphertext: ciphertext.to_string(),
            additional_authenticated_data: context_str,
        };

        let token = self.get_token().await?;

        let res = self
            .client
            .post(&url)
            .bearer_auth(token.as_str())
            .json(&req_body)
            .send()
            .await?;

        if !res.status().is_success() {
            let status = res.status();
            let body = res.text().await.unwrap_or_default();
            return Err(format!("GCP KMS decrypt error: {} - {}", status, body).into());
        }

        let resp_json: DecryptResponse = res.json().await?;
        let b64_plaintext = resp_json
            .plaintext
            .ok_or("Missing plaintext in GCP response")?;

        let decoded = base64_standard.decode(&b64_plaintext)?;
        Ok(decoded)
    }
}

#[async_trait::async_trait]
impl crate::manager::crypto_manager::KmsProvider for GcpAdapter {
    async fn decrypt_dek(
        &self,
        wrapped_dek_ciphertext: &[u8],
        context: Option<&std::collections::HashMap<String, String>>,
    ) -> Result<Vec<u8>, crate::manager::crypto_manager::CryptoError> {
        let ciphertext_str = String::from_utf8(wrapped_dek_ciphertext.to_vec())
            .map_err(|_| crate::manager::crypto_manager::CryptoError::KmsFailed("Invalid ciphertext".to_string()))?;

        let decrypted = self
            .decrypt(&self.key_id, &ciphertext_str, context)
            .await
            .map_err(|e| crate::manager::crypto_manager::CryptoError::KmsFailed(format!("GCP KMS decrypt failed. Are you logged in? Try 'gcloud auth application-default login'. Underlying error: {}", e)))?;
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
            .map_err(|e| crate::manager::crypto_manager::CryptoError::KmsFailed(format!("GCP KMS encrypt failed. Are you logged in? Try 'gcloud auth application-default login'. Underlying error: {}", e)))?;
        Ok(encrypted.into_bytes())
    }
}
