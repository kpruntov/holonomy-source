// @trace TASK-024
// @trace TASK-095
use base64::{Engine as _, engine::general_purpose::STANDARD as base64_standard};
use reqwest::Client;
use serde::{Deserialize, Serialize};


pub struct VaultAdapter {
    client: Client,
    endpoint: String,
    token: String,
    key_name: String,
}

#[derive(Serialize)]
struct EncryptRequest {
    plaintext: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<String>,
}

#[derive(Deserialize)]
struct VaultResponse {
    data: VaultData,
}

#[derive(Deserialize)]
struct VaultData {
    ciphertext: Option<String>,
    plaintext: Option<String>,
}

#[derive(Serialize)]
struct DecryptRequest {
    ciphertext: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<String>,
}

impl VaultAdapter {
    pub fn new(endpoint: String, token: String, key_name: String) -> Self {
        Self {
            client: Client::new(),
            endpoint,
            token,
            key_name,
        }
    }
}

#[async_trait::async_trait]
impl crate::manager::crypto_manager::KmsProvider for VaultAdapter {
    async fn wrap_key(
        &self,
        key: &[u8],
        context: Option<&std::collections::HashMap<String, String>>,
    ) -> Result<Vec<u8>, crate::manager::crypto_manager::CryptoError> {
        let b64_plaintext = base64_standard.encode(key);
        let url = format!("{}/v1/transit/encrypt/{}", self.endpoint, self.key_name);

        let context_str = context.map(|ctx| {
            let json = serde_json::to_string(ctx).unwrap_or_default();
            base64_standard.encode(json.as_bytes())
        });

        let req_body = EncryptRequest {
            plaintext: b64_plaintext,
            context: context_str,
        };

        let res = self
            .client
            .post(&url)
            .header("X-Vault-Token", &self.token)
            .json(&req_body)
            .send()
            .await
            .map_err(|e| crate::manager::crypto_manager::CryptoError::KmsFailed(e.to_string()))?;

        if !res.status().is_success() {
            let status = res.status();
            let body = res.text().await.unwrap_or_default();
            return Err(crate::manager::crypto_manager::CryptoError::KmsFailed(format!("Vault encrypt error: {} - {}", status, body)));
        }

        let resp_json: VaultResponse = res.json().await
            .map_err(|e| crate::manager::crypto_manager::CryptoError::KmsFailed(e.to_string()))?;
        let ciphertext = resp_json
            .data
            .ciphertext
            .ok_or_else(|| crate::manager::crypto_manager::CryptoError::KmsFailed("Missing ciphertext in response".to_string()))?;

        Ok(ciphertext.into_bytes())
    }

    async fn decrypt_dek(
        &self,
        wrapped_dek_ciphertext: &[u8],
        context: Option<&std::collections::HashMap<String, String>>,
    ) -> Result<Vec<u8>, crate::manager::crypto_manager::CryptoError> {
        let url = format!("{}/v1/transit/decrypt/{}", self.endpoint, self.key_name);

        let context_str = context.map(|ctx| {
            let json = serde_json::to_string(ctx).unwrap_or_default();
            base64_standard.encode(json.as_bytes())
        });

        let ciphertext_str = std::str::from_utf8(wrapped_dek_ciphertext)
            .map_err(|_| crate::manager::crypto_manager::CryptoError::DecryptionFailed)?;

        let req_body = DecryptRequest {
            ciphertext: ciphertext_str.to_string(),
            context: context_str,
        };

        let res = self
            .client
            .post(&url)
            .header("X-Vault-Token", &self.token)
            .json(&req_body)
            .send()
            .await
            .map_err(|e| crate::manager::crypto_manager::CryptoError::KmsFailed(e.to_string()))?;

        if !res.status().is_success() {
            return Err(crate::manager::crypto_manager::CryptoError::DecryptionFailed);
        }

        let resp_json: VaultResponse = res.json().await
            .map_err(|e| crate::manager::crypto_manager::CryptoError::KmsFailed(e.to_string()))?;
        let b64_plaintext = resp_json
            .data
            .plaintext
            .ok_or(crate::manager::crypto_manager::CryptoError::DecryptionFailed)?;

        let decoded = base64_standard.decode(&b64_plaintext)
            .map_err(|_| crate::manager::crypto_manager::CryptoError::DecryptionFailed)?;
        Ok(decoded)
    }
}
