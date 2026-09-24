// @trace TASK-064
// @trace FR-002
use base64::{Engine as _, engine::general_purpose::STANDARD as base64_standard};
use holonomy_core::adapters::gcp::GcpAdapter;
use holonomy_core::manager::crypto_manager::KmsProvider;
use mockito::Server;
use std::collections::HashMap;

#[tokio::test]
#[ignore]
async fn test_gcp_kms_mock_server() {
    let mut server = Server::new_async().await;
    let endpoint_url = server.url();

    // Implement dummy token provider
    struct DummyProvider;
    #[async_trait::async_trait]
    impl gcp_auth::TokenProvider for DummyProvider {
        async fn token(
            &self,
            _scopes: &[&str],
        ) -> Result<std::sync::Arc<gcp_auth::Token>, gcp_auth::Error> {
            let s = r#"{"access_token":"dummy-token","expires_in":3600}"#;
            let token: gcp_auth::Token = serde_json::from_str(s).unwrap();
            Ok(std::sync::Arc::new(token))
        }
        async fn project_id(&self) -> Result<std::sync::Arc<str>, gcp_auth::Error> {
            Ok("dummy-project".into())
        }
    }

    let key_name = "projects/test/locations/global/keyRings/test/cryptoKeys/test-key";

    let adapter = GcpAdapter::new_with_provider(
        key_name.to_string(),
        endpoint_url,
        std::sync::Arc::new(DummyProvider),
    );

    let plaintext = b"secret dek payload";
    let mock_ciphertext_b64 = "bW9ja19jaXBoZXJ0ZXh0";

    // Mock encrypt endpoint
    let encrypt_mock = server
        .mock("POST", format!("/v1/{}:encrypt", key_name).as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(format!(r#"{{"ciphertext": "{}"}}"#, mock_ciphertext_b64))
        .create_async()
        .await;

    // Mock decrypt endpoint
    let decrypt_mock = server
        .mock("POST", format!("/v1/{}:decrypt", key_name).as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(format!(
            r#"{{"plaintext": "{}"}}"#,
            base64_standard.encode(plaintext)
        ))
        .create_async()
        .await;

    let mut ctx = HashMap::new();
    ctx.insert("purpose".to_string(), "test".to_string());

    // Test wrap_key
    let wrapped = adapter
        .wrap_key(plaintext, Some(&ctx))
        .await
        .expect("Failed wrap_key");
    assert_eq!(wrapped, mock_ciphertext_b64.as_bytes());

    // Test decrypt_dek
    let decrypted = adapter
        .decrypt_dek(&wrapped, Some(&ctx))
        .await
        .expect("Failed decrypt_dek");
    assert_eq!(decrypted, plaintext);

    encrypt_mock.assert_async().await;
    decrypt_mock.assert_async().await;
}
