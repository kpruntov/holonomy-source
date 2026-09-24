// @trace TASK-024
// @trace TASK-095
use holonomy_core::adapters::vault::VaultAdapter;
use reqwest::Client;
use testcontainers::{
    GenericImage, ImageExt,
    core::{ContainerPort, WaitFor},
    runners::AsyncRunner,
};

#[tokio::test]
#[ignore]
async fn test_vault_transit_engine() {
    let image = GenericImage::new("docker.io/hashicorp/vault", "latest")
        .with_wait_for(WaitFor::message_on_stdout(
            "Development mode should NOT be used in production installations!",
        ))
        .with_env_var("VAULT_DEV_ROOT_TOKEN_ID", "myroot")
        .with_mapped_port(8200, ContainerPort::Tcp(8200));

    let _container = image.start().await.expect("Failed to start Vault");

    let endpoint_url = "http://127.0.0.1:8200";
    let token = "myroot";

    // Setup transit engine first
    let client = Client::new();
    let mount_url = format!("{}/v1/sys/mounts/transit", endpoint_url);
    let mount_res = client
        .post(&mount_url)
        .header("X-Vault-Token", token)
        .json(&serde_json::json!({"type": "transit"}))
        .send()
        .await
        .expect("Failed to mount transit engine");

    assert!(mount_res.status().is_success() || mount_res.status().as_u16() == 400);

    // Create key
    let key_url = format!("{}/v1/transit/keys/my-test-key", endpoint_url);
    let key_res = client
        .post(&key_url)
        .header("X-Vault-Token", token)
        .send()
        .await
        .expect("Failed to create transit key");
    assert!(key_res.status().is_success() || key_res.status().as_u16() == 204);

    let vault_adapter = VaultAdapter::new(endpoint_url.to_string(), token.to_string(), "my-test-key".to_string());

    let original_plaintext = b"Hello from Vault Transit!";

    use holonomy_core::manager::crypto_manager::KmsProvider;

    let ciphertext = vault_adapter
        .wrap_key(original_plaintext, None)
        .await
        .unwrap();
    let ciphertext_str = std::str::from_utf8(&ciphertext).unwrap();
    assert!(ciphertext_str.starts_with("vault:v1:"));

    let decrypted_plaintext = vault_adapter
        .decrypt_dek(&ciphertext, None)
        .await
        .unwrap();
    assert_eq!(decrypted_plaintext, original_plaintext);
}
