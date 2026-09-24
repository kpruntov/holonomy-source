// @trace TASK-085
// @trace TASK-134
use crate::cli::Cli;
use clap::Parser;
use serial_test::serial;
use std::fs;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tempfile::NamedTempFile;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
#[serial]
async fn test_auth_login_args() {
    let args = vec!["holonomy", "auth", "login"];
    let result = Cli::try_parse_from(args);
    assert!(
        result.is_ok(),
        "Failed to parse auth login subcommand: {:?}",
        result.err()
    );
}

#[tokio::test]
#[serial]
async fn test_fallback_token_file() {
    let temp_file = NamedTempFile::new().unwrap();
    fs::write(temp_file.path(), "test-token").unwrap();

    let mut config = holonomy_core::config::resolver::ResolvedConfiguration::default();
    config.auth.credential_file = Some(temp_file.path().to_str().unwrap().to_string());

    let result = crate::cmd_auth::perform_login_with_config(&config).await;
    assert!(result.is_ok());
}

#[tokio::test]
#[serial]
async fn test_oidc_device_flow() {
    let mock_server = MockServer::start().await;

    let device_auth_resp = serde_json::json!({
        "device_code": "dc123",
        "user_code": "uc123",
        "verification_uri_complete": format!("{}/verify", mock_server.uri()),
        "interval": 1
    });

    Mock::given(method("POST"))
        .and(path("/protocol/openid-connect/auth/device"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&device_auth_resp))
        .mount(&mock_server)
        .await;

    let poll_count = Arc::new(AtomicUsize::new(0));
    let poll_count_clone = poll_count.clone();

    // Wiremock custom responder to simulate authorization_pending then success
    let token_mock = Mock::given(method("POST"))
        .and(path("/protocol/openid-connect/token"))
        .respond_with(move |_: &wiremock::Request| {
            let count = poll_count_clone.fetch_add(1, Ordering::SeqCst);
            if count < 1 {
                ResponseTemplate::new(400).set_body_json(serde_json::json!({
                    "error": "authorization_pending"
                }))
            } else {
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "mocked-access-token",
                    "id_token": "mocked-id-token"
                }))
            }
        });

    mock_server.register(token_mock).await;

    let temp_home = tempfile::tempdir().unwrap();
    let creds_path = temp_home.path().join("credentials");

    let mut config = holonomy_core::config::resolver::ResolvedConfiguration::default();
    config.auth.issuer = mock_server.uri();
    config.auth.client_id = "test-client".to_string();
    config.auth.credential_file = Some(creds_path.to_str().unwrap().to_string());

    let result = crate::cmd_auth::perform_login_with_config(&config).await;
    assert!(result.is_ok());

    assert!(creds_path.exists());
    assert_eq!(
        fs::read_to_string(creds_path).unwrap(),
        "mocked-access-token"
    );
}

#[tokio::test]
#[serial]
async fn test_auth_logout_success() {
    let temp_dir = tempfile::tempdir().unwrap();
    let creds_path = temp_dir.path().join("credentials");
    fs::write(&creds_path, "test-token").unwrap();

    let mut config = holonomy_core::config::resolver::ResolvedConfiguration::default();
    config.auth.credential_file = Some(creds_path.to_str().unwrap().to_string());

    assert!(creds_path.exists());
    let result = crate::cmd_auth::perform_logout_with_config(&config);
    assert!(result.is_ok());
    assert!(!creds_path.exists());
}

#[tokio::test]
#[serial]
async fn test_auth_logout_no_file() {
    let temp_dir = tempfile::tempdir().unwrap();
    let creds_path = temp_dir.path().join("credentials");

    let mut config = holonomy_core::config::resolver::ResolvedConfiguration::default();
    config.auth.credential_file = Some(creds_path.to_str().unwrap().to_string());

    assert!(!creds_path.exists());
    let result = crate::cmd_auth::perform_logout_with_config(&config);
    // Should succeed gracefully if file doesn't exist
    assert!(result.is_ok()); 
}
