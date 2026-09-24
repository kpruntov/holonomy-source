// @trace TASK-085
use reqwest::Client;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Configuration Error: {0}")]
    Config(String),
    #[error("I/O Error: {0}")]
    Io(#[from] std::io::Error),
    #[error("HTTP Error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Protocol Error: {0}")]
    Protocol(String),
}

pub fn get_credentials_path(config: &holonomy_core::config::resolver::ResolvedConfiguration) -> Result<PathBuf, AuthError> {
    if let Some(cred_file) = &config.auth.credential_file
        && !cred_file.is_empty() {
            return Ok(PathBuf::from(cred_file));
        }

    let home_dir = dirs::home_dir().ok_or_else(|| {
        AuthError::Config("Could not determine HOME directory".to_string())
    })?;

    Ok(home_dir.join(".holonomy").join("credentials"))
}

pub async fn perform_login() -> Result<(), AuthError> {
    // @trace TASK-130
    let config = holonomy_core::config::resolver::get_config();
    perform_login_with_config(config).await
}

pub fn perform_logout() -> Result<(), AuthError> {
    // @trace TASK-134
    let config = holonomy_core::config::resolver::get_config();
    perform_logout_with_config(config)
}

pub fn perform_logout_with_config(config: &holonomy_core::config::resolver::ResolvedConfiguration) -> Result<(), AuthError> {
    let credentials_path = get_credentials_path(config)?;

    if credentials_path.exists() {
        fs::remove_file(&credentials_path)?;
        println!("Successfully logged out. Credentials removed.");
    } else {
        println!("Not logged in (no credentials file found).");
    }

    Ok(())
}

pub async fn perform_login_with_config(config: &holonomy_core::config::resolver::ResolvedConfiguration) -> Result<(), AuthError> {

    let credentials_path = get_credentials_path(config)?;

    // 1. Check for existing credential file fallback
    if credentials_path.exists() {
        // If it's a non-interactive provided file from config, print a special message
        if config.auth.credential_file.is_some() {
            println!(
                "Non-interactive auth using configured credential file: {:?}",
                credentials_path
            );
            return Ok(());
        }
    }

    // 2. Setup environment variables for OIDC
    let issuer = config.auth.issuer.clone();
    if issuer.is_empty() {
        return Err(AuthError::Config("HOLONOMY_ISSUER must be set".to_string()));
    }
    let client_id = if config.auth.client_id.is_empty() {
        "holonomy-cli".to_string()
    } else {
        config.auth.client_id.clone()
    };

    let device_auth_url = format!("{}/protocol/openid-connect/auth/device", issuer);
    let token_url = format!("{}/protocol/openid-connect/token", issuer);

    let client = Client::new();

    // PKCE: Generate code_verifier and code_challenge
    use rand::Rng;
    use sha2::{Sha256, Digest};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    let mut verifier_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut verifier_bytes);
    let code_verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);
    
    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let code_challenge = URL_SAFE_NO_PAD.encode(hasher.finalize());

    // 3. Initiate Device Authorization
    let res = client
        .post(&device_auth_url)
        .form(&[
            ("client_id", client_id.as_str()),
            ("code_challenge", &code_challenge),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await?;

    if !res.status().is_success() {
        return Err(AuthError::Protocol(format!(
            "Device authorization failed: {}",
            res.status()
        )));
    }

    let device_auth: Value = res.json().await?;

    let device_code = device_auth
        .get("device_code")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AuthError::Protocol("Missing device_code".to_string()))?;
    let user_code = device_auth
        .get("user_code")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AuthError::Protocol("Missing user_code".to_string()))?;
    let verification_uri = device_auth
        .get("verification_uri_complete")
        .or_else(|| device_auth.get("verification_uri"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| AuthError::Protocol("Missing verification_uri".to_string()))?;
    let mut interval = device_auth
        .get("interval")
        .and_then(|v| v.as_u64())
        .unwrap_or(5);

    println!("Initiating OIDC Device Authorization Flow...");
    println!("Please visit: {}", verification_uri);
    println!("Enter code if prompted: {}", user_code);
    println!("Waiting for authorization...");

    // 4. Poll for token
    loop {
        tokio::time::sleep(Duration::from_secs(interval)).await;

        let token_res = client
            .post(&token_url)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("client_id", &client_id),
                ("device_code", device_code),
                ("code_verifier", &code_verifier),
            ])
            .send()
            .await;

        match token_res {
            Ok(response) => {
                let status = response.status();
                let token_data: Value = response.json().await.unwrap_or(serde_json::json!({}));

                if status.is_success() {
                    if let Some(access_token) =
                        token_data.get("access_token").and_then(|v| v.as_str())
                    {
                        if let Some(parent) = credentials_path.parent()
                            && !parent.exists() {
                                fs::create_dir_all(parent)?;
                            }
                        fs::write(&credentials_path, access_token)?;

                        println!(
                            "Successfully logged in. Credentials saved to {:?}",
                            credentials_path
                        );
                        return Ok(());
                    } else {
                        return Err(AuthError::Protocol(
                            "Token response missing access_token".to_string(),
                        ));
                    }
                } else if let Some(err) = token_data.get("error").and_then(|v| v.as_str()) {
                    if err == "authorization_pending" {
                        continue;
                    } else if err == "slow_down" {
                        interval += 5;
                        continue;
                    } else {
                        return Err(AuthError::Protocol(format!(
                            "Authorization failed: {}",
                            err
                        )));
                    }
                } else {
                    return Err(AuthError::Protocol(format!(
                        "Token fetch failed with status: {}",
                        status
                    )));
                }
            }
            Err(e) => {
                println!("Error polling for token: {}. Retrying...", e);
            }
        }
    }
}
