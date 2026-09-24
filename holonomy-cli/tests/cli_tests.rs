// @trace TASK-021
use ed25519_dalek::SigningKey;
use std::io::Write;
use std::process::Command;
use tempfile::NamedTempFile;

#[test]
fn test_cli_sign_and_verify() {
    let secret = [1u8; 32];
    let signing_key = SigningKey::from_bytes(&secret);
    let verifying_key = signing_key.verifying_key();

    // Format to hex using core functionality or standard
    let priv_hex = hex::encode(signing_key.to_bytes());
    let pub_hex = hex::encode(verifying_key.to_bytes());

    // Create temp manifest
    let mut manifest_file = NamedTempFile::new().expect("Failed to create temp file");
    write!(manifest_file, r#"{{"policy": "allow"}}"#).unwrap();
    let manifest_path = manifest_file.path().to_str().unwrap();

    let bin_path = env!("CARGO_BIN_EXE_holonomy-cli");

    // Test sign
    let sign_output = Command::new(bin_path)
        .args(["sign", manifest_path, "--key", &priv_hex])
        .output()
        .expect("Failed to run sign");

    assert!(
        sign_output.status.success(),
        "Sign failed: {:?}",
        String::from_utf8_lossy(&sign_output.stderr)
    );
    let stdout_str = String::from_utf8_lossy(&sign_output.stdout);
    let signature = stdout_str
        .lines()
        .find(|l| l.starts_with("Signature: "))
        .map(|l| l.replace("Signature: ", "").trim().to_string())
        .expect("Could not find signature in output");

    // Test verify success
    let verify_output = Command::new(bin_path)
        .args(["verify", manifest_path, &pub_hex, "--signature", &signature])
        .output()
        .expect("Failed to run verify");

    assert!(
        verify_output.status.success(),
        "Verify failed: {:?}",
        String::from_utf8_lossy(&verify_output.stderr)
    );

    // Test verify failure (tampered manifest)
    let mut tampered_manifest_file = NamedTempFile::new().expect("Failed to create temp file");
    write!(tampered_manifest_file, r#"{{"policy": "deny"}}"#).unwrap();
    let tampered_path = tampered_manifest_file.path().to_str().unwrap();

    let verify_tampered = Command::new(bin_path)
        .args(["verify", tampered_path, &pub_hex, "--signature", &signature])
        .output()
        .expect("Failed to run verify tampered");

    assert!(!verify_tampered.status.success());
}
