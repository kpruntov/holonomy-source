// @trace TASK-021
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::convert::TryFrom;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SignerError {
    #[error("Invalid key length: {0}")]
    InvalidKeyLength(usize),
    #[error("Invalid signature format")]
    InvalidSignatureFormat,
    #[error("Signature verification failed")]
    VerificationFailed,
    #[error("Signature generation failed")]
    SigningFailed,
}

pub fn sign_manifest(
    manifest_content: &str,
    private_key: &[u8; 32],
) -> Result<String, SignerError> {
    let signing_key = SigningKey::from_bytes(private_key);
    let signature = signing_key.sign(manifest_content.as_bytes());
    Ok(hex::encode(signature.to_bytes()))
}

pub fn get_public_key_hex(private_key: &[u8; 32]) -> String {
    let signing_key = SigningKey::from_bytes(private_key);
    let verifying_key = signing_key.verifying_key();
    hex::encode(verifying_key.to_bytes())
}

pub fn verify_manifest(
    manifest_content: &str,
    signature_hex: &str,
    public_key: &[u8; 32],
) -> Result<(), SignerError> {
    let verifying_key = VerifyingKey::from_bytes(public_key)
        .map_err(|_| SignerError::InvalidKeyLength(public_key.len()))?;

    let sig_bytes = hex::decode(signature_hex).map_err(|_| SignerError::InvalidSignatureFormat)?;

    let signature = Signature::try_from(sig_bytes.as_slice())
        .map_err(|_| SignerError::InvalidSignatureFormat)?;

    verifying_key
        .verify(manifest_content.as_bytes(), &signature)
        .map_err(|_| SignerError::VerificationFailed)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn test_sign_and_verify_success() {
        let secret = [1u8; 32];
        let signing_key = SigningKey::from_bytes(&secret);
        let verifying_key = signing_key.verifying_key();

        let manifest = r#"{"policy": "allow"}"#;

        let signature_hex = sign_manifest(manifest, signing_key.as_bytes()).unwrap();
        let result = verify_manifest(manifest, &signature_hex, verifying_key.as_bytes());

        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_failure_tampered() {
        let secret = [1u8; 32];
        let signing_key = SigningKey::from_bytes(&secret);
        let verifying_key = signing_key.verifying_key();

        let manifest = r#"{"policy": "allow"}"#;
        let signature_hex = sign_manifest(manifest, signing_key.as_bytes()).unwrap();

        let tampered_manifest = r#"{"policy": "deny"}"#;
        let result = verify_manifest(tampered_manifest, &signature_hex, verifying_key.as_bytes());

        assert!(matches!(result, Err(SignerError::VerificationFailed)));
    }
}
