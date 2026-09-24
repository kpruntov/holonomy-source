// @trace TASK-038
use holonomy_core::crypto::pme_encrypt::PmeEncryptor;
use zeroize::Zeroizing;

#[test]
fn test_pme_encryptor_wraps_dek() {
    let footer_dek = Zeroizing::new(b"1234567890123456".to_vec());
    let wrapped_footer_dek = b"kms_wrapped:base64_encoded_stuff".to_vec();

    let mut column_deks = std::collections::HashMap::new();
    column_deks.insert(
        "col1".to_string(),
        Zeroizing::new(b"abcdefghijklmnop".to_vec()),
    );

    let mut wrapped_column_deks = std::collections::HashMap::new();
    wrapped_column_deks.insert("col1".to_string(), b"kms_wrapped:abcdefghijklmnop".to_vec());

    let encryptor = PmeEncryptor::new(
        footer_dek,
        wrapped_footer_dek.clone(),
        column_deks,
        wrapped_column_deks,
    );

    let props = encryptor.get_writer_properties_builder().build();

    // Verify that the file encryption properties contain the base64 encoded wrapped DEK
    let enc_props = props
        .file_encryption_properties()
        .expect("Should have file encryption properties");
    let footer_metadata = enc_props
        .footer_key_metadata()
        .expect("Should have footer key metadata");

    use base64::{Engine as _, engine::general_purpose::STANDARD as base64_standard};
    let expected_val = base64_standard.encode(&wrapped_footer_dek).into_bytes();
    assert_eq!(footer_metadata, expected_val.as_slice());
    assert_ne!(footer_metadata, b"1234567890123456");
}
