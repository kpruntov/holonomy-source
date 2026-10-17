// @trace TASK-023
// @trace TASK-063
// @trace FR-002
use aws_config::BehaviorVersion;
use aws_sdk_kms::Client as KmsClient;
use aws_sdk_kms::types::KeySpec;
use aws_sdk_kms::types::KeyUsageType;
use aws_sdk_s3::Client as S3Client;
use aws_smithy_types::Blob;
use holonomy_core::adapters::aws::AwsAdapter;
use testcontainers::{ImageExt, core::ContainerPort, runners::AsyncRunner};
use testcontainers_modules::localstack::LocalStack;

#[tokio::test]
#[ignore]
async fn test_aws_kms_and_s3_localstack() {
    let image = LocalStack::default()
        .with_tag("3.8.0")
        .with_env_var("SERVICES", "s3,kms")
        .with_mapped_port(4566, ContainerPort::Tcp(4566));
    let _container = image.start().await.expect("Failed to start localstack");

    let endpoint_url = "http://127.0.0.1:4566".to_string();

    // Create custom AWS config pointing to LocalStack
    let config = aws_config::defaults(BehaviorVersion::latest())
        .endpoint_url(&endpoint_url)
        .region(aws_config::Region::new("us-east-1"))
        .credentials_provider(aws_credential_types::Credentials::new(
            "test",
            "test",
            None,
            None,
            "localstack",
        ))
        .load()
        .await;

    // S3 setup
    let s3_client = S3Client::new(&config);
    let bucket_name = "test-bucket";
    s3_client
        .create_bucket()
        .bucket(bucket_name)
        .send()
        .await
        .expect("Failed to create bucket");

    // KMS setup
    let kms_client = KmsClient::new(&config);
    let create_key_res = kms_client
        .create_key()
        .key_usage(KeyUsageType::EncryptDecrypt)
        .key_spec(KeySpec::SymmetricDefault)
        .send()
        .await
        .expect("Failed to create key");
    let key_id = create_key_res.key_metadata.unwrap().key_id;

    let plaintext = b"secret data";

    // Encrypt directly via KMS client
    let encrypt_res = kms_client
        .encrypt()
        .key_id(key_id.clone())
        .plaintext(Blob::new(plaintext))
        .send()
        .await
        .expect("Failed to encrypt");

    let ciphertext = encrypt_res.ciphertext_blob.unwrap().into_inner();

    let adapter = AwsAdapter::new(&config, key_id.clone());

    // Test KMS decrypt
    let decrypted = adapter
        .decrypt(&ciphertext, None)
        .await
        .expect("Failed to decrypt");
    assert_eq!(plaintext.as_slice(), decrypted.as_slice());

    // Test KmsProvider trait directly (TASK-063)
    use holonomy_core::manager::crypto_manager::KmsProvider;
    let decrypted_dek = adapter
        .decrypt_dek(&ciphertext, None)
        .await
        .expect("Failed to decrypt_dek via trait");
    assert_eq!(plaintext.as_slice(), decrypted_dek.as_slice());

    // Test KmsProvider trait wrap_key
    let wrapped_dek = adapter
        .wrap_key(plaintext.as_slice(), None)
        .await
        .expect("Failed to wrap_key via trait");
    let unwrapped_dek = adapter
        .decrypt_dek(&wrapped_dek, None)
        .await
        .expect("Failed to decrypt_dek the newly wrapped key");
    assert_eq!(plaintext.as_slice(), unwrapped_dek.as_slice());

    // Test S3 upload and download
    let key_name = "test-file.txt";
    adapter
        .upload(bucket_name, key_name, b"hello s3".to_vec())
        .await
        .expect("Failed to upload");

    let downloaded = adapter
        .download(bucket_name, key_name)
        .await
        .expect("Failed to download");
    assert_eq!(b"hello s3".as_slice(), downloaded.as_slice());
}
