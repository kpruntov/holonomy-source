// @trace TASK-039
use aws_config::BehaviorVersion;
use aws_sdk_s3::Client as S3Client;
use holonomy_core::crypto::pme_encrypt::StreamItem;
use holonomy_core::crypto::pme_encrypt::{S3MultipartUploader, StorageUploader};
use testcontainers::{ImageExt, core::ContainerPort, runners::AsyncRunner};
use testcontainers_modules::localstack::LocalStack;
use tokio::sync::mpsc;

// @trace TASK-098
#[tokio::test]
#[ignore]
async fn test_multipart_streaming() {
    let image = LocalStack::default()
        .with_tag("3.8.0")
        .with_env_var("SERVICES", "s3")
        .with_mapped_port(4566, ContainerPort::Tcp(4566));
    let _container = image.start().await.expect("Failed to start localstack");

    let endpoint_url = "http://127.0.0.1:4566".to_string();

    // S3 setup
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

    let s3_client = S3Client::new(&config);
    let bucket_name = "test-bucket-stream";
    s3_client
        .create_bucket()
        .bucket(bucket_name)
        .send()
        .await
        .expect("Failed to create bucket");

    let uploader = S3MultipartUploader::new(
        bucket_name.to_string(),
        Some(endpoint_url),
        Some("us-east-1".to_string()),
        Some(5 * 1024 * 1024),
        Some(("mock".to_string(), "mock".to_string())),
    )
    .await;

    let (tx, rx) = mpsc::channel(10);

    // Spawn task to send chunks
    tokio::spawn(async move {
        // Send three 5MB chunks (Multipart requires >5MB for parts except last)
        for _ in 0..3 {
            tx.send(StreamItem::Data(vec![0u8; 5 * 1024 * 1024]))
                .await
                .unwrap();
        }
        // Send a smaller final chunk
        tx.send(StreamItem::Data(vec![1u8; 1024])).await.unwrap();
        // Send success signal
        tx.send(StreamItem::Success).await.unwrap();
    });

    let result = uploader.upload_stream("streaming_test.parquet", rx).await;
    assert!(result.is_ok(), "Upload stream failed: {:?}", result.err());

    // Verify object exists
    let head_res = s3_client
        .head_object()
        .bucket(bucket_name)
        .key("streaming_test.parquet")
        .send()
        .await;
    assert!(
        head_res.is_ok(),
        "File should exist in S3 after streaming upload"
    );
}

// @trace TASK-099
#[tokio::test]
#[ignore]
async fn test_multipart_drop_guard_cleans_up() {
    let image = LocalStack::default()
        .with_tag("3.8.0")
        .with_env_var("SERVICES", "s3")
        .with_mapped_port(4566, ContainerPort::Tcp(4566));
    let _container = image.start().await.expect("Failed to start localstack");

    let endpoint_url = "http://127.0.0.1:4566".to_string();

    // S3 setup
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

    let s3_client = S3Client::new(&config);
    let bucket_name = "test-drop-guard";
    s3_client
        .create_bucket()
        .bucket(bucket_name)
        .send()
        .await
        .expect("Failed to create bucket");

    let uploader = S3MultipartUploader::new(
        bucket_name.to_string(),
        Some(endpoint_url),
        Some("us-east-1".to_string()),
        Some(5 * 1024 * 1024),
        Some(("mock".to_string(), "mock".to_string())),
    )
    .await;

    let (tx, rx) = mpsc::channel(10);
    tx.send(StreamItem::Data(vec![0u8; 5 * 1024 * 1024]))
        .await
        .unwrap();

    let upload_fut = uploader.upload_stream("dropped_test.parquet", rx);

    // Use tokio::time::timeout to drop the future while it's waiting for more data
    let res = tokio::time::timeout(std::time::Duration::from_millis(500), upload_fut).await;
    assert!(res.is_err(), "Future should timeout and be dropped");

    // Wait a brief moment for the drop task to execute its abort request in the background
    tokio::time::sleep(std::time::Duration::from_millis(1000)).await;

    // Verify no active multipart uploads remain
    let uploads = s3_client
        .list_multipart_uploads()
        .bucket(bucket_name)
        .send()
        .await
        .unwrap();

    // uploads() returns a slice of active uploads
    let active_uploads_count = uploads.uploads().len();
    assert_eq!(
        active_uploads_count, 0,
        "Drop guard failed to abort the upload"
    );
}
