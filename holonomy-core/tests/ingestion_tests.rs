// @trace TASK-010
use holonomy_core::ingestion::s3_client::{IngestionProvider, S3Client};
use mockito::Server;
use parquet::file::properties::WriterProperties;
use parquet::file::writer::SerializedFileWriter;
use parquet::schema::parser::parse_message_type;
use std::sync::Arc;

fn generate_empty_parquet() -> Vec<u8> {
    let schema_str = "message schema { OPTIONAL INT32 col1; }";
    let schema = Arc::new(parse_message_type(schema_str).unwrap());
    let props = Arc::new(WriterProperties::builder().build());
    let mut buf = Vec::new();
    {
        let writer = SerializedFileWriter::new(&mut buf, schema, props).unwrap();
        writer.close().unwrap();
    }
    buf
}

#[tokio::test]
async fn test_fetch_parquet_metadata() {
    let mut server = Server::new_async().await;
    let file_data = generate_empty_parquet();

    // We serve the speculative fetch
    let mock_speculative = server
        .mock("GET", "/test.parquet")
        .match_header("Range", "bytes=-65536")
        .with_status(206)
        .with_body(&file_data)
        .create_async()
        .await;

    let client = S3Client::new(None);
    let url = format!("{}/test.parquet", server.url());

    let metadata = client
        .fetch_parquet_metadata(&url, None)
        .await
        .expect("Failed to fetch metadata");

    assert_eq!(metadata.file_metadata().num_rows(), 0);
    mock_speculative.assert_async().await;
}

#[tokio::test]
async fn test_fetch_multiple_ranges() {
    let mut server = Server::new_async().await;
    let file_data = b"Hello, World! Parquet chunks here.";

    let mock1 = server
        .mock("GET", "/data")
        .match_header("Range", "bytes=0-4")
        .with_status(206)
        .with_body(&file_data[0..5])
        .create_async()
        .await;

    let mock2 = server
        .mock("GET", "/data")
        .match_header("Range", "bytes=7-11")
        .with_status(206)
        .with_body(&file_data[7..12])
        .create_async()
        .await;

    let client = S3Client::new(None);
    let url = format!("{}/data", server.url());
    let ranges = vec![0..5, 7..12];

    let results = client.fetch_multiple_ranges(&url, ranges).await.unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(&results[0][..], b"Hello");
    assert_eq!(&results[1][..], b"World");

    mock1.assert_async().await;
    mock2.assert_async().await;
}

#[tokio::test]
async fn test_parse_url() {
    let client = S3Client::new(None);

    let s3_parsed = client
        .parse_url("s3://my-bucket/path/to/file.parquet")
        .unwrap();
    assert_eq!(s3_parsed.bucket, "my-bucket");
    assert_eq!(s3_parsed.key, "path/to/file.parquet");
    assert_eq!(
        s3_parsed.http_url,
        "https://my-bucket.s3.us-east-1.amazonaws.com/path/to/file.parquet"
    );

    let http_parsed = client
        .parse_url("https://my-minio.com/example-bucket/path/to/file.parquet")
        .unwrap();
    assert_eq!(http_parsed.bucket, "example-bucket");
    assert_eq!(http_parsed.key, "path/to/file.parquet");
    assert_eq!(
        http_parsed.http_url,
        "https://my-minio.com/example-bucket/path/to/file.parquet"
    );

    let r2_parsed = client.parse_url("r2://my-bucket/path.parquet").unwrap();
    assert_eq!(r2_parsed.bucket, "my-bucket");
    assert_eq!(r2_parsed.key, "path.parquet");
    assert_eq!(
        r2_parsed.http_url,
        "https://unknown_account.r2.cloudflarestorage.com/my-bucket/path.parquet"
    );
}
