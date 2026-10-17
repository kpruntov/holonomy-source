// @trace TASK-044
use holonomy_core::schema::footer::fetch_parquet_metadata;
use mockito::Server;

#[tokio::test]
async fn test_fetch_metadata_range_requests() {
    let mut server = Server::new_async().await;
    let url = server.url();

    let mock_8bytes = server
        .mock("GET", "/")
        .match_header("Range", "bytes=-8")
        .with_status(206)
        .with_body(vec![16, 0, 0, 0, b'P', b'A', b'R', b'1'])
        .create_async()
        .await;

    let mock_24bytes = server
        .mock("GET", "/")
        .match_header("Range", "bytes=-24")
        .with_status(206)
        .with_body(vec![0; 24]) // dummy body
        .create_async()
        .await;

    let client = reqwest::Client::new();
    let res = fetch_parquet_metadata(None, Some(&client), &url).await;

    assert!(res.is_err());

    mock_8bytes.assert_async().await;
    mock_24bytes.assert_async().await;
}

#[tokio::test]
async fn test_fetch_metadata_invalid_magic() {
    let mut server = Server::new_async().await;
    let url = server.url();

    let mock_8bytes = server
        .mock("GET", "/")
        .match_header("Range", "bytes=-8")
        .with_status(206)
        .with_body(vec![16, 0, 0, 0, b'I', b'N', b'V', b'L'])
        .create_async()
        .await;

    let client = reqwest::Client::new();
    let res = fetch_parquet_metadata(None, Some(&client), &url).await;

    assert!(res.is_err());
    assert!(
        res.unwrap_err()
            .to_string()
            .contains("Invalid magic number")
    );

    mock_8bytes.assert_async().await;
}
