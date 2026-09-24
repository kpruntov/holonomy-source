// @trace TASK-051
use holonomy_core::schema::s3_list::list_s3_objects;
use mockito::Server;
use reqwest::Client;

#[tokio::test]
async fn test_s3_traversal() {
    let mut server = Server::new_async().await;
    let url = server.url();

    let mock_xml = r#"
        <ListBucketResult>
            <IsTruncated>false</IsTruncated>
            <Contents>
                <Key>data1.parquet</Key>
            </Contents>
            <Contents>
                <Key>data2.parquet</Key>
            </Contents>
            <Contents>
                <Key>ignore.txt</Key>
            </Contents>
        </ListBucketResult>
    "#;

    let mock = server
        .mock("GET", "/?list-type=2&prefix=folder/")
        .with_status(200)
        .with_body(mock_xml)
        .create_async()
        .await;

    let client = Client::new();
    let objects = list_s3_objects(&client, "s3://test-bucket/folder/", 50, Some(&url))
        .await
        .unwrap();

    assert_eq!(objects.len(), 2);
    assert_eq!(objects[0], "s3://test-bucket/data1.parquet");
    assert_eq!(objects[1], "s3://test-bucket/data2.parquet");

    mock.assert_async().await;
}
