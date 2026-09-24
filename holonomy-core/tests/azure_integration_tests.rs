// @trace TASK-026
// @trace TASK-032
use holonomy_core::adapters::azure::AzureAdapter;
use testcontainers::{GenericImage, ImageExt, runners::AsyncRunner};

#[tokio::test]
#[ignore]
async fn test_azure_adapter_upload_download_range() {
    let image = GenericImage::new("mcr.microsoft.com/azure-storage/azurite", "latest")
        .with_wait_for(testcontainers::core::WaitFor::message_on_stdout(
            "Azurite Blob service is successfully listening",
        ))
        .with_mapped_port(10000, testcontainers::core::ContainerPort::Tcp(10000))
        .with_cmd([
            "azurite",
            "--loose",
            "--blobHost",
            "0.0.0.0",
            "--blobPort",
            "10000",
        ]);

    let _container = image.start().await.expect("Failed to start Azurite");
    let endpoint = "http://127.0.0.1:10000/devstoreaccount1".to_string();

    let account = "devstoreaccount1";
    let key =
        "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";

    let adapter =
        AzureAdapter::new(account, key, Some(&endpoint)).expect("Failed to create adapter");

    let container_name = "testcontainer";
    let blob_name = "testblob.txt";

    adapter
        .create_container(container_name)
        .await
        .expect("Failed to create container");

    let data = b"Hello, Azure Blob Storage! This is a test for byte range fetches.".to_vec();
    adapter
        .upload(container_name, blob_name, data.clone())
        .await
        .expect("Failed to upload");

    let downloaded = adapter
        .download(container_name, blob_name)
        .await
        .expect("Failed to download");
    assert_eq!(data, downloaded);

    // Fetch range: "Azure" (start: 7, length: 5)
    let range = adapter
        .fetch_byte_range(container_name, blob_name, 7, 5)
        .await
        .expect("Failed to fetch range");
    assert_eq!(b"Azure".to_vec(), range);
}
