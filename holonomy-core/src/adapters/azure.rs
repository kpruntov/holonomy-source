// @trace TASK-026
use azure_storage::StorageCredentials;
use azure_storage_blobs::prelude::*;
use futures::StreamExt;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AzureAdapterError {
    #[error("Azure SDK error: {0}")]
    SdkError(#[from] azure_core::Error),
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

pub struct AzureAdapter {
    client: BlobServiceClient,
}

impl AzureAdapter {
    pub fn new(
        account: &str,
        key: &str,
        endpoint: Option<&str>,
    ) -> Result<Self, AzureAdapterError> {
        let creds = StorageCredentials::access_key(account.to_string(), key.to_string());
        let builder = BlobServiceClient::builder(account, creds);
        let client = if let Some(ep) = endpoint {
            let url = reqwest::Url::parse(ep)
                .map_err(|e| AzureAdapterError::ConfigError(e.to_string()))?;
            let address = url.host_str().unwrap_or("127.0.0.1").to_string();
            let port = url.port().unwrap_or(10000);
            let loc = azure_storage::CloudLocation::Emulator { address, port };
            builder.cloud_location(loc).blob_service_client()
        } else {
            builder.blob_service_client()
        };
        Ok(Self { client })
    }

    pub async fn create_container(&self, container: &str) -> Result<(), AzureAdapterError> {
        let container_client = self.client.container_client(container);
        container_client.create().await?;
        Ok(())
    }

    pub async fn upload(
        &self,
        container: &str,
        blob_name: &str,
        data: Vec<u8>,
    ) -> Result<(), AzureAdapterError> {
        let container_client = self.client.container_client(container);
        let blob_client = container_client.blob_client(blob_name);
        blob_client.put_block_blob(data).await?;
        Ok(())
    }

    pub async fn download(
        &self,
        container: &str,
        blob_name: &str,
    ) -> Result<Vec<u8>, AzureAdapterError> {
        let container_client = self.client.container_client(container);
        let blob_client = container_client.blob_client(blob_name);
        let mut stream = blob_client.get().into_stream();
        let mut data = Vec::new();
        while let Some(res) = stream.next().await {
            let res = res?;
            data.extend_from_slice(&res.data.collect().await?);
        }
        Ok(data)
    }

    pub async fn fetch_byte_range(
        &self,
        container: &str,
        blob_name: &str,
        start: u64,
        length: u64,
    ) -> Result<Vec<u8>, AzureAdapterError> {
        let container_client = self.client.container_client(container);
        let blob_client = container_client.blob_client(blob_name);
        let mut stream = blob_client.get().range(start..start + length).into_stream();
        let mut data = Vec::new();
        while let Some(res) = stream.next().await {
            let res = res?;
            data.extend_from_slice(&res.data.collect().await?);
        }
        Ok(data)
    }
}
