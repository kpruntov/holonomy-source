// @trace TASK-016
// @trace TASK-040
// @trace TASK-042
use aws_credential_types::Credentials;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
use aws_sdk_s3::{Client as S3Client, primitives::ByteStream};
use parquet::encryption::encrypt::FileEncryptionProperties;

use crate::manager::crypto_manager::CryptoManager;
use moka::future::Cache;
use rand::Rng;
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

// @trace TASK-070
#[derive(Clone)]
pub struct CachedDek {
    pub plaintext: Zeroizing<Vec<u8>>,
    pub wrapped: Vec<u8>,
}

pub struct WriteDekCache {
    pub cache: Cache<String, CachedDek>,
}

impl WriteDekCache {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            cache: Cache::builder()
                .time_to_live(Duration::from_secs(ttl_secs))
                .build(),
        }
    }
}

pub enum StreamItem {
    Data(Vec<u8>),
    Success,
}

pub struct PmeEncryptor {
    pub footer_dek: Zeroizing<Vec<u8>>,
    pub wrapped_footer_dek: Vec<u8>,
    pub column_deks: std::collections::HashMap<String, Zeroizing<Vec<u8>>>,
    pub wrapped_column_deks: std::collections::HashMap<String, Vec<u8>>,
}

impl PmeEncryptor {
    pub fn new(
        footer_dek: Zeroizing<Vec<u8>>,
        wrapped_footer_dek: Vec<u8>,
        column_deks: std::collections::HashMap<String, Zeroizing<Vec<u8>>>,
        wrapped_column_deks: std::collections::HashMap<String, Vec<u8>>,
    ) -> Self {
        Self {
            footer_dek,
            wrapped_footer_dek,
            column_deks,
            wrapped_column_deks,
        }
    }

    pub fn get_writer_properties_builder(
        &self,
    ) -> parquet::file::properties::WriterPropertiesBuilder {
        use base64::Engine;
        let b64_wrapped =
            base64::engine::general_purpose::STANDARD.encode(&self.wrapped_footer_dek);

        // RISK ACCEPTANCE (BR-001 Zero Persistence):
        // The upstream Apache Parquet Rust crate requires a standard `Vec<u8>` for keys.
        // It takes ownership of these vectors and drops them via the global allocator, 
        // bypassing the `Zeroizing` pattern. We accept this known limitation. 
        // The DEK is briefly exposed in Parquet's memory but remains protected in our DekCache.
        let mut builder = FileEncryptionProperties::builder(self.footer_dek.as_slice().to_vec())
            .with_plaintext_footer(true)
            .with_footer_key_metadata(b64_wrapped.into_bytes());

        for (col, dek) in &self.column_deks {
            let wrapped = &self.wrapped_column_deks[col];
            let b64_col_wrapped = base64::engine::general_purpose::STANDARD.encode(wrapped);
            builder = builder.with_column_key_and_metadata(
                col,
                dek.as_slice().to_vec(),
                b64_col_wrapped.into_bytes(),
            );
        }
        let file_encryption = builder.build().unwrap();

        parquet::file::properties::WriterProperties::builder()
            .set_writer_version(parquet::file::properties::WriterVersion::PARQUET_2_0)
            .set_max_row_group_row_count(Some(100))
            .with_file_encryption_properties(file_encryption)
    }

    // @trace TASK-070
    pub async fn generate_or_get_dek(
        crypto_manager: &Arc<CryptoManager>,
        target: &str,
        purpose: &str,
        column_name: &str,
        user_ctx: &str,
    ) -> Result<CachedDek, Box<dyn std::error::Error + Send + Sync>> {
        let cache_key = format!("{}|{}|{}|{}", target, purpose, column_name, user_ctx);

        let dek = crypto_manager
            .write_dek_cache
            .cache
            .try_get_with(cache_key, async {
                let mut raw_key = vec![0u8; 16];
                rand::rng().fill_bytes(&mut raw_key);

                let wrapped = crypto_manager
                    .wrap_key(&raw_key, None)
                    .await
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

                Ok::<CachedDek, Box<dyn std::error::Error + Send + Sync>>(CachedDek {
                    plaintext: Zeroizing::new(raw_key),
                    wrapped,
                })
            })
            .await
            .map_err(|e| {
                Box::new(std::io::Error::other(e.to_string()))
                    as Box<dyn std::error::Error + Send + Sync>
            })?;

        Ok(dek)
    }
}

// @trace TASK-099
pub struct MultipartUploadGuard {
    client: S3Client,
    bucket: String,
    key: String,
    upload_id: String,
    pub completed: bool,
}

impl Drop for MultipartUploadGuard {
    fn drop(&mut self) {
        if !self.completed {
            let client = self.client.clone();
            let bucket = self.bucket.clone();
            let key = self.key.clone();
            let upload_id = self.upload_id.clone();

            tokio::spawn(async move {
                let _ = client
                    .abort_multipart_upload()
                    .bucket(&bucket)
                    .key(&key)
                    .upload_id(&upload_id)
                    .send()
                    .await;
            });
        }
    }
}

pub struct S3MultipartUploader {
    client: S3Client,
    bucket: String,
    chunk_size: usize,
}

#[async_trait::async_trait]
pub trait StorageUploader: Send + Sync {
    async fn upload_stream(
        &self,
        key: &str,
        mut rx: tokio::sync::mpsc::Receiver<StreamItem>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

impl S3MultipartUploader {
    pub async fn new(
        bucket: String,
        endpoint_url: Option<String>,
        region_name: Option<String>,
        chunk_size: Option<usize>,
        credentials: Option<(String, String)>,
    ) -> Self {
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
        if let Some(reg) = region_name {
            loader = loader.region(aws_config::Region::new(reg));
        }
        let sdk_config = loader.load().await;
        
        let mut builder = aws_sdk_s3::config::Builder::from(&sdk_config);

        if let Some(url) = endpoint_url {
            builder = builder
                .endpoint_url(url)
                .force_path_style(true);

            if let Some((access_key, secret_key)) = credentials {
                builder = builder.credentials_provider(Credentials::new(
                    access_key, secret_key, None, None, "injected",
                ));
            }
        }

        let client = S3Client::from_conf(builder.build());
        let chunk_size = chunk_size.unwrap_or(5 * 1024 * 1024); // Default 5MB
        Self {
            client,
            bucket,
            chunk_size,
        }
    }

    // @trace TASK-098
    // @trace TASK-099
    pub async fn upload_file(
        &self,
        key: &str,
        data: Vec<u8>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Step 1: Create multipart upload
        let create_res = self
            .client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .checksum_algorithm(aws_sdk_s3::types::ChecksumAlgorithm::Crc32)
            .send()
            .await?;

        let upload_id = create_res
            .upload_id()
            .ok_or("Missing upload_id")?
            .to_string();

        let mut guard = MultipartUploadGuard {
            client: self.client.clone(),
            bucket: self.bucket.clone(),
            key: key.to_string(),
            upload_id: upload_id.clone(),
            completed: false,
        };

        // Step 2: Upload parts concurrently with bounds
        let mut join_set = tokio::task::JoinSet::new();
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(8));

        for (i, chunk) in data.chunks(self.chunk_size).enumerate() {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let part_number = (i + 1) as i32;
            let stream = ByteStream::from(chunk.to_vec());
            let client = self.client.clone();
            let bucket = self.bucket.clone();
            let key = key.to_string();
            let uid = upload_id.clone();

            join_set.spawn(async move {
                let res = client
                    .upload_part()
                    .bucket(&bucket)
                    .key(&key)
                    .upload_id(&uid)
                    .part_number(part_number)
                    .body(stream)
                    .send()
                    .await;
                drop(permit);
                (part_number, res)
            });
        }

        let mut completed_parts_with_index = Vec::new();
        while let Some(result) = join_set.join_next().await {
            let (part_num, s3_res) = result?;
            let upload_part_res = s3_res?;

            let mut part_builder = CompletedPart::builder()
                .e_tag(upload_part_res.e_tag().unwrap_or_default())
                .part_number(part_num);

            if let Some(crc32) = upload_part_res.checksum_crc32() {
                part_builder = part_builder.checksum_crc32(crc32);
            }

            completed_parts_with_index.push((part_num, part_builder.build()));
        }

        completed_parts_with_index.sort_by_key(|(num, _)| *num);
        let completed_parts: Vec<_> = completed_parts_with_index
            .into_iter()
            .map(|(_, p)| p)
            .collect();

        // Step 3: Complete multipart upload
        let completed_upload = CompletedMultipartUpload::builder()
            .set_parts(Some(completed_parts))
            .build();

        self.client
            .complete_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(&upload_id)
            .multipart_upload(completed_upload)
            .send()
            .await?;

        guard.completed = true;
        Ok(())
    }
}

#[async_trait::async_trait]
impl StorageUploader for S3MultipartUploader {
    // @trace TASK-098
    // @trace TASK-099
    async fn upload_stream(
        &self,
        key: &str,
        mut rx: tokio::sync::mpsc::Receiver<StreamItem>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let create_res = self
            .client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .checksum_algorithm(aws_sdk_s3::types::ChecksumAlgorithm::Crc32)
            .send()
            .await?;

        let upload_id = create_res
            .upload_id()
            .ok_or("Missing upload_id")?
            .to_string();

        let mut guard = MultipartUploadGuard {
            client: self.client.clone(),
            bucket: self.bucket.clone(),
            key: key.to_string(),
            upload_id: upload_id.clone(),
            completed: false,
        };

        let mut join_set = tokio::task::JoinSet::new();
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(8));
        let mut part_number = 1;
        let mut success_signal_received = false;
        let mut upload_error: Option<Box<dyn std::error::Error + Send + Sync>> = None;
        let mut completed_parts_with_index = Vec::new();

        let mut permit_opt: Option<tokio::sync::OwnedSemaphorePermit> = None;

        loop {
            tokio::select! {
                permit_res = semaphore.clone().acquire_owned(), if permit_opt.is_none() => {
                    permit_opt = Some(permit_res.unwrap());
                }
                item = rx.recv(), if permit_opt.is_some() => {
                    match item {
                        Some(StreamItem::Data(chunk)) => {
                            let permit = permit_opt.take().unwrap();
                            let stream = ByteStream::from(chunk);
                            let client = self.client.clone();
                            let bucket = self.bucket.clone();
                            let key_str = key.to_string();
                            let uid = upload_id.clone();

                            join_set.spawn(async move {
                                let res = client
                                    .upload_part()
                                    .bucket(&bucket)
                                    .key(&key_str)
                                    .upload_id(&uid)
                                    .part_number(part_number)
                                    .body(stream)
                                    .send()
                                    .await;
                                drop(permit);
                                (part_number, res)
                            });

                            part_number += 1;
                        }
                        Some(StreamItem::Success) => {
                            success_signal_received = true;
                            break;
                        }
                        None => {
                            break;
                        }
                    }
                }
                Some(result) = join_set.join_next(), if !join_set.is_empty() => {
                    match result {
                        Ok((part_num, Ok(upload_part_res))) => {
                            let mut part_builder = CompletedPart::builder()
                                .e_tag(upload_part_res.e_tag().unwrap_or_default())
                                .part_number(part_num);

                            if let Some(crc32) = upload_part_res.checksum_crc32() {
                                part_builder = part_builder.checksum_crc32(crc32);
                            }
                            completed_parts_with_index.push((part_num, part_builder.build()));
                        }
                        Ok((_, Err(e))) => {
                            upload_error = Some(Box::new(e) as Box<dyn std::error::Error + Send + Sync>);
                            break;
                        }
                        Err(e) => {
                            upload_error = Some(Box::new(std::io::Error::other(format!("Task panicked: {}", e))) as Box<dyn std::error::Error + Send + Sync>);
                            break;
                        }
                    }
                }
            }
        }

        if upload_error.is_none() {
            while let Some(result) = join_set.join_next().await {
                match result {
                    Ok((part_num, Ok(upload_part_res))) => {
                        let mut part_builder = CompletedPart::builder()
                            .e_tag(upload_part_res.e_tag().unwrap_or_default())
                            .part_number(part_num);

                        if let Some(crc32) = upload_part_res.checksum_crc32() {
                            part_builder = part_builder.checksum_crc32(crc32);
                        }
                        completed_parts_with_index.push((part_num, part_builder.build()));
                    }
                    Ok((_, Err(e))) => {
                        upload_error =
                            Some(Box::new(e) as Box<dyn std::error::Error + Send + Sync>);
                        break;
                    }
                    Err(e) => {
                        upload_error = Some(Box::new(std::io::Error::other(format!(
                            "Task panicked: {}",
                            e
                        )))
                            as Box<dyn std::error::Error + Send + Sync>);
                        break;
                    }
                }
            }
        }

        if !success_signal_received || upload_error.is_some() {
            if let Some(err) = upload_error {
                return Err(err);
            } else {
                return Err("Upload aborted due to missing success signal from stream".into());
            }
        }

        completed_parts_with_index.sort_by_key(|(num, _)| *num);
        let completed_parts: Vec<_> = completed_parts_with_index
            .into_iter()
            .map(|(_, p)| p)
            .collect();

        let completed_upload = CompletedMultipartUpload::builder()
            .set_parts(Some(completed_parts))
            .build();

        self.client
            .complete_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(&upload_id)
            .multipart_upload(completed_upload)
            .send()
            .await?;

        guard.completed = true;
        Ok(())
    }
}
